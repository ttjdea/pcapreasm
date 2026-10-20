# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 ttjdea@eightry.jp
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
pcapreasm - PCAP TCP/UDP Stream Reassembly Library

A Python standard-library-only module designed to extract application-layer
data from PCAP packet captures. It strips Layer 2 headers (Ethernet, 802.1Q/QinQ,
Linux SLL/SLL2, RAW, Loopback), parses IPv4/IPv6 (including extended headers and
IP fragment reassembly), and reconstructs TCP streams into bidirectional
conversations.

Key Features
============
* Supports classic PCAP files (both Little-Endian / Big-Endian, microsecond /
  nanosecond timestamp resolutions).
* Gracefully handles truncated PCAP files by processing valid records and
  warning without breaking multi-file pipelines.
* Maintains capture timestamps as 64-bit integer nanoseconds (timestamp_ns) to
  prevent floating-point precision loss.
* Full IP fragment reassembly for IPv4 and IPv6 with timeout and buffer limits.
* Robust TCP stream reassembly: handles 32-bit sequence number wrap-around,
  deduplicates retransmissions, tracks sequence gaps, and lingers for delayed
  segments after FIN.
* Bidirectional API: `on_tcp_conversation` pairs client and server streams.
* Flexible memory bounds: controls resource usage via `max_conversations`,
  `max_conversation_bytes`, `max_total_bytes`, and `idle_timeout`.
* UDP handling: per-datagram immediate callbacks and per-flow batch callbacks.

Quickstart
==========
Reassembling TCP streams::

    from pcapreasm import PcapStreamProcessor, BaseAnalyzer

    class MyAnalyzer(BaseAnalyzer):
        def on_tcp_stream(self, flow_id, data, meta):        # Unidirectional
            print(flow_id, len(data), meta.evict_reason)

        def on_tcp_conversation(self, conversation):          # Bidirectional
            print(conversation.client.flow_id, conversation.server.flow_id)

    PcapStreamProcessor(analyzers=[MyAnalyzer()]).process_files(["a.pcap", "b.pcap"])

Handling UDP datagrams::

    class UdpAnalyzer(BaseAnalyzer):
        def on_udp_datagram(self, flow_id, payload, timestamp_ns):
            print(flow_id, payload[:16].hex(), timestamp_ns)

Processing Pipeline
===================
::

    PCAP File
      |  (1) Parse records (Global Header -> [Packet Header + Packet Payload]*)
      v
    Strip L2 ............. Ethernet / VLAN / SLL / SLL2 / RAW / Loopback
      |
      v
    Parse L3 ............. IPv4 / IPv6 (Reassemble IP fragments into L4 payloads)
      |
      +-- UDP ------------> Invoke `on_udp_datagram` immediately
      |                     (Per-flow batches dispatched upon flush)
      |
      +-- TCP ------------> Buffer segments per 4-tuple and direction
                             |  Evict conversation on FIN/RST, idle, or limit overflow
                             v
                           Sort sequence numbers, strip duplicates, track missing
                           gaps, and construct contiguous byte stream.
                             |
                             v
                           Dispatch to `on_tcp_stream` / `on_tcp_conversation`

Terminology
===========
* timestamp_ns : Packet capture time in nanoseconds since UNIX epoch.
                 Convert to seconds using `ns_to_seconds()`.
* flow_id      : 4-tuple `(src_ip, src_port, dst_ip, dst_port)` for a single direction.
* conversation : Bidirectional TCP connection grouping both directions of a 4-tuple.
                 Serves as the unit for memory tracking and eviction.
* payload      : Raw application-layer data from a single packet segment.
* data         : Reconstructed contiguous byte stream for a single direction.
* evict        : Finalize a stream, remove it from memory, and dispatch it to analyzers.

Caveats
=======
* Time-based operations (e.g., `idle_timeout`) rely on packet capture timestamps,
  not system clock time.
* Memory usage is unbound by default (`max_*` and `idle_timeout` default to None/5000).
  Set limits when processing very large PCAPs.
* Does not perform decryption for encrypted protocols (e.g., TLS).
"""

from __future__ import annotations

import abc
import collections
import functools
import logging
import os
import socket
import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "FlowId",
    "NS_PER_SEC",
    "ns_to_seconds",
    "UDPDatagram",
    "UDPFlowMeta",
    "TCPFlowMeta",
    "TCPStream",
    "TCPConversation",
    "BaseAnalyzer",
    "PcapStreamProcessor",
    "EVICT_FIN",
    "EVICT_RST",
    "EVICT_NEW_CONNECTION",
    "EVICT_IDLE",
    "EVICT_FIN_TIMEOUT",
    "EVICT_MAX_CONVERSATIONS",
    "EVICT_MAX_BYTES",
    "EVICT_MAX_TOTAL_BYTES",
    "EVICT_FLUSH",
]
__version__ = "0.0.1"

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------
# Standardize time units across external APIs and internal processing
NS_PER_SEC = 1_000_000_000  # 1 second = 10^9 nanoseconds
SWEEP_INTERVAL_NS = NS_PER_SEC  # Interval for timeout checks (1 sec in capture time)

# Data Link Types (network field in PCAP global header = L2 encapsulation)
DLT_NULL = 0x00        # BSD loopback header (4 bytes)
DLT_EN10MB = 0x01      # Ethernet (10Mb, 100Mb, 1000Mb, etc.)
DLT_RAW2 = 0x0C        # Raw IP (some OS variants)
DLT_RAW = 0x65         # Raw IP
DLT_LOOP = 0x6C        # OpenBSD loopback header (4 bytes)
DLT_LINUX_SLL = 0x71   # Linux cooked capture v1 (16 bytes)
DLT_LINUX_SLL2 = 0x114 # Linux cooked capture v2 (20 bytes)
DLT_IPV4 = 0xE4        # Raw IPv4
DLT_IPV6 = 0xE5        # Raw IPv6
LINKTYPE_MASK = 0x0FFFFFFF  # Exclude high 4 bits used for FCS flags

# PCAP Magic Numbers. Keys are 4-byte integers read via struct "<I".
# Maps magic numbers to tuple: (endianness_format_char, is_nanosecond_resolution)
_MAGIC_TABLE = {
    0xA1B2C3D4: ("<", False),  # Little-Endian, microsecond resolution
    0xA1B23C4D: ("<", True),   # Little-Endian, nanosecond resolution
    0xD4C3B2A1: (">", False),  # Big-Endian, microsecond resolution
    0x4D3CB2A1: (">", True),   # Big-Endian, nanosecond resolution
}
PCAP_GLOBAL_HEADER_LEN = 0x18  # 24 bytes global header
PCAP_PACKET_HEADER_LEN = 0x10  # 16 bytes per-packet record header
PCAP_MAX_INCL_LEN = 0x0A00000  # 10 MB sanity limit for captured packet length

# Ethernet Parameters
ETH_HEADER_LEN = 0x0E      # 14 bytes: Dst MAC (6) + Src MAC (6) + EtherType (2)
ETH_TYPE_OFFSET = 0x0C     # Offset to EtherType field
ETH_TYPE_IPV4 = 0x0800     # IPv4 EtherType
ETH_TYPE_IPV6 = 0x86DD     # IPv6 EtherType
ETH_TYPE_VLAN = (0x8100, 0x88A8, 0x9100)  # VLAN EtherTypes (802.1Q / QinQ)
VLAN_TAG_LEN = 0x04        # 4 bytes: TPID (2) + TCI (2)
SLL_HEADER_LEN = 0x10      # 16 bytes for SLL v1
SLL_PROTO_OFFSET = 0x0E    # Offset to protocol field in SLL v1
SLL2_HEADER_LEN = 0x14     # 20 bytes for SLL v2
LOOPBACK_HEADER_LEN = 0x04 # 4 bytes address family header

# IPv4 Header Constraints
IPV4_MIN_HEADER_LEN = 0x14      # Minimum length without options (20 bytes)
IPV4_TOTAL_LEN_OFFSET = 0x02    # Total length offset
IPV4_ID_OFFSET = 0x04           # Identification offset
IPV4_FLAGS_FRAG_OFFSET = 0x06   # Flags (3 bits) + Fragment Offset (13 bits)
IPV4_PROTO_OFFSET = 0x09        # Protocol field offset
IPV4_SRC_OFFSET = 0x0C          # Source IPv4 address offset
IPV4_DST_OFFSET = 0x10          # Destination IPv4 address offset
IPV4_MF_FLAG = 0x2000           # More Fragments flag mask
IPV4_FRAG_OFFSET_MASK = 0x1FFF  # Fragment offset mask (in 8-byte units)

# IPv6 Header Constraints
IPV6_HEADER_LEN = 0x28          # Fixed base header length (40 bytes)
IPV6_PAYLOAD_LEN_OFFSET = 0x04  # Payload length offset
IPV6_NEXT_HEADER_OFFSET = 0x06  # Next header field offset
IPV6_SRC_OFFSET = 0x08          # Source IPv6 address offset
IPV6_DST_OFFSET = 0x18          # Destination IPv6 address offset
IPV6_EXT_HOP = 0x00             # Hop-by-Hop Options
IPV6_EXT_ROUTING = 0x2B         # Routing Header
IPV6_EXT_FRAG = 0x2C            # Fragment Header
IPV6_EXT_AH = 0x33              # Authentication Header
IPV6_EXT_DEST = 0x3C            # Destination Options
IPV6_FRAG_HEADER_LEN = 0x08     # Fragment header length (8 bytes)
IPV6_FRAG_NONTRIVIAL_MASK = 0xFFF9  # Offset (13 bits) + M flag (1 bit), excluding reserved

# IP Fragment Reassembly
IP_MAX_DATAGRAM_LEN = 0x10000   # Maximum reassembled datagram size (65,536 bytes)

# Layer 4 Protocols
IPPROTO_TCP = 0x06              # TCP Protocol Number
IPPROTO_UDP = 0x11              # UDP Protocol Number
TCP_MIN_HEADER_LEN = 0x14       # Minimum TCP header length (20 bytes)
TCP_HEADER_LEN_OFFSET = 0x0C    # Offset to Data Offset field (high 4 bits)
TCP_FLAGS_OFFSET = 0x0D         # Offset to TCP control flags
TCP_FIN = 0x01                  # FIN flag
TCP_SYN = 0x02                  # SYN flag
TCP_RST = 0x04                  # RST flag
TCP_ACK = 0x10                  # ACK flag
UDP_HEADER_LEN = 0x08           # Fixed UDP header length (8 bytes)

RECENTLY_CLOSED_MAX = 100_000   # Maximum tracking limit for recently closed connections

# Eviction Reason String Constants (TCPFlowMeta.evict_reason)
EVICT_FIN = "fin"                        # Both sides sent FIN and all data received cleanly
EVICT_RST = "rst"                        # RST frame observed
EVICT_NEW_CONNECTION = "new_connection"  # New SYN received on existing 4-tuple
EVICT_IDLE = "idle"                      # Idle timeout exceeded
EVICT_FIN_TIMEOUT = "fin_timeout"        # Timeout waiting for missing gaps post-FIN
EVICT_MAX_CONVERSATIONS = "max_conversations"  # Maximum active conversation count exceeded
EVICT_MAX_BYTES = "max_bytes"            # Single conversation memory limit exceeded
EVICT_MAX_TOTAL_BYTES = "max_total_bytes"# Aggregate buffer memory limit exceeded
EVICT_FLUSH = "flush"                    # Explicit stream flush (e.g. EOF)

FlowId = Tuple[str, int, str, int]       # (src_ip, src_port, dst_ip, dst_port)
Endpoint = Tuple[bytes, int]              # Internal key format: (raw_ip_bytes, port)
logger = logging.getLogger(__name__)


def ns_to_seconds(timestamp_ns: int) -> float:
    """Convert integer nanoseconds to epoch seconds as float.
    
    Note: Using floats causes precision loss; use primarily for display or rough metrics.
    """
    return timestamp_ns / NS_PER_SEC


def _ip_to_str(raw: bytes) -> str:
    """Convert raw IP bytes (4 bytes for IPv4, 16 bytes for IPv6) into standard string format."""
    return socket.inet_ntoa(raw) if len(raw) == 4 else socket.inet_ntop(socket.AF_INET6, raw)


@functools.lru_cache(maxsize=65536)
def _make_flow_id(src_raw: bytes, src_port: int, dst_raw: bytes, dst_port: int) -> FlowId:
    """Construct a FlowId tuple from raw binary addresses and port numbers.

    Caching reduces string formatting overhead for repeated packets in the same flow.
    """
    return (_ip_to_str(src_raw), src_port, _ip_to_str(dst_raw), dst_port)


# -------------------------------------------------------------------------
# Data Containers
# -------------------------------------------------------------------------
@dataclass
class UDPDatagram:
    """Represents a single parsed UDP datagram payload and metadata."""

    payload: bytes
    timestamp_ns: int


@dataclass
class UDPFlowMeta:
    """Metadata for a batched UDP flow dispatches (emitted during flush)."""

    first_timestamp_ns: int
    last_timestamp_ns: int
    datagram_count: int


@dataclass
class TCPFlowMeta:
    """Metadata for an evicted unidirectional TCP flow.

    Attributes:
        first_timestamp_ns: Capture timestamp of the first packet in this direction.
        last_timestamp_ns: Capture timestamp of the last packet in this direction.
        timeline: Chronological sequence of `[(timestamp_ns, payload_chunk)]`.
            Concatenating payloads yields the exact stream `data`. Can be used to map
            byte offsets to packet capture timestamps.
        segment_count: Total TCP segments with non-empty payload received (includes retransmissions).
        retrans_count: Count of retransmitted or duplicate segments discarded during reassembly.
        gaps: Sequence gaps `[(offset, missing_bytes), ...]`. Offset indicates position in `data`.
        is_closed: True if a FIN or RST was observed in this direction.
        evict_reason: Reason string for stream eviction (`EVICT_*` constants).
    """

    first_timestamp_ns: int
    last_timestamp_ns: int
    timeline: List[Tuple[int, bytes]]
    segment_count: int
    retrans_count: int
    gaps: List[Tuple[int, int]]
    is_closed: bool
    evict_reason: str

    @property
    def gap_count(self) -> int:
        """Total number of distinct missing gap ranges."""
        return len(self.gaps)

    @property
    def gap_bytes(self) -> int:
        """Aggregate total number of missing payload bytes across all gaps."""
        return sum(missing for _, missing in self.gaps)


@dataclass
class TCPStream:
    """Unidirectional TCP stream deliverable."""

    flow_id: FlowId
    data: bytes
    meta: TCPFlowMeta


@dataclass
class TCPConversation:
    """Bidirectional TCP conversation holding both endpoints.

    Attributes:
        client: Stream container for the initiator (SYN sender).
        server: Stream container for the responder.
        client_certain: True if initiator role was confirmed via SYN/SYN-ACK handshake.
            If False, the sender of the first observed packet was designated as the client.
        first_timestamp_ns: Earliest capture timestamp across both directions.
        last_timestamp_ns: Latest capture timestamp across both directions.
        evict_reason: Eviction reason string (`EVICT_*` constants).
    """

    client: TCPStream
    server: TCPStream
    client_certain: bool
    first_timestamp_ns: int
    last_timestamp_ns: int
    evict_reason: str


# -------------------------------------------------------------------------
# L2 / L3 / L4 Parsing Utilities
#
# Pure functions that accept raw frame bytes and return parsed layer details.
# Returns empty bytes or None for invalid/malformed frames without raising exceptions.
# -------------------------------------------------------------------------
def _strip_l2(packet: bytes, linktype: int) -> bytes:
    """Strip Layer 2 framing and return the encapsulated IP packet bytes.

    Returns `b""` if the encapsulated payload is not IPv4 or IPv6.
    """
    if linktype == DLT_EN10MB:
        if len(packet) < ETH_HEADER_LEN:
            return b""
        offset = ETH_HEADER_LEN
        eth_type = struct.unpack_from("!H", packet, ETH_TYPE_OFFSET)[0]
        # Recursively strip multi-tagged VLAN headers (802.1Q / 802.1ad QinQ)
        while eth_type in ETH_TYPE_VLAN and len(packet) >= offset + VLAN_TAG_LEN:
            eth_type = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += VLAN_TAG_LEN
        if eth_type in (ETH_TYPE_IPV4, ETH_TYPE_IPV6):
            return packet[offset:]
        return b""
    if linktype in (DLT_RAW, DLT_RAW2, DLT_IPV4, DLT_IPV6):
        return packet
    if linktype in (DLT_NULL, DLT_LOOP):
        return packet[LOOPBACK_HEADER_LEN:]
    if linktype == DLT_LINUX_SLL:
        if len(packet) < SLL_HEADER_LEN:
            return b""
        proto = struct.unpack_from("!H", packet, SLL_PROTO_OFFSET)[0]
        return packet[SLL_HEADER_LEN:] if proto in (ETH_TYPE_IPV4, ETH_TYPE_IPV6) else b""
    if linktype == DLT_LINUX_SLL2:
        if len(packet) < SLL2_HEADER_LEN:
            return b""
        proto = struct.unpack_from("!H", packet, 0)[0]
        return packet[SLL2_HEADER_LEN:] if proto in (ETH_TYPE_IPV4, ETH_TYPE_IPV6) else b""
    return b""


_SUPPORTED_LINKTYPES = {
    DLT_NULL, DLT_EN10MB, DLT_RAW2, DLT_RAW, DLT_LOOP,
    DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_IPV4, DLT_IPV6,
}

# Return type structure for IP parser: (src_raw, dst_raw, proto, l4_data, fragment_info)
_Fragment = Tuple[int, int, bool]
_ParsedIP = Tuple[bytes, bytes, int, bytes, Optional[_Fragment]]


def _parse_ipv4(ip_packet: bytes) -> Optional[_ParsedIP]:
    """Parse an IPv4 packet header. Returns None if malformed or truncated."""
    if len(ip_packet) < IPV4_MIN_HEADER_LEN or (ip_packet[0] >> 4) != 4:
        return None
    ip_header_len = (ip_packet[0] & 0x0F) * 4
    if ip_header_len < IPV4_MIN_HEADER_LEN or len(ip_packet) < ip_header_len:
        return None
    ip_total_len = struct.unpack_from("!H", ip_packet, IPV4_TOTAL_LEN_OFFSET)[0]
    flags_frag = struct.unpack_from("!H", ip_packet, IPV4_FLAGS_FRAG_OFFSET)[0]

    more_fragments = bool(flags_frag & IPV4_MF_FLAG)
    fragment_offset = (flags_frag & IPV4_FRAG_OFFSET_MASK) * 8

    fragment: Optional[_Fragment] = None
    if more_fragments or fragment_offset:
        identification = struct.unpack_from("!H", ip_packet, IPV4_ID_OFFSET)[0]
        fragment = (identification, fragment_offset, more_fragments)

    # Truncate payload to IP total length to eliminate Ethernet trailer padding
    end = ip_total_len if ip_header_len <= ip_total_len <= len(ip_packet) else len(ip_packet)
    return (
        ip_packet[IPV4_SRC_OFFSET:IPV4_SRC_OFFSET + 4],
        ip_packet[IPV4_DST_OFFSET:IPV4_DST_OFFSET + 4],
        ip_packet[IPV4_PROTO_OFFSET],
        ip_packet[ip_header_len:end],
        fragment,
    )


def _parse_ipv6(ip_packet: bytes) -> Optional[_ParsedIP]:
    """Parse an IPv6 header, skipping through extension headers. Returns None if invalid."""
    if len(ip_packet) < IPV6_HEADER_LEN or (ip_packet[0] >> 4) != 6:
        return None
    ip_payload_len = struct.unpack_from("!H", ip_packet, IPV6_PAYLOAD_LEN_OFFSET)[0]
    end = IPV6_HEADER_LEN + ip_payload_len
    if ip_payload_len == 0 or end > len(ip_packet):  # Handle jumbo payloads / TSO
        end = len(ip_packet)

    src_raw = ip_packet[IPV6_SRC_OFFSET:IPV6_SRC_OFFSET + 16]
    dst_raw = ip_packet[IPV6_DST_OFFSET:IPV6_DST_OFFSET + 16]

    next_header = ip_packet[IPV6_NEXT_HEADER_OFFSET]
    offset = IPV6_HEADER_LEN

    while next_header in (IPV6_EXT_HOP, IPV6_EXT_ROUTING, IPV6_EXT_DEST, IPV6_EXT_FRAG, IPV6_EXT_AH):
        if offset + 8 > end:
            return None
        if next_header == IPV6_EXT_FRAG:
            frag_field, identification = struct.unpack_from("!HI", ip_packet, offset + 2)
            if frag_field & IPV6_FRAG_NONTRIVIAL_MASK:
                fragment = (identification, (frag_field >> 3) * 8, bool(frag_field & 1))
                return src_raw, dst_raw, ip_packet[offset], ip_packet[offset + IPV6_FRAG_HEADER_LEN:end], fragment
            ext_len = IPV6_FRAG_HEADER_LEN  # Atomic fragment: proceed as normal header
        elif next_header == IPV6_EXT_AH:
            ext_len = (ip_packet[offset + 1] + 2) * 4
        else:
            ext_len = (ip_packet[offset + 1] + 1) * 8
        next_header = ip_packet[offset]
        offset += ext_len

    if offset > end:
        return None
    return src_raw, dst_raw, next_header, ip_packet[offset:end], None


def _parse_tcp(l4_data: bytes) -> Optional[Tuple[int, int, int, int, bytes]]:
    """Parse TCP header and extract `(src_port, dst_port, seq, flags, payload)`."""
    if len(l4_data) < TCP_MIN_HEADER_LEN:
        return None
    src_port, dst_port, seq = struct.unpack_from("!HHI", l4_data, 0)
    tcp_header_len = (l4_data[TCP_HEADER_LEN_OFFSET] >> 4) * 4
    if tcp_header_len < TCP_MIN_HEADER_LEN or len(l4_data) < tcp_header_len:
        return None
    return src_port, dst_port, seq, l4_data[TCP_FLAGS_OFFSET], l4_data[tcp_header_len:]


def _parse_udp(l4_data: bytes) -> Optional[Tuple[int, int, bytes]]:
    """Parse UDP header and extract `(src_port, dst_port, payload)`."""
    if len(l4_data) < UDP_HEADER_LEN:
        return None
    src_port, dst_port, udp_len = struct.unpack_from("!HHH", l4_data, 0)
    end = udp_len if UDP_HEADER_LEN <= udp_len <= len(l4_data) else len(l4_data)
    return src_port, dst_port, l4_data[UDP_HEADER_LEN:end]


def _parse_global_header(global_header: bytes) -> Optional[Tuple[str, int, bool]]:
    """Parse 24-byte PCAP global header to determine `(endian_char, linktype, is_nano)`."""
    if len(global_header) < PCAP_GLOBAL_HEADER_LEN:
        return None
    magic_info = _MAGIC_TABLE.get(struct.unpack_from("<I", global_header, 0)[0])
    if magic_info is None:
        return None
    endian, is_nano = magic_info
    _, version_major, _, _, _, _, network = struct.unpack(
        endian + "IHHiIII", global_header[:PCAP_GLOBAL_HEADER_LEN]
    )
    if version_major != 2:
        return None
    return endian, network & LINKTYPE_MASK, is_nano


# -------------------------------------------------------------------------
# IP Fragment Reassembly State
# -------------------------------------------------------------------------
class _FragmentSet:
    """Container for fragments belonging to a single IP datagram."""

    __slots__ = ("pieces", "total_len", "size", "last_timestamp_ns")

    def __init__(self, timestamp_ns: int):
        self.pieces: List[Tuple[int, bytes]] = []  # [(offset, payload_bytes)]
        self.total_len: Optional[int] = None      # Resolved when final fragment arrives
        self.size = 0                             # Total buffered bytes including overlaps
        self.last_timestamp_ns = timestamp_ns


class _FragmentReassembler:
    """Manages state for IPv4 and IPv6 fragment reassembly."""

    def __init__(self, timeout_ns: int, max_sets: int, stats: collections.Counter):
        self._timeout_ns = timeout_ns
        self._max_sets = max_sets
        self._stats = stats
        self._sets: "collections.OrderedDict[tuple, _FragmentSet]" = collections.OrderedDict()

    def expire(self, now_ns: int) -> None:
        """Evict incomplete fragment sets that have exceeded the timeout limit."""
        while self._sets:
            key, fragment_set = next(iter(self._sets.items()))
            if now_ns - fragment_set.last_timestamp_ns <= self._timeout_ns:
                break
            del self._sets[key]
            self._stats["frag_expired"] += 1

    def add(
        self, key: tuple, offset: int, more_fragments: bool, data: bytes, timestamp_ns: int
    ) -> Optional[bytes]:
        """Add a fragment piece and return reassembled L4 payload if complete."""
        self.expire(timestamp_ns)
        if offset + len(data) > IP_MAX_DATAGRAM_LEN:
            self._stats["frag_too_large"] += 1
            self._sets.pop(key, None)
            return None

        fragment_set = self._sets.get(key)
        if fragment_set is None:
            while len(self._sets) >= self._max_sets:
                self._sets.popitem(last=False)
                self._stats["frag_evicted"] += 1
            fragment_set = _FragmentSet(timestamp_ns)
            self._sets[key] = fragment_set
        else:
            self._sets.move_to_end(key)

        fragment_set.last_timestamp_ns = timestamp_ns
        fragment_set.pieces.append((offset, data))
        fragment_set.size += len(data)

        if not more_fragments:
            end = offset + len(data)
            if fragment_set.total_len is not None and fragment_set.total_len != end:
                del self._sets[key]
                self._stats["frag_conflict"] += 1
                return None
            fragment_set.total_len = end

        if fragment_set.size > 2 * IP_MAX_DATAGRAM_LEN:
            del self._sets[key]
            self._stats["frag_too_large"] += 1
            return None

        if fragment_set.total_len is None:
            return None

        assembled = self._try_assemble(fragment_set)
        if assembled is not None:
            del self._sets[key]
        return assembled

    @staticmethod
    def _try_assemble(fragment_set: _FragmentSet) -> Optional[bytes]:
        """Attempt to assemble contiguous payload fragments up to total_len."""
        covered = 0
        parts: List[bytes] = []
        for offset, data in sorted(fragment_set.pieces, key=lambda piece: piece[0]):
            if offset > covered:
                return None  # Missing gap remains
            if offset + len(data) <= covered:
                continue  # Fragment fully redundant
            parts.append(data[covered - offset:])
            covered = offset + len(data)

        if fragment_set.total_len is None or covered < fragment_set.total_len:
            return None
        return b"".join(parts)[:fragment_set.total_len]

    def clear(self) -> int:
        """Purge all buffered fragment sets and return discarded count."""
        count = len(self._sets)
        self._sets.clear()
        return count


# -------------------------------------------------------------------------
# TCP Stream Reassembly Core
# -------------------------------------------------------------------------
class _TCPReassembler:
    """Reassembles a single unidirectional TCP stream."""

    def __init__(self) -> None:
        self.chunks: List[Tuple[int, bytes, int]] = []  # [(unwrapped_seq, payload, timestamp_ns)]
        self.start_seq: Optional[int] = None
        self.fin_seq: Optional[int] = None
        self.is_rst = False
        self.first_timestamp_ns: Optional[int] = None
        self.last_timestamp_ns = 0
        self._ref_raw_seq: Optional[int] = None
        self._ref_unwrapped_seq = 0
        self._finished_cache: Optional[bool] = None

    @property
    def has_data(self) -> bool:
        return bool(self.chunks)

    def _unwrap_seq(self, seq: int) -> int:
        """Convert a 32-bit TCP sequence number to a monotonic integer, handling wraprange."""
        if self._ref_raw_seq is None:
            self._ref_raw_seq = seq
            self._ref_unwrapped_seq = seq
            return seq
        delta = ((seq - self._ref_raw_seq + 0x80000000) & 0xFFFFFFFF) - 0x80000000
        unwrapped_seq = self._ref_unwrapped_seq + delta
        self._ref_raw_seq = seq
        self._ref_unwrapped_seq = unwrapped_seq
        return unwrapped_seq

    def add(self, seq: int, payload: bytes, timestamp_ns: int, flags: int) -> int:
        """Add a TCP segment and return the byte length added to the buffer."""
        if self.first_timestamp_ns is None:
            self.first_timestamp_ns = timestamp_ns
        self.last_timestamp_ns = timestamp_ns
        unwrapped_seq = self._unwrap_seq(seq)
        data_seq = unwrapped_seq

        if flags & TCP_SYN:
            data_seq += 1
            self.start_seq = data_seq

        if payload:
            self.chunks.append((data_seq, payload, timestamp_ns))
            self._finished_cache = None

        if flags & TCP_FIN:
            self.fin_seq = data_seq + len(payload)
            self._finished_cache = None

        if flags & TCP_RST:
            self.is_rst = True

        return len(payload)

    def is_finished(self) -> bool:
        """Check if the stream is complete (either RST or all data up to FIN received)."""
        if self.is_rst:
            return True
        if self.fin_seq is None:
            return False
        if self._finished_cache is None:
            self._finished_cache = self._covers_up_to_fin()
        return self._finished_cache

    def _covers_up_to_fin(self) -> bool:
        """Verify contiguity from start_seq up to fin_seq."""
        assert self.fin_seq is not None
        spans = sorted((seq, seq + len(payload)) for seq, payload, _ in self.chunks)
        if self.start_seq is not None:
            covered = self.start_seq
        elif spans:
            covered = spans[0][0]
        else:
            covered = self.fin_seq

        for start, end in spans:
            if start > covered:
                return False
            if end > covered:
                covered = end
        return covered >= self.fin_seq

    def reassemble(self) -> Tuple[bytes, List[Tuple[int, bytes]], List[Tuple[int, int]], int]:
        """Order segments by sequence number, trim overlaps, and construct contiguous data.

        Returns:
            Tuple of `(data, timeline, gaps, retrans_count)`.
        """
        timeline: List[Tuple[int, bytes]] = []
        gaps: List[Tuple[int, int]] = []
        retrans_count = 0

        if not self.chunks:
            return b"", timeline, gaps, retrans_count

        # Primary sort by sequence number; secondary sort by payload length descending
        self.chunks.sort(key=lambda chunk: (chunk[0], -len(chunk[1])))

        parts: List[bytes] = []
        offset = 0
        covered_end = self.start_seq

        for seq, payload, timestamp_ns in self.chunks:
            original_len = len(payload)
            if covered_end is not None:
                if seq < covered_end:
                    overlap = covered_end - seq
                    if overlap >= original_len:
                        retrans_count += 1
                        continue
                    payload = payload[overlap:]
                elif seq > covered_end:
                    gaps.append((offset, seq - covered_end))

            parts.append(payload)
            timeline.append((timestamp_ns, payload))
            offset += len(payload)
            covered_end = seq + original_len

        if self.fin_seq is not None and covered_end is not None and covered_end < self.fin_seq:
            gaps.append((offset, self.fin_seq - covered_end))

        return b"".join(parts), timeline, gaps, retrans_count

    def clear(self) -> None:
        self.chunks.clear()


class _TCPConversation:
    """Manages bidirectional TCP state for a single normalized 4-tuple."""

    __slots__ = (
        "key", "directions", "seen", "client_index", "client_certain",
        "first_timestamp_ns", "last_timestamp_ns", "buffered", "closing",
    )

    def __init__(self, key: Tuple[Endpoint, Endpoint], timestamp_ns: int):
        self.key = key
        self.directions = (_TCPReassembler(), _TCPReassembler())
        self.seen = [False, False]
        self.client_index: Optional[int] = None
        self.client_certain = False
        self.first_timestamp_ns = timestamp_ns
        self.last_timestamp_ns = timestamp_ns
        self.buffered = 0
        self.closing = False

    def observe(self, index: int, flags: int, timestamp_ns: int) -> None:
        """Record packet observation and infer initiator/client direction."""
        self.seen[index] = True
        self.last_timestamp_ns = timestamp_ns
        if self.client_certain:
            return
        if flags & TCP_SYN:
            self.client_index = (1 - index) if (flags & TCP_ACK) else index
            self.client_certain = True
        elif self.client_index is None:
            self.client_index = index

    def done_reason(self) -> Optional[str]:
        """Return eviction reason string if conversation termination criteria are met."""
        if self.directions[0].is_rst or self.directions[1].is_rst:
            return EVICT_RST
        finished = [self.directions[0].is_finished(), self.directions[1].is_finished()]
        if any(finished) and all(finished[i] or not self.seen[i] for i in (0, 1)):
            return EVICT_FIN
        return None


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------
class BaseAnalyzer(abc.ABC):
    """Abstract base class for custom packet analyzers.

    Subclass `BaseAnalyzer` and override the callbacks corresponding to desired events.
    Exceptions raised within callbacks are logged and swallowed to prevent pipeline failure.
    """

    def on_tcp_stream(self, flow_id: FlowId, data: bytes, meta: TCPFlowMeta) -> None:
        """Invoked for each non-empty unidirectional TCP stream upon eviction."""

    def on_tcp_conversation(self, conversation: TCPConversation) -> None:
        """Invoked once per evicted TCP conversation holding bidirectional streams."""

    def on_udp_datagram(self, flow_id: FlowId, payload: bytes, timestamp_ns: int) -> None:
        """Invoked immediately upon parsing each individual UDP datagram."""

    def on_udp_flow(self, flow_id: FlowId, datagrams: List[UDPDatagram], meta: UDPFlowMeta) -> None:
        """Invoked during flush for each tracked UDP flow (if `on_udp_flow` is overridden)."""

    def on_complete(self) -> None:
        """Invoked once after all files are processed and stream buffers flushed."""


class PcapStreamProcessor:
    """Core processor for reading PCAP files and dispatching stream events to analyzers.

    Args:
        analyzers: List of registered `BaseAnalyzer` instances.
        evict_on_fin: Evict conversation immediately when connection termination is complete.
        max_conversations: Maximum concurrent active TCP conversations before evicting LRU streams.
        max_conversation_bytes: Per-conversation buffer threshold in bytes before forcing eviction.
        max_total_bytes: Aggregate buffer threshold across all active conversations.
        idle_timeout: Seconds of inactivity (packet capture time) before evicting an idle stream.
        close_linger: Max seconds to wait post-FIN for missing gaps or ignore late retransmissions.
        reassemble_fragments: Whether to reassemble IP fragments.
        fragment_timeout: Seconds before incomplete IP fragment sets expire.
        max_fragment_sets: Max concurrent incomplete fragment sets held in memory.
    """

    def __init__(
        self,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        evict_on_fin: bool = True,
        max_conversations: int = 5000,
        max_conversation_bytes: Optional[int] = None,
        max_total_bytes: Optional[int] = None,
        idle_timeout: Optional[float] = None,
        close_linger: float = 5.0,
        reassemble_fragments: bool = True,
        fragment_timeout: float = 30.0,
        max_fragment_sets: int = 1024,
    ):
        if max_conversations < 1:
            raise ValueError("max_conversations must be >= 1")
        self.analyzers = analyzers or []
        self.evict_on_fin = evict_on_fin
        self.stats: collections.Counter = collections.Counter()
        self._max_conversations = max_conversations
        self._max_conversation_bytes = max_conversation_bytes
        self._max_total_bytes = max_total_bytes
        self._idle_timeout_ns = None if idle_timeout is None else int(idle_timeout * NS_PER_SEC)
        self._close_linger_ns = int(close_linger * NS_PER_SEC)
        self._reassemble_fragments = reassemble_fragments
        self._fragments = _FragmentReassembler(
            int(fragment_timeout * NS_PER_SEC), max_fragment_sets, self.stats
        )
        self._conversations: "collections.OrderedDict[Tuple[Endpoint, Endpoint], _TCPConversation]" = (
            collections.OrderedDict()
        )
        self._closing: Dict[Tuple[Endpoint, Endpoint], None] = {}
        self._recently_closed: "collections.OrderedDict[Tuple[Endpoint, Endpoint], int]" = (
            collections.OrderedDict()
        )
        self._total_bytes = 0
        self._now_ns = 0
        self._last_sweep_ns = 0
        self._udp_flows: Dict[FlowId, List[UDPDatagram]] = collections.defaultdict(list)
        self._keep_udp_flows = False
        self._refresh_analyzer_flags()

    def _refresh_analyzer_flags(self) -> None:
        """Inspect registered analyzer overrides to optimize buffer allocations."""
        self._keep_udp_flows = any(
            type(a).on_udp_flow is not BaseAnalyzer.on_udp_flow for a in self.analyzers
        )
        self._wants_conversation = any(
            type(a).on_tcp_conversation is not BaseAnalyzer.on_tcp_conversation
            for a in self.analyzers
        )

    def _dispatch(self, method_name: str, *args) -> None:
        """Dispatch event callbacks to registered analyzers."""
        for analyzer in self.analyzers:
            try:
                getattr(analyzer, method_name)(*args)
            except Exception:
                logger.exception("Analyzer %s failed in %s", analyzer, method_name)

    # -- Clock & Maintenance ------------------------------------------------
    def _advance_clock(self, timestamp_ns: int) -> None:
        """Advance capture clock and trigger periodic sweep every second."""
        if timestamp_ns > self._now_ns:
            self._now_ns = timestamp_ns
        if self._now_ns - self._last_sweep_ns >= SWEEP_INTERVAL_NS:
            self._last_sweep_ns = self._now_ns
            self._sweep()

    def _sweep(self) -> None:
        """Purge idle conversations, linger timeouts, and expired IP fragments."""
        now = self._now_ns
        self._fragments.expire(now)

        if self.evict_on_fin and self._closing:
            for key in list(self._closing):
                conversation = self._conversations.get(key)
                if conversation is None:
                    self._closing.pop(key, None)
                elif now - conversation.last_timestamp_ns > self._close_linger_ns:
                    self._evict_conversation(key, EVICT_FIN_TIMEOUT)

        if self._idle_timeout_ns is not None:
            expired = []
            for key, conversation in self._conversations.items():
                if now - conversation.last_timestamp_ns <= self._idle_timeout_ns:
                    break
                expired.append(key)
            for key in expired:
                self._evict_conversation(key, EVICT_IDLE)

        while self._recently_closed:
            key, closed_ns = next(iter(self._recently_closed.items()))
            if now - closed_ns <= self._close_linger_ns:
                break
            del self._recently_closed[key]

    # -- TCP Processing ----------------------------------------------------
    def _evict_conversation(self, key: Tuple[Endpoint, Endpoint], reason: str) -> None:
        """Reassemble TCP conversation streams, notify analyzers, and free buffers."""
        conversation = self._conversations.pop(key, None)
        if conversation is None:
            return

        self._closing.pop(key, None)
        self._total_bytes -= conversation.buffered
        client_index = conversation.client_index if conversation.client_index is not None else 0

        streams: List[TCPStream] = []
        for index in (client_index, 1 - client_index):
            reassembler = conversation.directions[index]
            data, timeline, gaps, retrans_count = reassembler.reassemble()
            endpoint, peer = key[index], key[1 - index]
            flow_id = _make_flow_id(endpoint[0], endpoint[1], peer[0], peer[1])
            first = reassembler.first_timestamp_ns

            meta = TCPFlowMeta(
                first_timestamp_ns=conversation.first_timestamp_ns if first is None else first,
                last_timestamp_ns=reassembler.last_timestamp_ns or conversation.last_timestamp_ns,
                timeline=timeline,
                segment_count=len(reassembler.chunks),
                retrans_count=retrans_count,
                gaps=gaps,
                is_closed=reassembler.fin_seq is not None or reassembler.is_rst,
                evict_reason=reason,
            )
            streams.append(TCPStream(flow_id, data, meta))
            reassembler.clear()

        for stream in streams:
            if stream.data:
                self._dispatch("on_tcp_stream", stream.flow_id, stream.data, stream.meta)

        client, server = streams
        if self._wants_conversation and (client.data or server.data):
            self._dispatch(
                "on_tcp_conversation",
                TCPConversation(
                    client=client,
                    server=server,
                    client_certain=conversation.client_certain,
                    first_timestamp_ns=conversation.first_timestamp_ns,
                    last_timestamp_ns=conversation.last_timestamp_ns,
                    evict_reason=reason,
                ),
            )

    def _handle_tcp(self, timestamp_ns: int, src_raw: bytes, dst_raw: bytes, l4_data: bytes) -> None:
        """Ingest a single TCP segment, buffer payload, and evict stream if complete."""
        parsed_tcp = _parse_tcp(l4_data)
        if parsed_tcp is None:
            self.stats["bad_tcp"] += 1
            return
        src_port, dst_port, seq, flags, payload = parsed_tcp

        src_endpoint: Endpoint = (src_raw, src_port)
        dst_endpoint: Endpoint = (dst_raw, dst_port)
        if src_endpoint <= dst_endpoint:
            key, index = (src_endpoint, dst_endpoint), 0
        else:
            key, index = (dst_endpoint, src_endpoint), 1

        is_initial_syn = bool(flags & TCP_SYN) and not (flags & TCP_ACK)

        closed_ns = self._recently_closed.get(key)
        if closed_ns is not None:
            if is_initial_syn or timestamp_ns - closed_ns > self._close_linger_ns:
                del self._recently_closed[key]
            else:
                self.stats["late_packets"] += 1
                return

        conversation = self._conversations.get(key)
        if conversation is not None and is_initial_syn and conversation.directions[index].has_data:
            self._evict_conversation(key, EVICT_NEW_CONNECTION)
            conversation = None

        if conversation is None:
            if not payload and not (flags & TCP_SYN):
                self.stats["orphan_packets"] += 1
                return
            while len(self._conversations) >= self._max_conversations:
                self._evict_conversation(next(iter(self._conversations)), EVICT_MAX_CONVERSATIONS)
            conversation = _TCPConversation(key, timestamp_ns)
            self._conversations[key] = conversation
        else:
            self._conversations.move_to_end(key)

        conversation.observe(index, flags, timestamp_ns)
        added = conversation.directions[index].add(seq, payload, timestamp_ns, flags)
        conversation.buffered += added
        self._total_bytes += added

        if flags & (TCP_FIN | TCP_RST) and not conversation.closing:
            conversation.closing = True
            self._closing[key] = None

        if self._max_conversation_bytes is not None and conversation.buffered > self._max_conversation_bytes:
            self._evict_conversation(key, EVICT_MAX_BYTES)
            return

        if self.evict_on_fin and conversation.closing:
            reason = conversation.done_reason()
            if reason is not None:
                self._evict_conversation(key, reason)
                self._recently_closed[key] = timestamp_ns
                if len(self._recently_closed) > RECENTLY_CLOSED_MAX:
                    self._recently_closed.popitem(last=False)
                return

        if self._max_total_bytes is not None:
            while self._total_bytes > self._max_total_bytes and self._conversations:
                self._evict_conversation(next(iter(self._conversations)), EVICT_MAX_TOTAL_BYTES)

    # -- UDP Processing ----------------------------------------------------
    def _handle_udp(self, timestamp_ns: int, src_raw: bytes, dst_raw: bytes, l4_data: bytes) -> None:
        """Ingest a single UDP datagram and dispatch to analyzers."""
        parsed_udp = _parse_udp(l4_data)
        if parsed_udp is None:
            self.stats["bad_udp"] += 1
            return
        src_port, dst_port, payload = parsed_udp
        flow_id = _make_flow_id(src_raw, src_port, dst_raw, dst_port)
        self._dispatch("on_udp_datagram", flow_id, payload, timestamp_ns)
        if self._keep_udp_flows:
            self._udp_flows[flow_id].append(UDPDatagram(payload, timestamp_ns))

    # -- Packet Pipeline Entrypoint ---------------------------------------
    def _handle_packet(self, timestamp_ns: int, packet: bytes, linktype: int) -> None:
        """Process packet through L2 -> L3 -> (IP Reassembly) -> L4 parsing."""
        self.stats["packets"] += 1
        self._advance_clock(timestamp_ns)

        ip_packet = _strip_l2(packet, linktype)
        if not ip_packet:
            self.stats["non_ip"] += 1
            return

        version = ip_packet[0] >> 4
        parsed_ip = (
            _parse_ipv4(ip_packet) if version == 4
            else _parse_ipv6(ip_packet) if version == 6
            else None
        )
        if parsed_ip is None:
            self.stats["bad_ip"] += 1
            return

        src_raw, dst_raw, proto, l4_data, fragment = parsed_ip
        if fragment is not None:
            self.stats["fragments"] += 1
            if not self._reassemble_fragments:
                self.stats["fragments_dropped"] += 1
                return
            identification, fragment_offset, more_fragments = fragment
            assembled = self._fragments.add(
                (src_raw, dst_raw, proto, identification),
                fragment_offset, more_fragments, l4_data, timestamp_ns,
            )
            if assembled is None:
                return
            self.stats["frag_reassembled"] += 1
            l4_data = assembled

        if proto == IPPROTO_TCP:
            self._handle_tcp(timestamp_ns, src_raw, dst_raw, l4_data)
        elif proto == IPPROTO_UDP:
            self._handle_udp(timestamp_ns, src_raw, dst_raw, l4_data)

    # -- I/O Engine -------------------------------------------------------
    @staticmethod
    def _read_exact(stream: BinaryIO, size: int) -> Optional[bytes]:
        """Read exact number of bytes from stream. Returns short bytes on EOF."""
        buf = bytearray()
        while len(buf) < size:
            chunk = stream.read(size - len(buf))
            if not chunk:
                break
            buf += chunk
        if not buf:
            return None
        return bytes(buf)

    @staticmethod
    def _check_linktype(linktype: int) -> None:
        if linktype not in _SUPPORTED_LINKTYPES:
            logger.warning("Unsupported linktype %d: packets will be skipped", linktype)

    def _read_packets(self, stream: BinaryIO) -> None:
        """Stream PCAP records from file descriptor."""
        global_header = self._read_exact(stream, PCAP_GLOBAL_HEADER_LEN)
        if global_header is None:
            logger.warning("Empty file")
            return

        parsed = _parse_global_header(global_header)
        if parsed is None:
            raise ValueError(f"Invalid pcap global header: {global_header[:4].hex()}")

        endian, linktype, is_nano = parsed
        self._check_linktype(linktype)
        self.stats["files"] += 1
        ns_per_subsec = 1 if is_nano else 1000

        while True:
            packet_header = self._read_exact(stream, PCAP_PACKET_HEADER_LEN)
            if packet_header is None or len(packet_header) < PCAP_PACKET_HEADER_LEN:
                break

            epoch_sec, subsec, incl_len, _orig_len = struct.unpack(endian + "IIII", packet_header)
            if incl_len > PCAP_MAX_INCL_LEN:
                logger.warning("Unusually large incl_len %d, stopping", incl_len)
                break
            if incl_len == 0:
                continue

            packet = self._read_exact(stream, incl_len)
            if packet is None or len(packet) < incl_len:
                logger.warning("Truncated pcap (last packet incomplete)")
                break

            self._handle_packet(epoch_sec * NS_PER_SEC + subsec * ns_per_subsec, packet, linktype)

    def flush(self) -> None:
        """Flush all buffered streams and trigger final lifecycle callback."""
        while self._conversations:
            self._evict_conversation(next(iter(self._conversations)), EVICT_FLUSH)

        self._closing.clear()
        self._recently_closed.clear()

        incomplete = self._fragments.clear()
        if incomplete:
            self.stats["frag_incomplete_at_flush"] += incomplete

        for flow_id, datagrams in list(self._udp_flows.items()):
            if not datagrams:
                continue
            meta = UDPFlowMeta(
                first_timestamp_ns=min(d.timestamp_ns for d in datagrams),
                last_timestamp_ns=max(d.timestamp_ns for d in datagrams),
                datagram_count=len(datagrams),
            )
            self._dispatch("on_udp_flow", flow_id, datagrams, meta)

        self._udp_flows.clear()
        self._dispatch("on_complete")

    def process_file(self, pcap_path: str, flush_at_end: bool = True) -> None:
        """Process a single PCAP file.

        Args:
            pcap_path: Path to raw classic PCAP file or named pipe.
            flush_at_end: Whether to flush active streams when file reading ends.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(pcap_path)
        logger.info("Processing %s", pcap_path)
        self._refresh_analyzer_flags()

        try:
            with open(pcap_path, "rb") as stream:
                try:
                    self._read_packets(stream)
                except OSError as error:
                    self.stats["read_errors"] += 1
                    logger.warning("Read error (%s): continuing with data read so far", error)
        except ValueError as error:
            raise ValueError(f"{pcap_path}: {error}") from error

        if flush_at_end:
            self.flush()

    def process_files(self, pcap_paths: Iterable[str]) -> None:
        """Process a sequence of PCAP files in chronological order, holding conversation state across boundaries."""
        paths = list(pcap_paths)
        for index, path in enumerate(paths):
            self.process_file(path, flush_at_end=(index == len(paths) - 1))
