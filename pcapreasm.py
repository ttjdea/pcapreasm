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
import argparse
import bisect
import collections
import datetime
import functools
import heapq
import ipaddress
import json
import logging
import math
import os
import re
import socket
import struct
import sys
import zlib
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Dict, Iterable, List, Optional, Tuple

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
    "PcapFormatError",
    "AnalyzerError",
    "FilterSyntaxError",
    "compile_filter",
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
__version__ = "0.2.2"

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
FRAG_MAX_PIECES = 1400          # Max stored pieces per fragment set (a 68-byte MTU needs 1,366)

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
# Internal packet predicate: (ip_proto, src_raw, src_port, dst_raw, dst_port) -> keep?
_PacketPredicate = Callable[[int, bytes, int, bytes, int], bool]
logger = logging.getLogger(__name__)


class PcapFormatError(ValueError):
    """Raised when an input is not a readable classic PCAP file.

    Subclasses `ValueError`, so code written for 0.0.x (`except ValueError`) keeps working.
    """


class AnalyzerError(Exception):
    """Raised when user code called by the processor fails and the failure must not be hidden.

    Raised if an analyzer callback fails and `raise_on_analyzer_error=True` was given, and
    always if a `packet_filter` callable fails (a broken filter would otherwise silently
    drop or keep packets). The original exception is available as `__cause__`.
    """


class FilterSyntaxError(ValueError):
    """Raised when a `filter_expr` cannot be parsed or uses an unsupported construct."""


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
        truncated_segments: Number of segments whose IP packet was cut short by the
            capture's snaplen. Their payload is incomplete, so the resulting `gaps` may be
            caused by truncation rather than packet loss. (Added in 0.1.0.)
    """

    first_timestamp_ns: int
    last_timestamp_ns: int
    timeline: List[Tuple[int, bytes]]
    segment_count: int
    retrans_count: int
    gaps: List[Tuple[int, int]]
    is_closed: bool
    evict_reason: str
    truncated_segments: int = 0

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

# Return type structure for IP parser:
# (src_raw, dst_raw, proto, l4_data, fragment_info, truncated_by_snaplen)
_Fragment = Tuple[int, int, bool]
_ParsedIP = Tuple[bytes, bytes, int, bytes, Optional[_Fragment], bool]


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

    # Truncate payload to IP total length to eliminate Ethernet trailer padding.
    # A total length larger than the captured bytes means the capture's snaplen cut the
    # packet short (a total length of 0 is TSO/GSO offload and is not truncation).
    if 0 < ip_total_len < ip_header_len:
        return None  # Impossible length: cannot tell payload from link-layer padding
    if ip_header_len <= ip_total_len <= len(ip_packet):
        end, truncated = ip_total_len, False
    else:
        end, truncated = len(ip_packet), ip_total_len > len(ip_packet)
    return (
        ip_packet[IPV4_SRC_OFFSET:IPV4_SRC_OFFSET + 4],
        ip_packet[IPV4_DST_OFFSET:IPV4_DST_OFFSET + 4],
        ip_packet[IPV4_PROTO_OFFSET],
        ip_packet[ip_header_len:end],
        fragment,
        truncated,
    )


def _parse_ipv6(ip_packet: bytes) -> Optional[_ParsedIP]:
    """Parse an IPv6 header, skipping through extension headers. Returns None if invalid."""
    if len(ip_packet) < IPV6_HEADER_LEN or (ip_packet[0] >> 4) != 6:
        return None
    ip_payload_len = struct.unpack_from("!H", ip_packet, IPV6_PAYLOAD_LEN_OFFSET)[0]
    end = IPV6_HEADER_LEN + ip_payload_len
    truncated = False
    if ip_payload_len == 0 or end > len(ip_packet):  # Handle jumbo payloads / TSO
        truncated = ip_payload_len != 0  # payload_len 0 is jumbo/TSO; otherwise snaplen cut it
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
                return (
                    src_raw, dst_raw, ip_packet[offset],
                    ip_packet[offset + IPV6_FRAG_HEADER_LEN:end], fragment, truncated,
                )
            ext_len = IPV6_FRAG_HEADER_LEN  # Atomic fragment: proceed as normal header
        elif next_header == IPV6_EXT_AH:
            ext_len = (ip_packet[offset + 1] + 2) * 4
        else:
            ext_len = (ip_packet[offset + 1] + 1) * 8
        next_header = ip_packet[offset]
        offset += ext_len

    if offset > end:
        return None
    return src_raw, dst_raw, next_header, ip_packet[offset:end], None, truncated


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


def _describe_bad_header(global_header: bytes) -> str:
    """Build the error message for an unreadable global header, with a hint where possible.

    The message always starts with "Invalid pcap global header" (kept from 0.0.x).
    """
    magic = global_header[:4]
    message = f"Invalid pcap global header: {magic.hex()}"
    if magic == b"\x0a\x0d\x0d\x0a":
        return (
            message + " (this looks like a pcapng file, which is not supported; "
            "save it as classic pcap or convert it: editcap -F pcap in.pcapng out.pcap)"
        )
    if magic[:2] == b"\x1f\x8b":
        return (
            message + " (this looks like a gzip-compressed file; decompress it first, "
            "or pass gzip.open(path, 'rb') to process_stream)"
        )
    if len(global_header) < PCAP_GLOBAL_HEADER_LEN:
        return message + f" (file too short: {len(global_header)} bytes)"
    if len(magic) == 4 and struct.unpack_from("<I", magic)[0] in _MAGIC_TABLE:
        return message + " (unsupported pcap version)"
    return message


# -------------------------------------------------------------------------
# IP Fragment Reassembly State
# -------------------------------------------------------------------------
class _Intervals:
    """Sorted, disjoint, merged half-open integer intervals.

    Used to track which byte ranges have been received so that "is everything up to X
    present?" is answered incrementally (O(log n) per insertion) instead of re-sorting
    every buffered piece on each packet.
    """

    __slots__ = ("starts", "ends")

    def __init__(self) -> None:
        self.starts: List[int] = []
        self.ends: List[int] = []

    def add(self, start: int, end: int) -> bool:
        """Add `[start, end)`. Returns True if it covered any byte not covered before."""
        if end <= start:
            return False
        starts, ends = self.starts, self.ends
        if not ends or start > ends[-1]:  # Fast path: in-order data after a gap/at the start
            starts.append(start)
            ends.append(end)
            return True
        if start == ends[-1]:  # Fast path: directly extends the last interval
            ends[-1] = end
            return True
        lo = bisect.bisect_left(ends, start)    # First interval touching/overlapping `start`
        hi = bisect.bisect_right(starts, end)   # Intervals [lo, hi) touch/overlap `end`
        if lo < hi:
            if hi - lo == 1 and starts[lo] <= start and ends[lo] >= end:
                return False  # Already fully covered
            new_start = min(start, starts[lo])
            new_end = max(end, ends[hi - 1])
            starts[lo:hi] = [new_start]
            ends[lo:hi] = [new_end]
        else:
            starts.insert(lo, start)
            ends.insert(lo, end)
        return True

    def reach(self, base: int) -> int:
        """End of the contiguous coverage that contains `base` (or `base` if none does)."""
        index = bisect.bisect_right(self.starts, base) - 1
        if index >= 0 and self.ends[index] > base:
            return self.ends[index]
        return base


class _ContiguousCover:
    """Tracks the lowest contiguous block of received byte ranges.

    Answers "is everything from `base` up to X present?" for a TCP stream whose segments keep
    arriving (in any order) after the FIN. Blocks above the first gap wait in a min-heap and are
    absorbed once the gap is filled, so each segment costs O(log n) amortised, whatever the
    arrival order (a sorted list would be O(n) per out-of-order insertion).
    """

    __slots__ = ("lo", "hi", "heap")

    def __init__(self) -> None:
        self.lo: Optional[int] = None  # Start of the lowest block
        self.hi = 0                    # End (exclusive) of the lowest block
        self.heap: List[Tuple[int, int]] = []  # Other blocks (all start above `hi`)

    def add(self, start: int, end: int) -> None:
        if end <= start:
            return
        lo = self.lo
        if lo is None:
            self.lo, self.hi = start, end
        elif start < lo:
            if end >= lo:
                self.lo = start
                self.hi = max(self.hi, end)
            else:  # A new lowest block separated by a gap; the old one waits in the heap
                heapq.heappush(self.heap, (lo, self.hi))
                self.lo, self.hi = start, end
        elif start <= self.hi:
            if end > self.hi:
                self.hi = end
        else:
            heapq.heappush(self.heap, (start, end))
            return
        heap = self.heap
        while heap and heap[0][0] <= self.hi:
            block_end = heapq.heappop(heap)[1]
            if block_end > self.hi:
                self.hi = block_end

    def reach(self, base: int) -> int:
        """End of the contiguous coverage containing `base` (or `base` if none does)."""
        if self.lo is not None and self.lo <= base < self.hi:
            return self.hi
        return base


class _FragmentSet:
    """Container for fragments belonging to a single IP datagram."""

    __slots__ = ("pieces", "total_len", "size", "last_timestamp_ns", "cover", "truncated")

    def __init__(self, timestamp_ns: int):
        self.pieces: List[Tuple[int, bytes]] = []  # [(offset, payload_bytes)] (new coverage only)
        self.total_len: Optional[int] = None      # Resolved when final fragment arrives
        self.size = 0                             # Total buffered bytes
        self.last_timestamp_ns = timestamp_ns
        self.cover = _Intervals()                 # Byte ranges received so far
        self.truncated = False                    # Any piece was cut short by snaplen


class _FragmentReassembler:
    """Manages state for IPv4 and IPv6 fragment reassembly."""

    def __init__(self, timeout_ns: int, max_sets: int, stats: "collections.Counter[str]"):
        self._timeout_ns = timeout_ns
        self._max_sets = max_sets
        self._stats = stats
        self._sets: "collections.OrderedDict[Tuple[Any, ...], _FragmentSet]" = collections.OrderedDict()
        self.last_truncated = False  # Whether the most recently assembled datagram had a cut-short piece

    def expire(self, now_ns: int) -> None:
        """Evict incomplete fragment sets that have exceeded the timeout limit."""
        while self._sets:
            key, fragment_set = next(iter(self._sets.items()))
            if now_ns - fragment_set.last_timestamp_ns <= self._timeout_ns:
                break
            del self._sets[key]
            self._stats["frag_expired"] += 1

    def add(
        self, key: Tuple[Any, ...], offset: int, more_fragments: bool, data: bytes,
        timestamp_ns: int, truncated: bool = False,
    ) -> Optional[bytes]:
        """Add a fragment piece and return reassembled L4 payload if complete.

        Pieces that add no new byte range (duplicates, fully overlapped) are not stored, so
        buffered size stays bounded. Pieces are stored whole, so where two stored pieces overlap
        the one with the lower offset supplies the overlapping bytes. `last_truncated`
        reports, after a successful return, whether any piece was cut short by snaplen.
        """
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
        if truncated:
            fragment_set.truncated = True
        if fragment_set.cover.add(offset, offset + len(data)):
            fragment_set.pieces.append((offset, data))
            fragment_set.size += len(data)
            if len(fragment_set.pieces) > FRAG_MAX_PIECES:
                del self._sets[key]
                self._stats["frag_too_many_pieces"] += 1
                return None

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

        # Only assemble once the received ranges are known to cover [0, total_len).
        # (Previously every arriving piece triggered a full sort: quadratic in piece count.)
        cover = fragment_set.cover
        if fragment_set.total_len > 0 and (
            not cover.starts or cover.starts[0] != 0 or cover.ends[0] < fragment_set.total_len
        ):
            return None

        assembled = self._try_assemble(fragment_set)
        if assembled is not None:
            self.last_truncated = fragment_set.truncated
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
_SEQ_FOLLOW_LIMIT = 1 << 30  # Max sequence step that moves the unwrapping reference


class _TCPReassembler:
    """Reassembles a single unidirectional TCP stream."""

    def __init__(self) -> None:
        self.chunks: List[Tuple[int, bytes, int]] = []  # [(unwrapped_seq, payload, timestamp_ns)]
        self.start_seq: Optional[int] = None
        self.fin_seq: Optional[int] = None
        self.is_rst = False
        self.first_timestamp_ns: Optional[int] = None
        self.last_timestamp_ns = 0
        self.syn_raw: Optional[int] = None  # Raw ISN of the SYN seen in this direction
        self.truncated_segments = 0
        self._ref_raw_seq: Optional[int] = None
        self._ref_unwrapped_seq = 0
        self._finished_cache: Optional[bool] = None
        # Byte ranges received, built lazily the first time FIN-completeness is checked and
        # then updated incrementally (see `_covers_up_to_fin`).
        self._cover: Optional[_ContiguousCover] = None
        self._cover_n = 0  # Number of `chunks` already folded into `_cover`
        self._cover_base: Optional[int] = None  # `start_seq` the cover was built for

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
        # Follow the stream only through small steps. A packet far from the reference (a junk or
        # spoofed packet) is placed relative to the unchanged reference but does not move it,
        # so a few such packets cannot accumulate a 2**32 error for the genuine packets after them.
        if -_SEQ_FOLLOW_LIMIT < delta < _SEQ_FOLLOW_LIMIT:
            self._ref_raw_seq = seq
            self._ref_unwrapped_seq = unwrapped_seq
        return unwrapped_seq

    def add(self, seq: int, payload: bytes, timestamp_ns: int, flags: int, truncated: bool = False) -> int:
        """Add a TCP segment and return the byte length added to the buffer."""
        if self.first_timestamp_ns is None:
            self.first_timestamp_ns = timestamp_ns
        self.last_timestamp_ns = timestamp_ns
        unwrapped_seq = self._unwrap_seq(seq)
        data_seq = unwrapped_seq

        if flags & TCP_SYN:
            data_seq += 1
            self.start_seq = data_seq
            self.syn_raw = seq

        if payload:
            self.chunks.append((data_seq, payload, timestamp_ns))
            self._finished_cache = None
            if truncated:
                self.truncated_segments += 1

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
        """Verify contiguity from start_seq (or the lowest seen byte) up to fin_seq.

        Coverage is kept as merged intervals and only newly arrived chunks are folded in on
        each call, so a stream that keeps receiving segments after a FIN (e.g. while a gap
        stays unfilled) costs O(log n) per segment rather than a full re-sort each time.
        """
        assert self.fin_seq is not None
        base = self.start_seq
        cover = self._cover
        if cover is None or self._cover_base != base:
            # (Re)build: the first check, or the SYN arrived/changed after data was already folded in.
            cover = self._cover = _ContiguousCover()
            self._cover_n = 0
            self._cover_base = base
        chunks = self.chunks
        for index in range(self._cover_n, len(chunks)):
            seq, payload, _ = chunks[index]
            start = seq if base is None or seq > base else base  # Bytes before the SYN do not count
            cover.add(start, seq + len(payload))
        self._cover_n = len(chunks)

        if base is None:
            base = cover.lo if cover.lo is not None else self.fin_seq
        return cover.reach(base) >= self.fin_seq

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
        self._cover = None
        self._cover_n = 0


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

    def has_any_data(self) -> bool:
        """True if payload has been buffered in either direction."""
        return self.directions[0].has_data or self.directions[1].has_data

    def fully_closing(self) -> bool:
        """True if every direction that was seen has sent FIN or RST.

        A conversation where only one side has closed is a half-close: the other side may
        legitimately keep sending for a long time, so it must not be timed out as "closing".
        """
        for index in (0, 1):
            direction = self.directions[index]
            if self.seen[index] and direction.fin_seq is None and not direction.is_rst:
                return False
        return True


# -------------------------------------------------------------------------
# tcpdump-style filter expressions
# -------------------------------------------------------------------------
_FILTER_TOKEN_RE = re.compile(r"\s+|(&&|\|\||[()!]|[^\s()!&|]+)|(.)")
_FILTER_AND = ("and", "&&")
_FILTER_OR = ("or", "||")
_FILTER_NOT = ("not", "!")
_FILTER_PROTOS = ("tcp", "udp", "ip", "ip6")
_FILTER_TYPES = ("host", "net", "port", "portrange")
_FILTER_MAX_DEPTH = 100  # Max nesting of parentheses / 'not' (deeper would risk RecursionError)
_FILTER_PORT_RE = re.compile(r"[0-9]{1,5}")  # ASCII digits only (int() would also accept "1_0", "+80", ...)
_FILTER_SUPPORTED_HELP = (
    "supported: tcp, udp, ip, ip6, [src|dst|src or dst|src and dst] host/net/port/portrange, "
    "and, or, not, parentheses"
)


def _filter_directional(direction: Optional[str], match: Callable[[Any], bool]) -> Callable[[Any, Any], bool]:
    """Apply `match` to (source, destination) according to the direction qualifier."""
    if direction == "src":
        return lambda a, b: match(a)
    if direction == "dst":
        return lambda a, b: match(b)
    if direction == "both":
        return lambda a, b: match(a) and match(b)
    return lambda a, b: match(a) or match(b)


def _filter_proto_test(proto: Optional[str]) -> Optional[_PacketPredicate]:
    if proto is None:
        return None
    if proto == "tcp":
        return lambda p, s, sp, d, dp: p == IPPROTO_TCP
    if proto == "udp":
        return lambda p, s, sp, d, dp: p == IPPROTO_UDP
    if proto == "ip":
        return lambda p, s, sp, d, dp: len(s) == 4
    return lambda p, s, sp, d, dp: len(s) == 16  # "ip6"


def _filter_primitive(proto: Optional[str], direction: Optional[str], ptype: str, literal: str) -> _PacketPredicate:
    """Compile one `[proto] [dir] type value` primitive into a packet predicate."""
    core: _PacketPredicate
    if ptype in ("host", "net"):
        try:
            if ptype == "host":
                packed = ipaddress.ip_address(literal).packed
                addr_match: Callable[[bytes], bool] = lambda raw: raw == packed  # noqa: E731
            else:
                if "/" not in literal:
                    raise FilterSyntaxError(f"net {literal!r}: write the network in CIDR form, e.g. 10.0.0.0/8")
                network = ipaddress.ip_network(literal, strict=True)
                net_len = network.max_prefixlen // 8
                net_int, mask = int(network.network_address), int(network.netmask)
                addr_match = lambda raw: len(raw) == net_len and (int.from_bytes(raw, "big") & mask) == net_int  # noqa: E731
        except ValueError as error:  # includes FilterSyntaxError raised above (it is a ValueError)
            if isinstance(error, FilterSyntaxError):
                raise
            raise FilterSyntaxError(
                f"{ptype} {literal!r}: only literal IP addresses/CIDR networks are supported "
                f"(no hostnames or DNS lookups): {error}"
            ) from error
        by_addr = _filter_directional(direction, addr_match)
        core = lambda p, s, sp, d, dp: by_addr(s, d)  # noqa: E731
    else:
        try:
            if ptype == "port":
                if not _FILTER_PORT_RE.fullmatch(literal):
                    raise ValueError("expected digits")
                low = high = int(literal)
            else:
                low_text, separator, high_text = literal.partition("-")
                if not (
                    separator and _FILTER_PORT_RE.fullmatch(low_text) and _FILTER_PORT_RE.fullmatch(high_text)
                ):
                    raise ValueError("expected LOW-HIGH")
                low, high = int(low_text), int(high_text)
        except ValueError:
            raise FilterSyntaxError(
                f"{ptype} {literal!r}: expected a numeric "
                + ("port number (service names are not supported)" if ptype == "port" else "range like 8000-8100")
            ) from None
        if not (0 <= low <= high <= 65535):
            raise FilterSyntaxError(f"{ptype} {literal!r}: ports must satisfy 0 <= low <= high <= 65535")
        by_port = _filter_directional(direction, lambda port: low <= port <= high)
        core = lambda p, s, sp, d, dp: by_port(sp, dp)  # noqa: E731

    proto_test = _filter_proto_test(proto)
    if proto_test is None:
        return core
    return lambda p, s, sp, d, dp: proto_test(p, s, sp, d, dp) and core(p, s, sp, d, dp)


class _FilterParser:
    """Recursive-descent parser turning a tcpdump-style expression into a predicate."""

    def __init__(self, text: str) -> None:
        self.tokens: List[str] = []
        for match in _FILTER_TOKEN_RE.finditer(text):
            if match.group(2) is not None:
                raise FilterSyntaxError(f"unexpected character {match.group(2)!r} in filter expression")
            if match.group(1) is not None:
                self.tokens.append(match.group(1))
        self.pos = 0
        self.depth = 0  # Current nesting of parentheses / 'not' (bounded by _FILTER_MAX_DEPTH)
        # Qualifiers of the previous primitive, so "port 80 or 443" means "port 80 or port 443"
        self.last_qualifiers: Optional[Tuple[Optional[str], Optional[str], str]] = None

    def parse(self) -> _PacketPredicate:
        if not self.tokens:
            return lambda p, s, sp, d, dp: True  # Like tcpdump, an empty expression matches everything
        node = self._expression()
        if self.pos != len(self.tokens):
            raise FilterSyntaxError(f"unexpected {self.tokens[self.pos]!r} in filter expression")
        return node

    def _peek(self, offset: int = 0) -> Optional[str]:
        index = self.pos + offset
        return self.tokens[index].lower() if index < len(self.tokens) else None

    def _expression(self) -> _PacketPredicate:
        # A chain "a or b or c ..." is collected into one list and evaluated in a loop. Building
        # nested closures instead would recurse once per term and hit Python's recursion limit
        # on long (e.g. block-list sized) expressions.
        terms = [self._unary()]
        operator: Optional[str] = None
        while True:
            token = self._peek()
            if token in _FILTER_AND:
                current = "and"
            elif token in _FILTER_OR:
                current = "or"
            else:
                break
            if operator is not None and operator != current:
                raise FilterSyntaxError(
                    "mixing 'and' and 'or' without parentheses is ambiguous (tcpdump treats them as "
                    "equal precedence, left to right); add parentheses"
                )
            operator = current
            self.pos += 1
            terms.append(self._unary())
        return self._combine(operator, terms)

    @staticmethod
    def _combine(operator: Optional[str], terms: List[_PacketPredicate]) -> _PacketPredicate:
        if operator is None:
            return terms[0]
        funcs = tuple(terms)
        if operator == "and":
            def all_of(p: int, s: bytes, sp: int, d: bytes, dp: int) -> bool:
                for func in funcs:
                    if not func(p, s, sp, d, dp):
                        return False
                return True
            return all_of

        def any_of(p: int, s: bytes, sp: int, d: bytes, dp: int) -> bool:
            for func in funcs:
                if func(p, s, sp, d, dp):
                    return True
            return False
        return any_of

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > _FILTER_MAX_DEPTH:
            raise FilterSyntaxError(
                f"filter expression is nested too deeply (more than {_FILTER_MAX_DEPTH} levels of "
                "parentheses / 'not')"
            )

    def _unary(self) -> _PacketPredicate:
        token = self._peek()
        if token in _FILTER_NOT:
            self.pos += 1
            self._enter()
            inner = self._unary()
            self.depth -= 1
            return lambda p, s, sp, d, dp: not inner(p, s, sp, d, dp)
        if token == "(":
            self.pos += 1
            self._enter()
            node = self._expression()
            if self._peek() != ")":
                raise FilterSyntaxError("missing closing parenthesis in filter expression")
            self.pos += 1
            self.depth -= 1
            return node
        return self._primitive()

    def _is_operator(self, token: Optional[str]) -> bool:
        return token is None or token in _FILTER_AND + _FILTER_OR + _FILTER_NOT + ("(", ")")

    def _literal(self, context: str) -> str:
        if self._is_operator(self._peek()):
            raise FilterSyntaxError(f"expected a value after {context!r} in filter expression")
        literal = self.tokens[self.pos]
        self.pos += 1
        return literal

    def _primitive(self) -> _PacketPredicate:
        token = self._peek()
        if self._is_operator(token):
            raise FilterSyntaxError("unexpected end or operator in filter expression; expected a primitive")
        proto: Optional[str] = None
        direction: Optional[str] = None

        if token in _FILTER_PROTOS:
            proto = token
            self.pos += 1
            token = self._peek()
        if token in ("src", "dst"):
            direction = token
            self.pos += 1
            partner = "dst" if direction == "src" else "src"
            if direction == "src" and self._peek() in _FILTER_AND + _FILTER_OR and self._peek(1) == partner:
                direction = "both" if self._peek() in _FILTER_AND else "either"
                self.pos += 2
            token = self._peek()

        if token in _FILTER_TYPES:
            ptype = str(token)
            self.pos += 1
            literal = self._literal(ptype)
        elif proto is not None and direction is None and self._is_operator(token):
            node = _filter_proto_test(proto)
            assert node is not None
            return node  # Bare protocol primitive such as "tcp"
        elif proto is None and direction is None and self.last_qualifiers is not None:
            # Implicit qualifiers: "host a or b" means "host a or host b"
            proto, direction, ptype = self.last_qualifiers
            literal = self._literal(ptype)
        else:
            bad = self.tokens[self.pos] if self.pos < len(self.tokens) else "end of expression"
            raise FilterSyntaxError(
                f"unsupported or unexpected {bad!r} in filter expression ({_FILTER_SUPPORTED_HELP})"
            )

        self.last_qualifiers = (proto, direction, ptype)
        return _filter_primitive(proto, direction, ptype, literal)


def compile_filter(expression: str) -> _PacketPredicate:
    """Compile a tcpdump-style filter expression into a packet predicate. (Added in 0.1.0.)

    This is a deliberately small subset of tcpdump / pcap-filter syntax, evaluated on parsed
    TCP/UDP packets (not compiled to BPF)::

        [tcp|udp|ip|ip6]                              protocol
        [tcp|udp|ip|ip6] [src|dst|src or dst|src and dst] host  <IP address>
        [tcp|udp|ip|ip6] [src|dst|src or dst|src and dst] net   <CIDR, e.g. 10.0.0.0/8>
        [tcp|udp|ip|ip6] [src|dst|src or dst|src and dst] port  <number>
        [tcp|udp|ip|ip6] [src|dst|src or dst|src and dst] portrange <low>-<high>
        not / !,  and / &&,  or / ||,  ( ... )

    Differences from tcpdump, by design: hostnames and service names are not resolved (use
    IP literals and port numbers); mixing `and` with `or` at one level without parentheses is
    rejected instead of being evaluated left to right; `net` needs CIDR notation; `ether`,
    `vlan`, byte-offset expressions such as `tcp[13]`, `less`/`greater` and other protocols
    are not supported and raise `FilterSyntaxError`. Like tcpdump, `port 80` without a
    protocol matches both TCP and UDP, and `port 80 or 443` reuses the previous qualifiers.
    Non-first IP fragments carry no port, so the filter is applied after fragment
    reassembly (tcpdump's `port` does not match such fragments at all).

    Returns:
        A function `f(ip_proto, src_raw, src_port, dst_raw, dst_port) -> bool` where the
        addresses are packed bytes (4 bytes for IPv4, 16 for IPv6).

    Raises:
        FilterSyntaxError: If the expression is invalid or uses an unsupported construct.
    """
    return _FilterParser(expression).parse()


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------
class BaseAnalyzer(abc.ABC):
    """Abstract base class for custom packet analyzers.

    Subclass `BaseAnalyzer` and override the callbacks corresponding to desired events.
    By default, exceptions raised within callbacks are logged and swallowed to prevent
    pipeline failure (set `raise_on_analyzer_error=True` on the processor to raise
    `AnalyzerError` instead).
    """

    def on_file_start(self, path: str) -> None:
        """Invoked before a file (or stream) starts being read. (Added in 0.1.0.)"""

    def on_file_end(self, path: str) -> None:
        """Invoked after a file (or stream) has been read, before any final flush. (Added in 0.1.0.)"""

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
        raise_on_analyzer_error: Raise `AnalyzerError` when an analyzer callback fails instead
            of logging and continuing. (Added in 0.1.0.)
        segment_overhead_bytes: Bytes added to the buffer accounting of every buffered
            segment, on top of its payload, when checking `max_conversation_bytes` and
            `max_total_bytes`. Many tiny segments use far more memory than their payload
            suggests (about 110-220 bytes per segment were measured), so the default 150
            makes the limits track real memory. Pass 0 for the 0.0.x/0.1.x behaviour
            (payload bytes only). (Added in 0.1.0 with default 0; default 150 since 0.2.0.)
        packet_filter: Optional callable `f(ip_proto, flow_id) -> bool`, called for every
            TCP/UDP packet (after IP fragment reassembly). Return False to drop the packet
            before any stream state is created. `ip_proto` is 6 (TCP) or 17 (UDP).
            (Added in 0.1.0.)
        filter_expr: Optional tcpdump-style expression, e.g. `"tcp and port 80"`; see
            `compile_filter` for the supported subset. Combined with `packet_filter` by AND.
            (Added in 0.1.0.)
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
        raise_on_analyzer_error: bool = False,
        segment_overhead_bytes: int = 150,
        packet_filter: Optional[Callable[[int, FlowId], bool]] = None,
        filter_expr: Optional[str] = None,
    ):
        if max_conversations < 1:
            raise ValueError("max_conversations must be >= 1")
        if segment_overhead_bytes < 0:
            raise ValueError("segment_overhead_bytes must be >= 0")
        self.analyzers = analyzers or []
        self.evict_on_fin = evict_on_fin
        self.stats: "collections.Counter[str]" = collections.Counter()
        self._raise_on_analyzer_error = raise_on_analyzer_error
        self._segment_overhead = segment_overhead_bytes
        self._filter = self._build_filter(packet_filter, filter_expr)
        self._current_name = "<unknown>"
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

    @staticmethod
    def _build_filter(
        packet_filter: Optional[Callable[[int, FlowId], bool]], filter_expr: Optional[str]
    ) -> Optional[_PacketPredicate]:
        """Combine `filter_expr` and `packet_filter` into one internal predicate (or None)."""
        predicates: List[_PacketPredicate] = []
        if filter_expr is not None and filter_expr.strip():
            predicates.append(compile_filter(filter_expr))
        if packet_filter is not None:
            user_filter = packet_filter

            def call_user_filter(proto: int, src: bytes, sport: int, dst: bytes, dport: int) -> bool:
                try:
                    return bool(user_filter(proto, _make_flow_id(src, sport, dst, dport)))
                except Exception as error:
                    # Wrapped so that e.g. an OSError raised by a filter is not mistaken for a read error.
                    raise AnalyzerError(f"packet_filter raised {error!r}") from error

            predicates.append(call_user_filter)
        if not predicates:
            return None
        if len(predicates) == 1:
            return predicates[0]
        first, second = predicates
        return lambda proto, src, sport, dst, dport: (
            first(proto, src, sport, dst, dport) and second(proto, src, sport, dst, dport)
        )

    def _dispatch(self, method_name: str, *args: Any) -> None:
        """Dispatch event callbacks to registered analyzers."""
        for analyzer in self.analyzers:
            try:
                getattr(analyzer, method_name)(*args)
            except Exception as error:
                if self._raise_on_analyzer_error:
                    raise AnalyzerError(f"Analyzer {analyzer!r} failed in {method_name}: {error}") from error
                logger.exception("Analyzer %s failed in %s", analyzer, method_name)

    # -- Clock & Maintenance ------------------------------------------------
    def _advance_clock(self, timestamp_ns: int) -> None:
        """Advance capture clock and trigger periodic sweep every second."""
        # The clock follows the capture time of the current packet (it is not a high-water mark):
        # one packet stamped far in the future must not stop idle/linger/fragment sweeps for the
        # rest of the run, and files whose timestamps start earlier than the previous file's
        # must still be swept. A jump in either direction triggers a sweep.
        self._now_ns = timestamp_ns
        if abs(self._now_ns - self._last_sweep_ns) >= SWEEP_INTERVAL_NS:
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
                elif (
                    now - conversation.last_timestamp_ns > self._close_linger_ns
                    and conversation.fully_closing()
                ):
                    # A half-close (only one side sent FIN) is NOT timed out here: the other
                    # side may keep the connection open and respond much later. Such
                    # conversations end by FIN/RST, `idle_timeout`, the size limits or flush.
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
        self.stats["tcp_conversations"] += 1
        self.stats["evict_" + reason] += 1
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
                truncated_segments=reassembler.truncated_segments,
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

    def _handle_tcp(
        self, timestamp_ns: int, src_raw: bytes, dst_raw: bytes, l4_data: bytes, truncated: bool = False
    ) -> None:
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
                if payload or flags & (TCP_SYN | TCP_FIN | TCP_RST):
                    self.stats["late_packets"] += 1
                else:
                    # A bare ACK after close is normal (e.g. the final ACK of the FIN
                    # exchange), so it is counted separately from real late data.
                    self.stats["late_acks"] += 1
                return

        conversation = self._conversations.get(key)
        if conversation is not None and is_initial_syn and self._starts_new_connection(
            conversation, index, seq
        ):
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
        added = conversation.directions[index].add(seq, payload, timestamp_ns, flags, truncated)
        if added:
            added += self._segment_overhead  # Accounted size of a buffered segment
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

    @staticmethod
    def _starts_new_connection(conversation: _TCPConversation, index: int, seq: int) -> bool:
        """Decide whether an initial SYN (no ACK) on a tracked 4-tuple begins a NEW connection.

        - If this direction already sent a SYN, a different ISN means a new connection. The
          same ISN is a SYN retransmission, unless this direction has already sent data: a
          retransmitted SYN cannot follow data, so that is a new connection that happens to
          reuse the ISN (constant-ISN stacks, replay tools). This is what 0.0.1 did.
        - Otherwise (no SYN seen from this side yet) it is a new connection only if data from
          an earlier connection is already buffered, in either direction. Looking at both
          directions matters for server-first protocols (SMTP, SSH, ...) where the SYN sender
          has not sent anything yet.

        Known limit: a new connection that reuses the client's ISN *and* only ever had
        server-first data is indistinguishable from a late duplicate SYN and is treated as one.
        """
        direction = conversation.directions[index]
        if direction.syn_raw is not None:
            return direction.syn_raw != seq or direction.has_data
        return conversation.has_any_data()

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

        src_raw, dst_raw, proto, l4_data, fragment, truncated = parsed_ip
        if truncated:
            self.stats["truncated_packets"] += 1
        if fragment is not None:
            self.stats["fragments"] += 1
            if not self._reassemble_fragments:
                self.stats["fragments_dropped"] += 1
                return
            identification, fragment_offset, more_fragments = fragment
            assembled = self._fragments.add(
                (src_raw, dst_raw, proto, identification),
                fragment_offset, more_fragments, l4_data, timestamp_ns, truncated,
            )
            if assembled is None:
                return
            self.stats["frag_reassembled"] += 1
            l4_data = assembled
            truncated = self._fragments.last_truncated

        if proto != IPPROTO_TCP and proto != IPPROTO_UDP:
            return
        if self._filter is not None and len(l4_data) >= 4:
            src_port, dst_port = struct.unpack_from("!HH", l4_data, 0)
            if not self._filter(proto, src_raw, src_port, dst_raw, dst_port):
                self.stats["filtered"] += 1
                return
        if proto == IPPROTO_TCP:
            self._handle_tcp(timestamp_ns, src_raw, dst_raw, l4_data, truncated)
        else:
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

    def _check_linktype(self, linktype: int) -> None:
        if linktype not in _SUPPORTED_LINKTYPES:
            logger.warning(
                "%s: Unsupported linktype %d: packets will be skipped", self._current_name, linktype
            )

    def _read_packets(self, stream: BinaryIO) -> None:
        """Stream PCAP records from file descriptor."""
        name = self._current_name
        global_header = self._read_exact(stream, PCAP_GLOBAL_HEADER_LEN)
        if global_header is None:
            logger.warning("%s: Empty file", name)
            return

        parsed = _parse_global_header(global_header)
        if parsed is None:
            raise PcapFormatError(_describe_bad_header(global_header))

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
                logger.warning("%s: Unusually large incl_len %d, stopping", name, incl_len)
                break
            if incl_len == 0:
                continue

            packet = self._read_exact(stream, incl_len)
            if packet is None or len(packet) < incl_len:
                logger.warning("%s: Truncated pcap (last packet incomplete)", name)
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

    def process_stream(self, stream: BinaryIO, flush_at_end: bool = True, name: str = "<stream>") -> None:
        """Process a classic PCAP read from an open binary file-like object. (Added in 0.1.0.)

        Args:
            stream: Binary stream positioned at the PCAP global header (e.g. `io.BytesIO`,
                an already-open file, a decompressing reader such as `gzip.open(path, "rb")`).
                The caller keeps ownership; it is not closed.
            flush_at_end: Whether to flush active streams when reading ends.
            name: Label used in log messages, error messages and `on_file_start/end`.

        Raises:
            PcapFormatError: If the data is not a classic PCAP.
        """
        self._refresh_analyzer_flags()
        self._current_name = name
        self._dispatch("on_file_start", name)
        try:
            try:
                self._read_packets(stream)
            except (OSError, EOFError, zlib.error) as error:
                # EOFError / zlib.error: a truncated or corrupt gzip/zlib stream passed in by the caller
                self.stats["read_errors"] += 1
                logger.warning("%s: Read error (%s): continuing with data read so far", name, error)
            except PcapFormatError as error:
                raise PcapFormatError(f"{name}: {error}") from error
        finally:
            self._dispatch("on_file_end", name)

        if flush_at_end:
            self.flush()

    def process_file(self, pcap_path: "str | os.PathLike[str]", flush_at_end: bool = True) -> None:
        """Process a single PCAP file.

        Args:
            pcap_path: Path to raw classic PCAP file or named pipe.
            flush_at_end: Whether to flush active streams when file reading ends.

        Raises:
            FileNotFoundError: If the file does not exist.
            PcapFormatError: If the file is not a classic PCAP (a `ValueError` subclass).
        """
        path = os.fspath(pcap_path)
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        logger.info("Processing %s", path)
        with open(path, "rb") as stream:
            self.process_stream(stream, flush_at_end=flush_at_end, name=path)

    def process_files(self, pcap_paths: Iterable["str | os.PathLike[str]"], on_error: str = "raise") -> None:
        """Process a sequence of PCAP files in chronological order, holding conversation state across boundaries.

        Args:
            pcap_paths: Files in chronological order.
            on_error: `"raise"` (default, the 0.0.x behaviour) stops at the first unreadable
                file and raises; streams buffered so far stay buffered (call `flush()` if
                you want them delivered). `"skip"` logs a warning, counts the file in
                `stats["failed_files"]`, continues with the remaining files and still flushes
                at the end.
        """
        if on_error not in ("raise", "skip"):
            raise ValueError('on_error must be "raise" or "skip"')
        paths = list(pcap_paths)
        for index, path in enumerate(paths):
            is_last = index == len(paths) - 1
            try:
                self.process_file(path, flush_at_end=is_last)
            except (PcapFormatError, OSError) as error:
                if on_error == "raise":
                    raise
                self.stats["failed_files"] += 1
                logger.warning("Skipping %s: %s", os.fspath(path), error)
                if is_last:
                    self.flush()


# -------------------------------------------------------------------------
# Command line (`python -m pcapreasm`, added in 0.2.0)
# -------------------------------------------------------------------------
def _format_timestamp(timestamp_ns: int) -> str:
    """UTC time with millisecond precision, e.g. `2026-11-16T12:34:56.789Z`."""
    seconds, nanos = divmod(timestamp_ns, 1_000_000_000)
    moment = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return "%s.%03dZ" % (moment.strftime("%Y-%m-%dT%H:%M:%S"), nanos // 1_000_000)


class _OutputStopped(BaseException):
    """Raised inside the command line's analyzer when stdout cannot be written to.

    `error` is None for a closed pipe (normal, e.g. `| head`), otherwise the cause.
    """

    def __init__(self, error: Optional[BaseException]) -> None:
        super().__init__(error)
        self.error = error


_cli_output_failed = False  # set by main(); _script_main() then silences the interpreter's own flush at exit


def _silence_stdout() -> None:
    """After a broken pipe, point stdout at /dev/null so Python does not complain again at exit."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _endpoint(host: str, port: int) -> str:
    return "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)


class _SummaryAnalyzer(BaseAnalyzer):
    """Prints one line per TCP conversation and per UDP flow (used by the command line)."""

    def __init__(self, out: Any, fmt: str, show_udp: bool) -> None:
        self._out = out
        self._json = fmt == "jsonl"
        self._show_udp = show_udp
        self._udp: Dict[FlowId, List[int]] = {}  # flow_id -> [datagrams, bytes, first_ns, last_ns]

    def _emit(self, record: Dict[str, Any], text: str) -> None:
        line = (json.dumps(record, ensure_ascii=False, sort_keys=True) if self._json else text) + "\n"
        try:
            self._out.write(line)
        except BrokenPipeError:
            # e.g. `| head`. A BaseException is not swallowed by the analyzer error handling.
            raise _OutputStopped(None) from None
        except (OSError, ValueError, AttributeError) as error:  # disk full, closed or missing stdout
            raise _OutputStopped(error) from None

    def on_tcp_conversation(self, conversation: TCPConversation) -> None:
        client, server = conversation.client, conversation.server
        src, sport, dst, dport = client.flow_id
        gaps = client.meta.gap_count + server.meta.gap_count
        record: Dict[str, Any] = {
            "type": "tcp",
            "first": _format_timestamp(conversation.first_timestamp_ns),
            "last": _format_timestamp(conversation.last_timestamp_ns),
            "client": _endpoint(src, sport),
            "server": _endpoint(dst, dport),
            "client_bytes": len(client.data),
            "server_bytes": len(server.data),
            "gaps": gaps,
            "retransmissions": client.meta.retrans_count + server.meta.retrans_count,
            "truncated_segments": client.meta.truncated_segments + server.meta.truncated_segments,
            "client_certain": conversation.client_certain,
            "evict_reason": conversation.evict_reason,
        }
        text = "%s TCP %s -> %s c2s=%dB s2c=%dB gaps=%d end=%s%s" % (
            record["first"], record["client"], record["server"], record["client_bytes"],
            record["server_bytes"], gaps, conversation.evict_reason,
            "" if conversation.client_certain else " (client/server guessed)",
        )
        self._emit(record, text)

    def on_udp_datagram(self, flow_id: FlowId, payload: bytes, timestamp_ns: int) -> None:
        if not self._show_udp:
            return
        entry = self._udp.get(flow_id)
        if entry is None:
            self._udp[flow_id] = [1, len(payload), timestamp_ns, timestamp_ns]
        else:
            entry[0] += 1
            entry[1] += len(payload)
            entry[3] = timestamp_ns

    def on_complete(self) -> None:
        for flow_id, (datagrams, size, first_ns, last_ns) in sorted(self._udp.items(), key=lambda item: item[1][2]):
            src, sport, dst, dport = flow_id
            record = {
                "type": "udp",
                "first": _format_timestamp(first_ns),
                "last": _format_timestamp(last_ns),
                "src": _endpoint(src, sport),
                "dst": _endpoint(dst, dport),
                "datagrams": datagrams,
                "bytes": size,
            }
            self._emit(record, "%s UDP %s -> %s datagrams=%d bytes=%dB" % (
                record["first"], record["src"], record["dst"], datagrams, size))


def _build_argument_parser() -> "argparse.ArgumentParser":
    parser = argparse.ArgumentParser(
        prog="python -m pcapreasm",
        description="Summarise the TCP conversations (and optionally UDP flows) in classic PCAP files. "
        "Times are UTC. Output goes to stdout; statistics and warnings go to stderr.",
    )
    parser.add_argument("pcap", nargs="*", help="PCAP files, in chronological order (use - for stdin)")
    parser.add_argument("-l", "--file-list", action="append", default=[], metavar="FILE",
                        help="text file with one PCAP path per line (blank lines ignored); may be repeated")
    parser.add_argument("-f", "--filter", dest="filter_expr", metavar="EXPR",
                        help='tcpdump-style filter, e.g. "tcp and port 80"')
    parser.add_argument("--udp", action="store_true", help="also print one line per UDP flow")
    parser.add_argument("--format", choices=("text", "jsonl"), default="text",
                        help="output format (default: text)")
    parser.add_argument("--on-error", choices=("raise", "skip"), default="raise",
                        help="what to do with an unreadable file (default: raise = stop with exit code 1)")
    parser.add_argument("--idle-timeout", type=float, default=300.0, metavar="SEC",
                        help="finish a TCP conversation idle for SEC seconds of capture time (default: 300, 0 = off)")
    parser.add_argument("--max-memory-mb", type=int, default=1024, metavar="MB",
                        help="buffer limit; the oldest conversations are finished first (default: 1024, 0 = off)")
    parser.add_argument("--max-conversations", type=int, default=5000, metavar="N",
                        help="max simultaneously tracked TCP conversations (default: 5000)")
    parser.add_argument("--no-fragments", action="store_true", help="do not reassemble IP fragments")
    parser.add_argument("--stats", action="store_true", help="print processing statistics to stderr")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    parser.add_argument("--version", action="version", version="pcapreasm " + __version__)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Command line entry point.

    Returns the exit code instead of exiting: 0 ok, 1 runtime error (unreadable file, not a classic
    PCAP, output cannot be written, or a file skipped with `--on-error skip`), 2 usage error.
    """
    try:
        return _run_cli(argv)
    except SystemExit as stop:  # argparse: --help / --version / usage errors
        code = stop.code
        return code if isinstance(code, int) else (0 if code is None else 1)


def _run_cli(argv: Optional[List[str]]) -> int:
    global _cli_output_failed
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s",
    )

    paths: List[str] = list(args.pcap)
    try:
        for list_path in args.file_list:
            with open(list_path, "r", encoding="utf-8-sig", errors="surrogateescape") as handle:
                paths.extend(line.rstrip("\r\n") for line in handle if line.strip())
    except OSError as error:
        print("Error: %s" % error, file=sys.stderr)
        return 1
    if not paths:
        parser.error("no PCAP files given")
    if "-" in paths and paths != ["-"]:
        parser.error("'-' (standard input) cannot be combined with other files")
    if not math.isfinite(args.idle_timeout) or args.idle_timeout < 0:
        parser.error("--idle-timeout must be a finite number >= 0")
    if args.max_memory_mb < 0 or args.max_conversations < 1:
        parser.error("--max-memory-mb must be >= 0 and --max-conversations >= 1")

    out = sys.stdout
    if out is None:
        print("Error: standard output is not available", file=sys.stderr)
        return 1
    try:
        processor = PcapStreamProcessor(
            analyzers=[_SummaryAnalyzer(out, args.format, args.udp)],
            max_conversations=args.max_conversations,
            idle_timeout=args.idle_timeout or None,
            max_total_bytes=(args.max_memory_mb << 20) or None,
            reassemble_fragments=not args.no_fragments,
            filter_expr=args.filter_expr,
        )
    except FilterSyntaxError as error:
        parser.error("invalid filter: %s" % error)

    try:
        if paths == ["-"]:
            stdin = getattr(sys.stdin, "buffer", None)
            if stdin is None:
                print("Error: standard input is not available", file=sys.stderr)
                return 1
            processor.process_stream(stdin, name="<stdin>")
        else:
            processor.process_files(paths, on_error=args.on_error)
        out.flush()
    except _OutputStopped as stopped:
        _cli_output_failed = True
        if stopped.error is None:
            return 0
        print("Error: cannot write to standard output: %s" % stopped.error, file=sys.stderr)
        return 1
    except BrokenPipeError:
        _cli_output_failed = True
        return 0
    except (OSError, ValueError) as error:  # unreadable file, not a classic PCAP, or a failed flush
        _cli_output_failed = isinstance(error, OSError) and error.errno is not None and error.filename is None
        print("Error: %s" % error, file=sys.stderr)
        return 1
    if args.stats or args.verbose:
        print("[stats] %s" % dict(sorted(processor.stats.items())), file=sys.stderr)
    failed = processor.stats.get("failed_files", 0)
    if failed:
        print("Error: %d file(s) could not be read (skipped)" % failed, file=sys.stderr)
        return 1
    return 0


def _script_main() -> int:
    """Entry point for `python -m pcapreasm` and the `pcapreasm` command."""
    code = main()
    if _cli_output_failed:
        _silence_stdout()  # keep the interpreter from reporting the same output error again at exit
    return code


if __name__ == "__main__":
    sys.exit(_script_main())
