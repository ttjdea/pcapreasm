# pcapreasm

A **standard-library-only** Python module that extracts TCP / UDP application-layer data from PCAP captures. It is a single file, `pcapreasm.py`, with no dependencies.

- License: MPL-2.0
- Version: 0.2.2 ([changelog](CHANGELOG.md))
- Python 3.9 or later (CI runs 3.9 - 3.13)
- Japanese (full documentation): [README.md](README.md)

## Features

| Feature | Details |
|---|---|
| PCAP input | Classic PCAP (little/big endian, microsecond/nanosecond). Reads files or any open binary stream (e.g. `gzip.open`). |
| L2 stripping | Ethernet, 802.1Q / QinQ, Linux cooked capture (SLL / SLL2), raw IP, loopback |
| L3 parsing | IPv4 / IPv6 (extension headers), IP fragment reassembly |
| Packet filter | A subset of tcpdump expressions (`tcp and port 80`); excluded traffic is dropped first, which is faster and uses no memory |
| TCP reassembly | Reordering, retransmission removal, 32-bit sequence wrap-around, gap tracking |
| Conversations | Client and server streams are delivered together as one conversation |
| UDP | Per-datagram callbacks and optional per-flow callbacks |
| Timestamps | 64-bit integer nanoseconds (`timestamp_ns`), no floating-point loss |
| Damaged input | Truncated files are processed as far as they can be read; multi-file runs continue |
| Snaplen detection | Packets cut short by the capture's snaplen are detected, so gaps caused by truncation can be told apart from packet loss |
| Memory limits | Caps on conversations, per-conversation bytes, total bytes, idle time |

## Install

Copy `pcapreasm.py` into your project, or install from GitHub (not published on PyPI):

```text
pip install git+https://github.com/ttjdea/pcapreasm
```

## Quick start

```python
from pcapreasm import PcapStreamProcessor, BaseAnalyzer


class Printer(BaseAnalyzer):
    def on_tcp_conversation(self, conv):
        c, s = conv.client, conv.server
        print(f"{c.flow_id} -> {s.flow_id}")
        print(f"  client {len(c.data)} bytes / server {len(s.data)} bytes ({conv.evict_reason})")


PcapStreamProcessor(analyzers=[Printer()]).process_file("sample.pcap")
```

### Filtering

```python
# A subset of tcpdump syntax (see "Filter expressions")
proc = PcapStreamProcessor(analyzers=[Printer()], filter_expr="tcp and (port 80 or port 8080) and not host 10.0.0.9")
proc.process_file("sample.pcap")
print(proc.stats["filtered"], "packets excluded")

# Anything the expression language cannot say can be a function
proc = PcapStreamProcessor(
    analyzers=[Printer()],
    packet_filter=lambda proto, flow_id: flow_id[3] in (80, 443) or flow_id[1] in (80, 443),
)
```

### Compressed input and several files

```python
import gzip

from pcapreasm import PcapStreamProcessor  # Printer is the analyzer from the quick start

proc = PcapStreamProcessor(analyzers=[Printer()])
with gzip.open("sample.pcap.gz", "rb") as stream:
    proc.process_stream(stream, name="sample.pcap.gz")

# Files must be given in chronological order; connection state carries across files.
# on_error="skip" logs unreadable files (e.g. pcapng), counts them in stats["failed_files"] and continues.
PcapStreamProcessor(analyzers=[Printer()]).process_files(["part1.pcap", "part2.pcap"], on_error="skip")
```

### Limiting memory on huge captures

```python
proc = PcapStreamProcessor(
    analyzers=[Printer()],
    max_conversations=2000,
    max_conversation_bytes=64 * 1024**2,
    max_total_bytes=1024**3,
    idle_timeout=120,               # seconds of *capture* time
)
```

## Command line (added in 0.2.0)

```text
python -m pcapreasm capture.pcap
python -m pcapreasm a.pcap b.pcap -f "tcp and port 80" --udp
python -m pcapreasm -l files.txt --format jsonl > conversations.jsonl
zcat capture.pcap.gz | python -m pcapreasm -
```

One line per TCP conversation (and per UDP flow with `--udp`), times in UTC:

```text
2026-11-16T12:34:56.789Z TCP 10.0.0.1:1234 -> 10.0.0.2:80 c2s=18B s2c=11B gaps=0 end=fin
```

| Option | Meaning |
|---|---|
| `pcap ...` | PCAP files in chronological order; `-` reads one file from stdin |
| `-l`, `--file-list FILE` | file with one path per line (blank lines ignored); repeatable |
| `-f`, `--filter EXPR` | tcpdump-style filter (see "Filter expressions"); a bad expression exits with 2 |
| `--udp` | also print UDP flows (datagram and byte counts per source/destination) |
| `--format text\|jsonl` | output format (default `text`) |
| `--on-error raise\|skip` | stop (default) or skip an unreadable file |
| `--idle-timeout SEC` | finish a conversation idle for SEC seconds of capture time (default 300, `0` = off) |
| `--max-memory-mb MB` | buffer limit (default 1024, `0` = unlimited) |
| `--max-conversations N` | simultaneously tracked TCP conversations (default 5000) |
| `--no-fragments` | do not reassemble IP fragments |
| `--stats`, `-v`, `--version` | statistics to stderr, verbose logging, version |

Results go to stdout; warnings and statistics go to stderr. Exit codes: `0` ok, `1` runtime error (unreadable file, not a classic PCAP, output cannot be written, or a file was skipped with `--on-error skip`), `2` bad arguments or filter.

Notes:
- Only TCP conversations that **carry data** are listed. Handshake-only, refused or reset connections do not appear (same as the library's `on_tcp_conversation`); `--stats` shows the total as `tcp_conversations`.
- TCP lines are printed in the order conversations are finished, not by start time. UDP lines are sorted by start time.
- `--udp` keeps one counter per flow in memory, which `--max-memory-mb` does not cover; input with a huge number of distinct UDP sources can use several times the PCAP's size.
- `-` (stdin) cannot be combined with other files. `-l` lists are UTF-8 (a BOM is accepted); leading/trailing spaces and `#` lines are taken literally as paths. After `pip install` the command is also available as `pcapreasm`.

## API

### `PcapStreamProcessor(...)`

| Argument | Default | Meaning |
|---|---|---|
| `analyzers` | `None` | List of `BaseAnalyzer` instances |
| `evict_on_fin` | `True` | Deliver a conversation as soon as FIN/RST completes it |
| `max_conversations` | `5000` | Max conversations held at once (least recently used is delivered first) |
| `max_conversation_bytes` | `None` | Per-conversation buffer limit |
| `max_total_bytes` | `None` | Total buffer limit |
| `idle_timeout` | `None` | Deliver conversations idle longer than this many seconds of capture time |
| `close_linger` | `5.0` | Seconds to wait for missing data **after both directions have closed**. Not applied to half-closed connections |
| `reassemble_fragments` | `True` | Reassemble IP fragments (otherwise they are dropped) |
| `fragment_timeout` | `30.0` | Seconds before an incomplete fragment set is discarded |
| `max_fragment_sets` | `1024` | Max incomplete fragment sets held |
| `raise_on_analyzer_error` | `False` | Raise `AnalyzerError` when an analyzer callback fails instead of logging it (added in 0.1.0) |
| `segment_overhead_bytes` | `150` | Bytes counted per buffered segment on top of its payload when checking the byte limits, so that the limits track real memory (about 110-220 bytes per segment were measured). `0` keeps the 0.0.x/0.1.x behaviour (payload only). Added in 0.1.0 with default `0`; **the default became `150` in 0.2.0**, so the same limits now finish old conversations earlier |
| `packet_filter` | `None` | `f(ip_proto, flow_id) -> bool`; return `False` to drop the packet. An exception becomes `AnalyzerError` (added in 0.1.0) |
| `filter_expr` | `None` | tcpdump-style expression; ANDed with `packet_filter` (added in 0.1.0) |

| Method | Purpose |
|---|---|
| `process_file(path, flush_at_end=True)` | Process one file (`str` / `pathlib.Path` / named pipe). Raises `PcapFormatError` if it is not a classic PCAP |
| `process_stream(stream, flush_at_end=True, name="<stream>")` | Process an open binary stream; the stream is not closed |
| `process_files(paths, on_error="raise")` | Process files in order, flushing after the last. `"skip"` continues past unreadable files |
| `flush()` | Deliver everything still buffered, then call `on_complete` |
| `stats` | `collections.Counter` of processing statistics |

If `process_files` stops on an error (the default), conversations buffered so far are not flushed; call `flush()` yourself if you need them.

### `BaseAnalyzer` callbacks

Override only what you need. By default an exception in a callback is logged and swallowed.

| Callback | Called |
|---|---|
| `on_file_start(path)` / `on_file_end(path)` | Around each file or stream (added in 0.1.0). `on_file_end` also runs when reading fails |
| `on_tcp_stream(flow_id, data, meta)` | One direction of a connection is complete (not called for empty `data`) |
| `on_tcp_conversation(conversation)` | A connection is complete (client and server together) |
| `on_udp_datagram(flow_id, payload, timestamp_ns)` | For each UDP datagram, immediately |
| `on_udp_flow(flow_id, datagrams, meta)` | At flush, per UDP flow. Overriding it keeps every datagram in memory until flush |
| `on_complete()` | Once, after all files and the flush |

### Metadata

`TCPFlowMeta` has `first_timestamp_ns`, `last_timestamp_ns`, `timeline` (`[(timestamp_ns, chunk)]` whose concatenation is `data`), `segment_count`, `retrans_count`, `gaps` (`[(offset, missing_bytes)]`), `gap_count`, `gap_bytes`, `is_closed`, `evict_reason`, and `truncated_segments` (segments cut short by snaplen, added in 0.1.0; when non-zero, some gaps are truncation rather than packet loss).

`TCPConversation` has `client`, `server` (both `TCPStream`: `flow_id`, `data`, `meta`), `client_certain`, `first_timestamp_ns`, `last_timestamp_ns`, `evict_reason`.

### Eviction reasons

`EVICT_FIN`, `EVICT_RST`, `EVICT_NEW_CONNECTION`, `EVICT_IDLE`, `EVICT_FIN_TIMEOUT` (both directions closed but a gap never filled), `EVICT_MAX_CONVERSATIONS`, `EVICT_MAX_BYTES`, `EVICT_MAX_TOTAL_BYTES`, `EVICT_FLUSH`. Anything other than `fin` may be partial data. When a limit (`max_*`) forces delivery, one long connection is reported as several streams.

### Exceptions

| Exception | Base | Raised when |
|---|---|---|
| `PcapFormatError` | `ValueError` | The input is not a classic PCAP. The message explains pcapng / gzip / unsupported version / too-short input |
| `AnalyzerError` | `Exception` | A callback fails with `raise_on_analyzer_error=True`, or a `packet_filter` raises. The original is `__cause__` |
| `FilterSyntaxError` | `ValueError` | `filter_expr` is invalid or uses an unsupported construct (raised when the processor is created) |

### Statistics (`stats`)

`files`, `failed_files`, `packets`, `non_ip`, `bad_ip` / `bad_tcp` / `bad_udp`, `truncated_packets`, `filtered`, `orphan_packets`, `late_packets` (data, SYN, FIN or RST arriving after a connection was delivered), `late_acks` (bare ACKs after delivery, e.g. the last ACK of a normal close), `tcp_conversations`, `evict_<reason>` (e.g. `evict_fin`), `fragments`, `fragments_dropped`, `frag_reassembled`, `frag_expired`, `frag_evicted`, `frag_too_large`, `frag_conflict`, `frag_too_many_pieces` (more than 1,400 pieces for one IP datagram; added in 0.2.2), `frag_incomplete_at_flush`, `read_errors`.

## Filter expressions

`filter_expr` accepts a **subset** of tcpdump (pcap-filter) syntax. It is evaluated on parsed TCP/UDP packets; it is not compiled to BPF.

| Syntax | Meaning |
|---|---|
| `tcp` `udp` `ip` `ip6` | Protocol (`ip` = IPv4, `ip6` = IPv6) |
| `host 10.0.0.1` | Source or destination address matches |
| `net 10.0.0.0/8` | Source or destination is inside the network (**CIDR required**) |
| `port 80` | Source or destination port matches (TCP and UDP when no protocol is given) |
| `portrange 8000-8100` | Port in range, inclusive |
| `src` / `dst` / `src or dst` / `src and dst` | Restrict direction, e.g. `dst port 53` |
| `and` `or` `not` (`&&` `\|\|` `!`), parentheses | Logic |
| `tcp port 80`, `udp dst port 53` | Protocol prefix |
| `port 80 or 443` | Like tcpdump, omitted qualifiers repeat: same as `port 80 or port 443` |

Deliberate differences from tcpdump:

- Host names and service names (`http`) are **not resolved**; use IP literals and port numbers.
- Mixing `and` with `or` without parentheses is an **error** (tcpdump evaluates left to right, which is easy to misread).
- Nesting of parentheses / `not` is limited to 100 levels; port numbers must be ASCII digits.
- Unsupported syntax (`ether`, `vlan`, byte offsets such as `tcp[13]`, `less` / `greater`, `icmp`, ...) raises `FilterSyntaxError` instead of being ignored, so a typo can never silently let everything through.
- IP fragments are filtered **after reassembly**, because later fragments carry no port number (tcpdump's `port` never matches them).
- `tests/test_filter.py` compares the match counts with tcpdump 4.99.4 (when tcpdump is installed) for 21 expressions over 400 random packets; they agree.

Notes: an expression that matches one direction only (`src port 80`) delivers one-directional streams, and `client_certain` is then likely `False`. Measured on one machine with synthetic data (500,500 packets of 40-byte segments), relative to no filter: about 91% speed for a simple expression that keeps everything, about 75% for a four-clause expression, and about 180% (with almost no memory) for an expression that drops everything. For very large files, `tcpdump -r in.pcap -w out.pcap 'expr'` first is much faster still.

## Limitations

- **Classic PCAP only.** pcapng raises `PcapFormatError` with the conversion hint (`editcap -F pcap in.pcapng out.pcap`). pcapng support is not planned.
- Compressed files: open them yourself and use `process_stream`.
- Gaps are not padded: `data` skips missing bytes, so offsets after a gap shift; use `meta.gaps`.
- Overlapping segments: the earliest-arriving data wins; OS-specific reassembly policies are not reproduced. Checksums are not verified.
- A half-closed connection (only one side sent FIN) is never timed out by `close_linger`; it ends by the peer's FIN/RST, `idle_timeout`, a limit, or `flush()`. Without `idle_timeout` such connections stay in memory until `max_conversations` is reached.
- A reused 4-tuple is split into separate connections by the new SYN's initial sequence number (same number = SYN retransmission) or, if that side has not sent a SYN yet, by leftover data from the previous connection in either direction.
- No decryption, no tunnel decapsulation, only TCP and UDP; packets of the same 4-tuple on different VLANs are treated as one connection.
- **Memory limits add 150 bytes per buffered segment by default** (`segment_overhead_bytes`; the default was `0`, payload only, up to 0.1.x). With `0`, many tiny segments use far more memory than counted. Example measurement: 500,500 segments of 40 bytes with `max_total_bytes` = 16 MiB grew memory by about 89 MiB at `segment_overhead_bytes=0`, about 27 MiB at `100`, about 21 MiB at `150`, at the price of more split streams (593, 2,162 and 2,822 streams). Measure on your own data.
- Not thread-safe: use one `PcapStreamProcessor` per thread. All time handling uses capture time.
- **Untrusted captures**: set the memory limits, and limit CPU time and memory with OS or container limits. See [SECURITY.md](SECURITY.md).

## License

Mozilla Public License 2.0. See `LICENSE` and the header of `pcapreasm.py`.
