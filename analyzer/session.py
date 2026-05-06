"""
analyzer/session.py
-------------------
TCP session reconstruction from a stream of PacketRecord objects.

Responsibilities:
  - Group packets by TCP 4-tuple (src_ip, src_port, dst_ip, dst_port) into flows.
    Both directions of the same connection are merged into one Session so
    downstream extractors see the full bidirectional payload.
  - Order segments within each flow by TCP sequence number to handle
    out-of-order delivery (common in captures taken at the edge).
  - Detect session completeness:
      * 'complete'    — SYN / SYN-ACK handshake AND a FIN/RST teardown seen.
      * 'established' — handshake seen, stream still open at capture end.
      * 'incomplete'  — data exchanged but no SYN observed (capture started
                        mid-stream; extremely common in real-world PCAPs).
      * 'rst'         — connection torn down by RST before FIN exchange.
      * 'empty'       — SYN/SYN-ACK seen but zero payload bytes transferred.
  - Infer the application-layer protocol from the well-known destination port
    (or source port for server-originated flows) so downstream code has a fast
    routing hint without needing a full DPI pass.
  - Expose `Session.payload_client_to_server` and `Session.payload_server_to_client`
    as the ordered, gap-aware reassembled byte strings for each direction.
    Extractors parse these as normal byte buffers.
  - Surface per-session metadata: timing, byte counts, packet counts, flags seen.

NOT handled here (on roadmap):
  - TCP reassembly gap filling (overlapping segments with conflicting data).
  - IP fragment reassembly.

Design notes:
  - Two-pass architecture:
      Pass 1 (feed): accumulates all packets into in-memory segment buffers.
      Pass 2 (build): sorts, stitches, and emits Session objects.
    Sequence-number ordering requires seeing all segments before stitching.
  - Memory: only application-layer payload bytes are stored per packet,
    NOT full frames. Capped at _MAX_PAYLOAD_BYTES per direction per session.
  - CLEARTEXT_PORTS lives in anomaly.py — it serves anomaly detection logic,
    not session reconstruction.
  - All timestamps kept as Unix epoch floats; ISO-8601 conversion happens
    only in Session.to_dict() so in-memory comparisons stay cheap.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import dpkt

from analyzer.parser import PacketRecord


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PORT_PROTO_MAP: Dict[int, str] = {
    20:   "FTP-DATA",
    21:   "FTP",
    22:   "SSH",
    23:   "TELNET",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS/TLS",
    465:  "SMTPS",
    587:  "SMTP-SUBMISSION",
    993:  "IMAPS",
    995:  "POP3S",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "ELASTICSEARCH",
}

# TCP flag bit masks (as used in dpkt.tcp.TCP.flags)
_TH_FIN = 0x01
_TH_SYN = 0x02
_TH_RST = 0x04
_TH_PSH = 0x08
_TH_ACK = 0x10
_TH_URG = 0x20

# Maximum application-layer payload bytes kept per session direction.
# Applied incrementally — never accumulates more than this in memory.
_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# Internal data structures — __slots__ for memory efficiency
# (instantiated once per packet; savings are significant on large captures)
# ---------------------------------------------------------------------------

FlowKey = Tuple[str, int, str, int]  # (ip_a, port_a, ip_b, port_b)


@dataclass
class _Segment:
    """
    One TCP/UDP segment extracted from a PacketRecord.
    Stores only what is needed for reconstruction.
    """
    __slots__ = ("seq", "flags", "payload", "timestamp", "from_a")

    seq:       int
    flags:     int
    payload:   bytes
    timestamp: float
    from_a:    bool   # True = a→b direction (canonical lower→higher)


@dataclass
class _FlowBuffer:
    """
    Accumulates raw segments for one bidirectional flow during Pass 1.
    Converted into a Session during Pass 2.
    """
    __slots__ = ("key", "initiator_a", "syn_seen", "segments",
                 "flags_seen", "packet_count")

    key:          FlowKey
    initiator_a:  bool        # True → ip_a:port_a is the SYN sender
    syn_seen:     bool        # True once a clean SYN (not SYN-ACK) is observed
    segments:     List[_Segment]
    flags_seen:   int         # OR of all TCP flag bytes across the flow
    packet_count: int


# ---------------------------------------------------------------------------
# Public data structure
# ---------------------------------------------------------------------------

@dataclass
class Session:
    """
    A fully reconstructed bidirectional TCP (or UDP pseudo) session.

    Payload bytes (payload_client_to_server, payload_server_to_client) are
    available in-memory for extractor consumption but are NOT included in
    to_dict() — they are too large for JSON output.

    Two separate flags track different kinds of data loss:
      truncated  — payload was capped at _MAX_PAYLOAD_BYTES (size limit hit)
      has_gaps   — sequence number gaps were found in TCP stream (data missing
                   from the capture itself, e.g. dropped packets at capture point)
    """
    session_id:               str
    protocol:                 str
    src_ip:                   str
    src_port:                 int
    dst_ip:                   str
    dst_port:                 int
    start_time:               float
    end_time:                 Optional[float]
    duration_seconds:         float
    bytes_client_to_server:   int
    bytes_server_to_client:   int
    bytes_transferred:        int
    packet_count:             int
    status:                   str
    flags_seen:               List[str]
    payload_client_to_server: bytes
    payload_server_to_client: bytes
    truncated:                bool   # hit _MAX_PAYLOAD_BYTES cap
    has_gaps:                 bool   # sequence number gaps detected in stream

    def to_dict(self) -> dict:
        """Serialize to the sessions[] block of the JSON report."""
        return {
            "session_id":        self.session_id,
            "protocol":          self.protocol,
            "src_ip":            self.src_ip,
            "src_port":          self.src_port,
            "dst_ip":            self.dst_ip,
            "dst_port":          self.dst_port,
            "start_time":        _epoch_to_iso(self.start_time),
            "end_time":          _epoch_to_iso(self.end_time) if self.end_time else None,
            "duration_seconds":  self.duration_seconds,
            "bytes_transferred": self.bytes_transferred,
            "bytes_c2s":         self.bytes_client_to_server,
            "bytes_s2c":         self.bytes_server_to_client,
            "packet_count":      self.packet_count,
            "status":            self.status,
            "flags_seen":        sorted(self.flags_seen),
            "truncated":         self.truncated,
            "has_gaps":          self.has_gaps,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _epoch_to_iso(ts: float) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> Tuple[FlowKey, bool]:
    """
    Return (canonical_key, from_a).

    Canonical key always orders (lower_ip, lower_port, higher_ip, higher_port)
    so both directions of a conversation hash to the same key.
    from_a is True when the given src→dst matches the a→b (lower→higher) order.

    Note: IP comparison is lexicographic (string), not numeric. This is
    intentional — we only need consistency, not numeric ordering.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port), True
    return (dst_ip, dst_port, src_ip, src_port), False


def _infer_protocol(port_a: int, port_b: int) -> str:
    """Return inferred protocol name; lower port checked first (usually server)."""
    lower, higher = sorted([port_a, port_b])
    return (
        _PORT_PROTO_MAP.get(lower)
        or _PORT_PROTO_MAP.get(higher)
        or "UNKNOWN"
    )


def _decode_flags(flag_byte: int) -> List[str]:
    """Return list of human-readable TCP flag names set in flag_byte."""
    mapping = [
        (_TH_SYN, "SYN"), (_TH_ACK, "ACK"), (_TH_FIN, "FIN"),
        (_TH_RST, "RST"), (_TH_PSH, "PSH"), (_TH_URG, "URG"),
    ]
    return [name for mask, name in mapping if flag_byte & mask]


def _infer_status(flags_seen: int) -> str:
    """
    Infer session completeness from OR'd TCP flags across all packets.

    Priority order:
      1. RST seen            → 'rst'
      2. SYN + FIN seen      → 'complete'
      3. SYN seen, no FIN    → 'established'
      4. No SYN              → 'incomplete'
    """
    has_syn = bool(flags_seen & _TH_SYN)
    has_fin = bool(flags_seen & _TH_FIN)
    has_rst = bool(flags_seen & _TH_RST)

    if has_rst:
        return "rst"
    if has_syn and has_fin:
        return "complete"
    if has_syn:
        return "established"
    return "incomplete"


def _stitch_segments(
    segments: List[_Segment], from_a: bool
) -> Tuple[bytes, bool, bool]:
    """
    Sort and concatenate payload bytes for one direction of a TCP flow.

    Segments sorted by sequence number. Overlaps/retransmits are deduplicated.
    Gaps get a capped null-byte placeholder (max 512 bytes) so byte offsets
    remain roughly meaningful for extractors.

    Returns
    -------
    (payload, truncated, has_gaps)
        payload    — Stitched application-layer bytes (capped at _MAX_PAYLOAD_BYTES)
        truncated  — True when cap was hit (data cut off due to size limit)
        has_gaps   — True when sequence number gaps were detected (data missing
                     from the capture itself — distinct from size truncation)
    """
    direction_segs = [s for s in segments if s.from_a == from_a and s.payload]
    direction_segs.sort(key=lambda s: s.seq)

    buf = bytearray()
    expected_seq: Optional[int] = None
    truncated = False
    has_gaps = False

    for seg in direction_segs:
        if len(buf) >= _MAX_PAYLOAD_BYTES:
            truncated = True
            break

        if expected_seq is None:
            buf.extend(seg.payload)
            expected_seq = seg.seq + len(seg.payload)
            continue

        gap = seg.seq - expected_seq

        if gap > 0:
            # Missing bytes in stream — insert placeholder, flag separately
            placeholder_size = min(gap, 512)
            buf.extend(b"\x00" * placeholder_size)
            has_gaps = True
            expected_seq = seg.seq  # advance past the gap

        # Write only the un-seen portion (handles overlap and retransmit)
        overlap = expected_seq - seg.seq
        new_data = seg.payload[max(0, overlap):]
        if new_data:
            # Apply cap incrementally — never accumulate more than limit
            space_left = _MAX_PAYLOAD_BYTES - len(buf)
            if len(new_data) > space_left:
                buf.extend(new_data[:space_left])
                truncated = True
                break
            buf.extend(new_data)
            expected_seq = seg.seq + len(seg.payload)

    return bytes(buf), truncated, has_gaps


# ---------------------------------------------------------------------------
# TCPSessionRebuilder
# ---------------------------------------------------------------------------

class TCPSessionRebuilder:
    """
    Two-pass TCP session reconstructor.

    Pass 1 — feed(packet)
        Call once per PacketRecord from PcapParser.parse().
        Non-TCP packets are silently ignored.

    Pass 2 — build()
        Call after all packets are fed. Returns Session objects sorted by
        start_time ascending.

    Example::

        rebuilder = TCPSessionRebuilder()
        for pkt in parser.parse():
            rebuilder.feed(pkt)
        sessions = rebuilder.build()
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, _FlowBuffer] = {}

    def feed(self, packet: PacketRecord) -> None:
        """Accumulate one TCP PacketRecord. Non-TCP packets are ignored."""
        if packet.transport != "TCP":
            return
        if None in (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port):
            return

        tcp = packet.ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return

        key, from_a = _canonical_key(
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
        )

        if key not in self._flows:
            self._flows[key] = _FlowBuffer(
                key=key,
                initiator_a=from_a,   # tentative — corrected below if SYN seen
                syn_seen=False,
                segments=[],
                flags_seen=0,
                packet_count=0,
            )

        buf = self._flows[key]
        buf.packet_count += 1
        buf.flags_seen |= tcp.flags

        # Correct initiator assignment: a clean SYN (not SYN-ACK) identifies
        # the true initiator. We update even if a packet was already seen —
        # this handles out-of-order captures where SYN-ACK arrives first.
        is_syn     = bool(tcp.flags & _TH_SYN)
        is_syn_ack = bool(tcp.flags & _TH_SYN) and bool(tcp.flags & _TH_ACK)
        if is_syn and not is_syn_ack and not buf.syn_seen:
            buf.initiator_a = from_a
            buf.syn_seen = True

        buf.segments.append(_Segment(
            seq=tcp.seq,
            flags=tcp.flags,
            payload=packet.payload,
            timestamp=packet.timestamp,
            from_a=from_a,
        ))

    def build(self) -> List[Session]:
        """Reconstruct and return all Session objects sorted by start_time."""
        sessions: List[Session] = []

        for key, buf in self._flows.items():
            if not buf.segments:
                continue  # defensive guard — should never occur

            ip_a, port_a, ip_b, port_b = key

            if buf.initiator_a:
                src_ip, src_port = ip_a, port_a
                dst_ip, dst_port = ip_b, port_b
            else:
                src_ip, src_port = ip_b, port_b
                dst_ip, dst_port = ip_a, port_a

            timestamps = [s.timestamp for s in buf.segments]
            start_time = min(timestamps)
            end_time   = max(timestamps) if len(timestamps) > 1 else None
            duration   = round(end_time - start_time, 6) if end_time else 0.0

            payload_c2s, trunc_c2s, gaps_c2s = _stitch_segments(
                buf.segments, from_a=buf.initiator_a
            )
            payload_s2c, trunc_s2c, gaps_s2c = _stitch_segments(
                buf.segments, from_a=not buf.initiator_a
            )

            status = _infer_status(buf.flags_seen)
            bytes_c2s = len(payload_c2s)
            bytes_s2c = len(payload_s2c)
            if status == "established" and bytes_c2s + bytes_s2c == 0:
                status = "empty"

            # Session ID always written from initiator perspective — consistent
            # with TCP and UDP for downstream parsers
            session_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

            sessions.append(Session(
                session_id=session_id,
                protocol=_infer_protocol(port_a, port_b),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                bytes_client_to_server=bytes_c2s,
                bytes_server_to_client=bytes_s2c,
                bytes_transferred=bytes_c2s + bytes_s2c,
                packet_count=buf.packet_count,
                status=status,
                flags_seen=_decode_flags(buf.flags_seen),
                payload_client_to_server=payload_c2s,
                payload_server_to_client=payload_s2c,
                truncated=trunc_c2s or trunc_s2c,
                has_gaps=gaps_c2s or gaps_s2c,
            ))

        sessions.sort(key=lambda s: s.start_time)
        return sessions

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    def reset(self) -> None:
        self._flows.clear()


# ---------------------------------------------------------------------------
# UDPFlowGrouper
# ---------------------------------------------------------------------------

class UDPFlowGrouper:
    """
    Groups UDP packets by 4-tuple and emits lightweight Session objects.

    UDP has no connection state so all packets sharing the same 4-tuple are
    treated as one pseudo-session. Status is always 'udp'.

    Session IDs use the same initiator:port-responder:port format as TCP
    (canonical lower→higher ordering since UDP has no SYN to identify initiator).
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, _FlowBuffer] = {}

    def feed(self, packet: PacketRecord) -> None:
        if packet.transport != "UDP":
            return
        if None in (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port):
            return

        key, from_a = _canonical_key(
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
        )

        if key not in self._flows:
            self._flows[key] = _FlowBuffer(
                key=key,
                initiator_a=True,
                syn_seen=False,
                segments=[],
                flags_seen=0,
                packet_count=0,
            )

        buf = self._flows[key]
        buf.packet_count += 1
        buf.segments.append(_Segment(
            seq=0,
            flags=0,
            payload=packet.payload,
            timestamp=packet.timestamp,
            from_a=from_a,
        ))

    def build(self) -> List[Session]:
        sessions: List[Session] = []

        for key, buf in self._flows.items():
            if not buf.segments:
                continue

            ip_a, port_a, ip_b, port_b = key

            timestamps = [s.timestamp for s in buf.segments]
            start_time = min(timestamps)
            end_time   = max(timestamps) if len(timestamps) > 1 else None
            duration   = round(end_time - start_time, 6) if end_time else 0.0

            # UDP: sort by timestamp, apply cap incrementally (no seq numbers)
            def _concat_incremental(segs: List[_Segment]) -> Tuple[bytes, bool]:
                buf_bytes = bytearray()
                truncated = False
                for s in sorted(segs, key=lambda x: x.timestamp):
                    if not s.payload:
                        continue
                    space = _MAX_PAYLOAD_BYTES - len(buf_bytes)
                    if space <= 0:
                        truncated = True
                        break
                    buf_bytes.extend(s.payload[:space])
                    if len(s.payload) > space:
                        truncated = True
                        break
                return bytes(buf_bytes), truncated

            payload_c2s, trunc_c2s = _concat_incremental(
                [s for s in buf.segments if s.from_a]
            )
            payload_s2c, trunc_s2c = _concat_incremental(
                [s for s in buf.segments if not s.from_a]
            )

            # Consistent session_id format: canonical lower→higher
            session_id = f"{ip_a}:{port_a}-{ip_b}:{port_b}"

            sessions.append(Session(
                session_id=session_id,
                protocol=_infer_protocol(port_a, port_b),
                src_ip=ip_a,
                src_port=port_a,
                dst_ip=ip_b,
                dst_port=port_b,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                bytes_client_to_server=len(payload_c2s),
                bytes_server_to_client=len(payload_s2c),
                bytes_transferred=len(payload_c2s) + len(payload_s2c),
                packet_count=buf.packet_count,
                status="udp",
                flags_seen=[],
                payload_client_to_server=payload_c2s,
                payload_server_to_client=payload_s2c,
                truncated=trunc_c2s or trunc_s2c,
                has_gaps=False,  # UDP has no sequence numbers, gaps undefined
            ))

        sessions.sort(key=lambda s: s.start_time)
        return sessions

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    def reset(self) -> None:
        self._flows.clear()
