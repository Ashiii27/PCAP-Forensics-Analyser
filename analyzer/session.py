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
  - Expose `Session.payload_a` and `Session.payload_b` as the ordered, gap-aware
    reassembled byte strings for the client→server and server→client directions
    respectively.  Extractors can then parse these as normal byte buffers.
  - Surface per-session metadata: timing, byte counts, packet counts, flags seen.

NOT handled here (on roadmap):
  - TCP reassembly gap filling (overlapping segments with conflicting data).
  - UDP "sessions" — handled separately; UDP flows are emitted as single-packet
    pseudo-sessions by UDPSessionBuilder.
  - IP fragment reassembly.

Design notes:
  - The reconstructor works in two passes:
      Pass 1 (feed): accumulates all packets into in-memory segment buffers.
      Pass 2 (build): sorts, stitches, and emits Session objects.
    This is intentional — sequence-number ordering requires seeing all
    segments before stitching; single-pass ordering would need a priority
    queue and is significantly more complex for marginal gain on offline PCAPs.
  - Memory: each packet's APPLICATION-LAYER payload bytes are stored
    (transport.data), NOT the full frame. For large captures this is still
    substantial; a future streaming mode may impose a payload cap per session.
  - All timestamps are kept as Unix epoch floats and converted to ISO-8601 UTC
    strings only in Session.to_dict() so comparisons stay cheap.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import dpkt

from analyzer.parser import PacketRecord


# ---------------------------------------------------------------------------
# Constants — well-known port → protocol name mapping
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

# Ports that carry cleartext traffic — flagged for anomaly detection later.
CLEARTEXT_PORTS = frozenset({21, 23, 80, 8080, 110, 143})

# TCP flag bit masks (as used in dpkt.tcp.TCP.flags)
_TH_FIN  = 0x01
_TH_SYN  = 0x02
_TH_RST  = 0x04
_TH_PSH  = 0x08
_TH_ACK  = 0x10
_TH_URG  = 0x20

# Maximum payload bytes kept per session direction.  Sessions exceeding this
# are truncated and flagged; prevents OOM on very large or deliberately crafted
# captures.  Set to 10 MB per direction.
_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

# A flow key is a canonical 4-tuple.  We always order (lower IP, lower port)
# first so both directions hash to the same key.
FlowKey = Tuple[str, int, str, int]   # (ip_a, port_a, ip_b, port_b)


@dataclass
class _Segment:
    """
    One TCP segment extracted from a PacketRecord.

    Stores only what is needed for reconstruction; raw frame bytes are
    discarded to keep memory footprint manageable.
    """
    seq:       int    # TCP sequence number
    flags:     int    # TCP flag byte
    payload:   bytes  # Application-layer data (may be b"")
    timestamp: float  # Packet capture timestamp (Unix epoch)
    from_a:    bool   # True = client→server direction; False = server→client


@dataclass
class Session:
    """
    A fully reconstructed bidirectional TCP session.

    Attributes
    ----------
    session_id:
        Human-readable identifier: ``"src_ip:src_port-dst_ip:dst_port"``.
        Always written from the initiating side (the host that sent the SYN).
    protocol:
        Inferred application-layer protocol name (e.g. ``"HTTP"``).
        ``"UNKNOWN"`` when the port is not in the well-known map.
    src_ip, src_port:
        The initiating endpoint (SYN sender).  If no SYN was seen, the
        endpoint with the lower (ip, port) tuple is arbitrarily chosen.
    dst_ip, dst_port:
        The responding endpoint.
    start_time:
        Unix timestamp of the first packet in this session.
    end_time:
        Unix timestamp of the last packet (None if only one packet seen).
    duration_seconds:
        ``end_time - start_time``, rounded to 6 decimal places.
    bytes_client_to_server:
        Application-layer bytes transferred in the client→server direction.
    bytes_server_to_client:
        Application-layer bytes transferred in the server→client direction.
    bytes_transferred:
        Total application-layer bytes (both directions combined).
    packet_count:
        Total packets attributed to this session (both directions).
    status:
        One of ``'complete'``, ``'established'``, ``'incomplete'``,
        ``'rst'``, or ``'empty'``.
    flags_seen:
        Set of TCP flag names observed (e.g. ``{'SYN', 'ACK', 'FIN'}``).
    payload_client_to_server:
        Ordered, stitched payload bytes for the client→server direction.
    payload_server_to_client:
        Ordered, stitched payload bytes for the server→client direction.
    truncated:
        True when payload exceeded ``_MAX_PAYLOAD_BYTES`` and was capped.
    """
    session_id:              str
    protocol:                str
    src_ip:                  str
    src_port:                int
    dst_ip:                  str
    dst_port:                int
    start_time:              float
    end_time:                Optional[float]
    duration_seconds:        float
    bytes_client_to_server:  int
    bytes_server_to_client:  int
    bytes_transferred:       int
    packet_count:            int
    status:                  str
    flags_seen:              List[str]
    payload_client_to_server: bytes
    payload_server_to_client: bytes
    truncated:               bool

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """
        Serialize to the ``sessions`` block of the JSON report.
        Payload bytes are NOT included (too large for JSON output); they
        are consumed in-memory by the extractor pipeline.
        """
        start_iso = _epoch_to_iso(self.start_time)
        end_iso   = _epoch_to_iso(self.end_time) if self.end_time else None

        return {
            "session_id":         self.session_id,
            "protocol":           self.protocol,
            "src_ip":             self.src_ip,
            "src_port":           self.src_port,
            "dst_ip":             self.dst_ip,
            "dst_port":           self.dst_port,
            "start_time":         start_iso,
            "end_time":           end_iso,
            "duration_seconds":   self.duration_seconds,
            "bytes_transferred":  self.bytes_transferred,
            "bytes_c2s":          self.bytes_client_to_server,
            "bytes_s2c":          self.bytes_server_to_client,
            "packet_count":       self.packet_count,
            "status":             self.status,
            "flags_seen":         sorted(self.flags_seen),
            "truncated":          self.truncated,
        }


@dataclass
class _FlowBuffer:
    """
    Accumulates raw segments for one bidirectional TCP flow during Pass 1.
    Converted into a Session during Pass 2.
    """
    key:         FlowKey
    # ip_a/port_a is the "lower" side; ip_a is the SYN sender if a SYN was seen.
    initiator_a: bool = True   # True → ip_a:port_a sent the SYN

    segments:    List[_Segment] = field(default_factory=list)
    flags_seen:  int = 0       # OR of all flag bytes seen across the flow
    packet_count: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _epoch_to_iso(ts: float) -> str:
    """Convert a Unix epoch float to an ISO-8601 UTC string."""
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> Tuple[FlowKey, bool]:
    """
    Return (canonical_key, from_a) where ``from_a`` is True when the
    given src→dst direction maps to the a→b (lower→higher) canonical order.

    The canonical key always has ``(smaller_ip, smaller_port, larger_ip,
    larger_port)`` so both sides of the conversation hash to the same key
    regardless of which direction a packet travels.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port), True
    return (dst_ip, dst_port, src_ip, src_port), False


def _infer_protocol(port_a: int, port_b: int) -> str:
    """
    Return the inferred application-layer protocol name using the well-known
    port map.  The lower-numbered port is checked first (usually the server
    port for client→server flows), then the higher-numbered port as a fallback.
    """
    lower, higher = sorted([port_a, port_b])
    return (
        _PORT_PROTO_MAP.get(lower)
        or _PORT_PROTO_MAP.get(higher)
        or "UNKNOWN"
    )


def _decode_flags(flag_byte: int) -> List[str]:
    """Return a list of human-readable flag names set in ``flag_byte``."""
    names = []
    if flag_byte & _TH_SYN: names.append("SYN")
    if flag_byte & _TH_ACK: names.append("ACK")
    if flag_byte & _TH_FIN: names.append("FIN")
    if flag_byte & _TH_RST: names.append("RST")
    if flag_byte & _TH_PSH: names.append("PSH")
    if flag_byte & _TH_URG: names.append("URG")
    return names


def _infer_status(flags_seen: int) -> str:
    """
    Infer session completeness from the OR'd TCP flags across all packets.

    Rules (evaluated in priority order):
      1. RST seen → 'rst'
      2. SYN + FIN seen → 'complete'
      3. SYN seen, no FIN → 'established'
      4. FIN seen, no SYN → 'incomplete' (capture started mid-stream)
      5. Neither SYN nor FIN → 'incomplete'
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


def _stitch_segments(segments: List[_Segment], from_a: bool) -> Tuple[bytes, bool]:
    """
    Sort and concatenate payload bytes for one direction of a TCP flow.

    Segments are sorted by sequence number.  Overlapping or duplicate data is
    deduplicated by skipping any segment whose starting sequence falls within
    an already-written range (simple gap-unaware approach — sufficient for the
    vast majority of captures).

    Returns
    -------
    (payload, truncated)
        ``payload``   — Stitched application-layer bytes.
        ``truncated`` — True when the result was capped at ``_MAX_PAYLOAD_BYTES``.
    """
    direction_segs = [s for s in segments if s.from_a == from_a and s.payload]
    direction_segs.sort(key=lambda s: s.seq)

    buf = bytearray()
    expected_seq: Optional[int] = None
    truncated = False

    for seg in direction_segs:
        if expected_seq is None:
            # First segment — just write it.
            buf.extend(seg.payload)
            expected_seq = seg.seq + len(seg.payload)
        else:
            gap = seg.seq - expected_seq
            if gap > 0:
                # Gap in the stream — insert a null-byte placeholder so byte
                # offsets stay roughly meaningful, and flag as truncated.
                placeholder = min(gap, 512)
                buf.extend(b"\x00" * placeholder)
                truncated = True
            # Write only the un-seen portion (handle overlap / retransmit).
            overlap = expected_seq - seg.seq
            new_data = seg.payload[max(0, overlap):]
            if new_data:
                buf.extend(new_data)
                expected_seq = seg.seq + len(seg.payload)

        if len(buf) >= _MAX_PAYLOAD_BYTES:
            del buf[_MAX_PAYLOAD_BYTES:]
            truncated = True
            break

    return bytes(buf), truncated


# ---------------------------------------------------------------------------
# Public API — TCPSessionRebuilder
# ---------------------------------------------------------------------------

class TCPSessionRebuilder:
    """
    Two-pass TCP session reconstructor.

    Pass 1 — ``feed(packet)``
        Call once per ``PacketRecord`` from ``PcapParser.parse()``.
        Non-TCP packets are silently ignored (use ``UDPFlowGrouper`` for UDP).

    Pass 2 — ``build()``
        Call once after all packets have been fed.  Returns a list of
        ``Session`` objects, one per unique TCP 4-tuple flow, sorted by
        ``start_time`` ascending.

    Example
    -------
    ::

        rebuilder = TCPSessionRebuilder()
        for pkt in parser.parse():
            rebuilder.feed(pkt)
        sessions = rebuilder.build()

    Notes
    -----
    - ``build()`` can be called multiple times safely; it does not mutate
      internal state.
    - Feeding packets after ``build()`` has been called is allowed but will
      require calling ``build()`` again to include the new packets.
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, _FlowBuffer] = {}

    # ------------------------------------------------------------------
    # Pass 1
    # ------------------------------------------------------------------

    def feed(self, packet: PacketRecord) -> None:
        """
        Accumulate a single ``PacketRecord`` into the internal flow table.
        Non-TCP, non-IP, and packets with missing endpoint info are ignored.
        """
        if packet.transport != "TCP":
            return
        if packet.src_ip is None or packet.dst_ip is None:
            return
        if packet.src_port is None or packet.dst_port is None:
            return

        tcp = packet.ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return  # safety guard — should never happen given transport == "TCP"

        key, from_a = _canonical_key(
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
        )

        if key not in self._flows:
            buf = _FlowBuffer(key=key)
            # If this packet carries a SYN (and only SYN — not SYN-ACK),
            # the sender is the initiator; mark accordingly.
            if (tcp.flags & _TH_SYN) and not (tcp.flags & _TH_ACK):
                buf.initiator_a = from_a
            self._flows[key] = buf

        buf = self._flows[key]
        buf.packet_count += 1
        buf.flags_seen |= tcp.flags

        seg = _Segment(
            seq=tcp.seq,
            flags=tcp.flags,
            payload=packet.payload,   # already bytes via PacketRecord.payload
            timestamp=packet.timestamp,
            from_a=from_a,
        )
        buf.segments.append(seg)

    # ------------------------------------------------------------------
    # Pass 2
    # ------------------------------------------------------------------

    def build(self) -> List[Session]:
        """
        Reconstruct and return all ``Session`` objects.

        Returns an empty list if no TCP packets have been fed.
        """
        sessions: List[Session] = []

        for key, buf in self._flows.items():
            ip_a, port_a, ip_b, port_b = key

            # Determine which side initiated (sent the SYN).
            if buf.initiator_a:
                src_ip, src_port = ip_a, port_a
                dst_ip, dst_port = ip_b, port_b
            else:
                src_ip, src_port = ip_b, port_b
                dst_ip, dst_port = ip_a, port_a

            # Timing
            timestamps = [s.timestamp for s in buf.segments]
            start_time = min(timestamps)
            end_time   = max(timestamps) if len(timestamps) > 1 else None
            duration   = round((end_time - start_time), 6) if end_time else 0.0

            # Payload reconstruction
            payload_c2s, trunc_c2s = _stitch_segments(
                buf.segments, from_a=buf.initiator_a
            )
            payload_s2c, trunc_s2c = _stitch_segments(
                buf.segments, from_a=not buf.initiator_a
            )
            truncated = trunc_c2s or trunc_s2c

            bytes_c2s = len(payload_c2s)
            bytes_s2c = len(payload_s2c)

            # Status and flags
            status     = _infer_status(buf.flags_seen)
            if status == "established" and bytes_c2s + bytes_s2c == 0:
                status = "empty"
            flags_seen = _decode_flags(buf.flags_seen)

            # Session ID: always written as initiator:port-responder:port
            session_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

            protocol = _infer_protocol(port_a, port_b)

            sessions.append(Session(
                session_id=session_id,
                protocol=protocol,
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
                flags_seen=flags_seen,
                payload_client_to_server=payload_c2s,
                payload_server_to_client=payload_s2c,
                truncated=truncated,
            ))

        sessions.sort(key=lambda s: s.start_time)
        return sessions

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def flow_count(self) -> int:
        """Number of distinct TCP flows accumulated so far."""
        return len(self._flows)

    def reset(self) -> None:
        """Clear all accumulated state.  Useful for reusing the instance."""
        self._flows.clear()


# ---------------------------------------------------------------------------
# Public API — UDPFlowGrouper
# ---------------------------------------------------------------------------

class UDPFlowGrouper:
    """
    Groups UDP packets by 4-tuple and emits lightweight ``Session`` objects.

    UDP has no connection state so every group of packets sharing the same
    4-tuple is treated as a single pseudo-session.  Status is always
    ``'udp'`` to make it easy for downstream code to distinguish from TCP.

    Usage mirrors ``TCPSessionRebuilder``:
    ::

        grouper = UDPFlowGrouper()
        for pkt in parser.parse():
            grouper.feed(pkt)
        udp_sessions = grouper.build()
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, _FlowBuffer] = {}

    def feed(self, packet: PacketRecord) -> None:
        """Accumulate a single UDP ``PacketRecord``."""
        if packet.transport != "UDP":
            return
        if packet.src_ip is None or packet.dst_ip is None:
            return
        if packet.src_port is None or packet.dst_port is None:
            return

        key, from_a = _canonical_key(
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
        )

        if key not in self._flows:
            self._flows[key] = _FlowBuffer(key=key)

        buf = self._flows[key]
        buf.packet_count += 1

        seg = _Segment(
            seq=0,        # UDP has no sequence number
            flags=0,
            payload=packet.payload,
            timestamp=packet.timestamp,
            from_a=from_a,
        )
        buf.segments.append(seg)

    def build(self) -> List[Session]:
        """Return all UDP pseudo-sessions sorted by start time."""
        sessions: List[Session] = []

        for key, buf in self._flows.items():
            ip_a, port_a, ip_b, port_b = key

            timestamps = [s.timestamp for s in buf.segments]
            start_time = min(timestamps)
            end_time   = max(timestamps) if len(timestamps) > 1 else None
            duration   = round((end_time - start_time), 6) if end_time else 0.0

            # Concatenate all payloads in timestamp order (no seq-sort for UDP)
            segs_c2s  = sorted(
                [s for s in buf.segments if s.from_a],
                key=lambda s: s.timestamp,
            )
            segs_s2c  = sorted(
                [s for s in buf.segments if not s.from_a],
                key=lambda s: s.timestamp,
            )
            payload_c2s = b"".join(s.payload for s in segs_c2s)
            payload_s2c = b"".join(s.payload for s in segs_s2c)

            truncated = False
            if len(payload_c2s) > _MAX_PAYLOAD_BYTES:
                payload_c2s = payload_c2s[:_MAX_PAYLOAD_BYTES]
                truncated = True
            if len(payload_s2c) > _MAX_PAYLOAD_BYTES:
                payload_s2c = payload_s2c[:_MAX_PAYLOAD_BYTES]
                truncated = True

            bytes_c2s = len(payload_c2s)
            bytes_s2c = len(payload_s2c)

            protocol = _infer_protocol(port_a, port_b)
            session_id = f"{ip_a}:{port_a}-{ip_b}:{port_b}"

            sessions.append(Session(
                session_id=session_id,
                protocol=protocol,
                src_ip=ip_a,
                src_port=port_a,
                dst_ip=ip_b,
                dst_port=port_b,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                bytes_client_to_server=bytes_c2s,
                bytes_server_to_client=bytes_s2c,
                bytes_transferred=bytes_c2s + bytes_s2c,
                packet_count=buf.packet_count,
                status="udp",
                flags_seen=[],
                payload_client_to_server=payload_c2s,
                payload_server_to_client=payload_s2c,
                truncated=truncated,
            ))

        sessions.sort(key=lambda s: s.start_time)
        return sessions

    @property
    def flow_count(self) -> int:
        """Number of distinct UDP flows accumulated so far."""
        return len(self._flows)

    def reset(self) -> None:
        """Clear all accumulated state."""
        self._flows.clear()
