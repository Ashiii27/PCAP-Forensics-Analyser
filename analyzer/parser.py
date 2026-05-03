"""
analyzer/parser.py
------------------
PCAP file loader and raw packet iterator.

Responsibilities:
  - Open and validate .pcap files
  - Iterate packets as a memory-efficient generator
  - Track capture metadata: filename, duration, packet counts (total/tcp/udp/other/skipped)
  - Expose convenience properties on PacketRecord so downstream modules never
    have to call socket.inet_ntoa() or navigate dpkt layers themselves
  - Surface decode errors without crashing the pipeline

Primary dependency: dpkt (fast C-backed offline PCAP parsing)
Fallback: raises PcapParseError with a clear message on failure

NOT supported yet: PCAPNG (on roadmap)
"""

from __future__ import annotations

import os
import socket
import struct
import warnings
from dataclasses import asdict, dataclass
from functools import cached_property
from typing import Generator, Optional

import dpkt


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PcapParseError(Exception):
    """Raised when the PCAP file cannot be opened or is corrupt."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """
    A single parsed packet ready for downstream processing.

    Attributes:
        timestamp:  Unix epoch float from the PCAP frame header.
        raw:        The raw bytes of the entire captured frame.
        eth:        Decoded dpkt.ethernet.Ethernet object, or None if
                    the link-layer type is not Ethernet / decoding fails.
        ip:         Decoded dpkt.ip.IP (or dpkt.ip6.IP6) object, or None.
        index:      0-based packet index within the capture file.

    Convenience properties (src_ip, dst_ip, src_port, dst_port, transport,
    payload) are computed lazily via cached_property so downstream modules
    never touch dpkt internals and repeated access is free.
    """
    timestamp: float
    raw: bytes
    eth: Optional[dpkt.ethernet.Ethernet]
    ip: Optional[dpkt.ip.IP | dpkt.ip6.IP6]
    index: int

    # ------------------------------------------------------------------
    # Convenience properties — cached so repeated access costs nothing
    # ------------------------------------------------------------------

    @cached_property
    def src_ip(self) -> Optional[str]:
        """Source IP as a dotted-decimal / colon-hex string, or None."""
        if self.ip is None:
            return None
        try:
            if isinstance(self.ip, dpkt.ip6.IP6):
                return socket.inet_ntop(socket.AF_INET6, self.ip.src)
            return socket.inet_ntoa(self.ip.src)
        except (OSError, struct.error):
            return None

    @cached_property
    def dst_ip(self) -> Optional[str]:
        """Destination IP as a dotted-decimal / colon-hex string, or None."""
        if self.ip is None:
            return None
        try:
            if isinstance(self.ip, dpkt.ip6.IP6):
                return socket.inet_ntop(socket.AF_INET6, self.ip.dst)
            return socket.inet_ntoa(self.ip.dst)
        except (OSError, struct.error):
            return None

    @cached_property
    def src_port(self) -> Optional[int]:
        """Source port for TCP/UDP packets, or None."""
        if self.ip is None:
            return None
        transport = self.ip.data
        if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            return transport.sport
        return None

    @cached_property
    def dst_port(self) -> Optional[int]:
        """Destination port for TCP/UDP packets, or None."""
        if self.ip is None:
            return None
        transport = self.ip.data
        if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            return transport.dport
        return None

    @cached_property
    def transport(self) -> Optional[str]:
        """'TCP', 'UDP', or None for non-TCP/UDP IP packets."""
        if self.ip is None:
            return None
        if isinstance(self.ip.data, dpkt.tcp.TCP):
            return "TCP"
        if isinstance(self.ip.data, dpkt.udp.UDP):
            return "UDP"
        return None

    @cached_property
    def payload(self) -> bytes:
        """
        Application-layer payload bytes.
        Returns b'' for non-TCP/UDP or packets with no payload.
        """
        if self.ip is None:
            return b""
        transport = self.ip.data
        if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            data = transport.data
            return data if isinstance(data, bytes) else bytes(data)
        return b""


@dataclass
class CaptureMeta:
    """
    Summary statistics collected while iterating over a PCAP file.
    Written verbatim to the report['meta'] block in the JSON output.

    Attributes:
        filename:                 Basename of the source file.
        capture_duration_seconds: Wall-clock seconds from first to last packet.
        total_packets:            All frames iterated, including skipped ones.
        tcp_packets:              Frames carrying a TCP segment.
        udp_packets:              Frames carrying a UDP datagram.
        other_packets:            IP frames that are neither TCP nor UDP (ICMP etc).
        skipped_packets:          Non-Ethernet / non-IP / decode-error / oversized
                                  frames. Counted in total_packets but not processable.
        analyzer_version:         Passed in from cli.py.
    """
    filename: str
    capture_duration_seconds: float = 0.0
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    skipped_packets: int = 0
    analyzer_version: str = "0.1.0"

    def to_dict(self) -> dict:
        """Serialize to the meta block in the JSON report."""
        # Uses dataclasses.asdict() so new fields are never silently omitted.
        return asdict(self)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class PcapParser:
    """
    Memory-efficient PCAP loader built on dpkt.

    Usage
    -----
    parser = PcapParser("capture.pcap")
    for packet in parser.parse():
        ...  # process PacketRecord
    meta = parser.meta  # accurate only after generator is exhausted

    Notes
    -----
    - Only classic .pcap is supported. PCAPNG raises PcapParseError immediately
      with a clear message rather than a cryptic dpkt internal error.
    - Ethernet (DLT_EN10MB) and loopback (DLT_NULL) link layers are supported.
      All others are skipped and counted in CaptureMeta.skipped_packets.
    - Frames larger than _MAX_FRAME_BYTES are skipped and counted as skipped_packets
      rather than passed to dpkt, guarding against malformed / fuzzed captures.
    - Truncated captures emit a RuntimeWarning and stop iteration cleanly
      rather than raising — callers receive all packets up to the truncation.
    """

    # DLT_NULL = BSD loopback encapsulation (common in local tcpdump captures)
    _DLT_NULL = 0

    # AF_INET6 varies by platform; define BSD and Linux values explicitly so
    # _decode_loopback works correctly on both without magic literals in-situ.
    _AF_INET6_BSD = 24
    _AF_INET6_LINUX = 10

    # Ethernet MTU ceiling — frames above this are almost certainly malformed.
    _MAX_FRAME_BYTES = 65_535

    def __init__(self, filepath: str, analyzer_version: str = "0.1.0") -> None:
        if not os.path.isfile(filepath):
            raise PcapParseError(f"File not found: {filepath!r}")

        # Reject PCAPNG early with a useful message. OSErrors here are
        # propagated so the caller sees them immediately rather than getting
        # a confusing error later from parse().
        self._reject_pcapng(filepath)

        self._filepath = filepath
        self._meta = CaptureMeta(
            filename=os.path.basename(filepath),
            analyzer_version=analyzer_version,
        )
        self._first_ts: Optional[float] = None
        self._last_ts: Optional[float] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def meta(self) -> CaptureMeta:
        """
        Capture metadata. total_packets and capture_duration_seconds are only
        meaningful after parse() has been fully consumed.
        """
        return self._meta

    def parse(self) -> Generator[PacketRecord, None, None]:
        """
        Yield one PacketRecord per frame in the capture file.

        Raises
        ------
        PcapParseError
            If the file cannot be opened or is not a valid PCAP.
        """
        try:
            fh = open(self._filepath, "rb")
        except OSError as exc:
            raise PcapParseError(f"Cannot open {self._filepath!r}: {exc}") from exc

        # Use the file handle as a context manager so it is always closed,
        # even if an unexpected exception escapes the try/except below.
        with fh:
            try:
                reader = dpkt.pcap.Reader(fh)
            except Exception as exc:
                raise PcapParseError(
                    f"{self._filepath!r} is not a valid PCAP file: {exc}"
                ) from exc

            link_type = reader.datalink()

            try:
                for index, (ts, raw) in enumerate(reader):
                    self._update_timestamps(ts)
                    self._meta.total_packets += 1

                    # Guard against malformed / fuzzed oversized frames.
                    if len(raw) > self._MAX_FRAME_BYTES:
                        self._meta.skipped_packets += 1
                        yield PacketRecord(
                            timestamp=ts, raw=raw, eth=None, ip=None, index=index
                        )
                        continue

                    eth, ip = self._decode_frame(raw, link_type)

                    if ip is None:
                        self._meta.skipped_packets += 1
                    elif isinstance(ip.data, dpkt.tcp.TCP):
                        self._meta.tcp_packets += 1
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        self._meta.udp_packets += 1
                    else:
                        self._meta.other_packets += 1

                    yield PacketRecord(
                        timestamp=ts,
                        raw=raw,
                        eth=eth,
                        ip=ip,
                        index=index,
                    )

            except (struct.error, dpkt.dpkt.NeedData) as exc:
                # Truncated capture — warn and stop cleanly, don't crash.
                warnings.warn(
                    f"Truncated PCAP at packet {self._meta.total_packets}: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )
            finally:
                self._finalise_meta()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _decode_frame(
        self, raw: bytes, link_type: int
    ) -> tuple[Optional[dpkt.ethernet.Ethernet], Optional[dpkt.ip.IP | dpkt.ip6.IP6]]:
        """
        Decode the frame and extract the IP layer.
        Returns (eth, ip) — either may be None on decode failure or
        unsupported link layer.

        Supported link types:
            DLT_EN10MB (1) — standard Ethernet
            DLT_NULL   (0) — BSD loopback (tcpdump on lo interface)
        """
        if link_type == dpkt.pcap.DLT_EN10MB:
            return self._decode_ethernet(raw)

        if link_type == self._DLT_NULL:
            return self._decode_loopback(raw)

        # Unsupported link layer (WiFi radiotap, etc.) — skip silently.
        return None, None

    def _decode_ethernet(
        self, raw: bytes
    ) -> tuple[Optional[dpkt.ethernet.Ethernet], Optional[dpkt.ip.IP | dpkt.ip6.IP6]]:
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except dpkt.dpkt.UnpackError:
            return None, None

        if isinstance(eth.data, dpkt.ip.IP):
            return eth, eth.data
        if isinstance(eth.data, dpkt.ip6.IP6):
            return eth, eth.data

        return eth, None

    def _decode_loopback(
        self, raw: bytes
    ) -> tuple[None, Optional[dpkt.ip.IP | dpkt.ip6.IP6]]:
        """
        DLT_NULL frames carry a 4-byte AF_ family header followed by a raw IP
        packet. socket.AF_INET6 is platform-resolved at runtime (10 on Linux,
        30 on macOS); _AF_INET6_BSD (24) and _AF_INET6_LINUX (10) are defined
        as class constants so the intent is explicit and grep-friendly.
        """
        if len(raw) < 4:
            return None, None
        try:
            family = struct.unpack("I", raw[:4])[0]
            ip_data = raw[4:]
            if family == socket.AF_INET:
                return None, dpkt.ip.IP(ip_data)
            if family in (socket.AF_INET6, self._AF_INET6_BSD, self._AF_INET6_LINUX):
                return None, dpkt.ip6.IP6(ip_data)
        except (dpkt.dpkt.UnpackError, struct.error):
            pass
        return None, None

    def _update_timestamps(self, ts: float) -> None:
        if self._first_ts is None:
            self._first_ts = ts
        self._last_ts = ts

    def _finalise_meta(self) -> None:
        if self._first_ts is not None and self._last_ts is not None:
            self._meta.capture_duration_seconds = round(
                self._last_ts - self._first_ts, 6
            )

    @staticmethod
    def _reject_pcapng(filepath: str) -> None:
        """
        Read the first 4 bytes of the file and raise PcapParseError immediately
        if it looks like a PCAPNG file (magic = 0x0A0D0D0A).

        OSErrors are propagated rather than swallowed so the caller sees the
        real failure immediately instead of getting a confusing error from parse().
        """
        pcapng_magic = b"\x0a\x0d\x0d\x0a"
        with open(filepath, "rb") as f:
            header = f.read(4)
        if header == pcapng_magic:
            raise PcapParseError(
                f"{filepath!r} is a PCAPNG file. Only classic .pcap is currently "
                "supported. Convert with: editcap -F pcap input.pcapng out.pcap"
            )