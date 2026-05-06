"""
analyzer/ioc.py
---------------
IOC aggregation, deduplication, and normalization.

Responsibilities:
  - Receive raw observations from every protocol extractor (HTTP, DNS, FTP, TLS)
    through a single unified interface.
  - Deduplicate by value so each IOC appears exactly once in the output,
    regardless of how many sessions or extractors reported it.
  - Accumulate per-IOC metadata incrementally:
      * IPs     — which protocols observed them, first-seen timestamp.
      * Domains — DNS query types seen, response IPs mapped, first-seen.
      * URIs    — HTTP method, Host header, User-Agent (one entry per unique
                  (method, host, uri) triple; not deduplicated by uri alone
                  because the same path may be hit with different methods/hosts).
      * User-Agents — unique strings; order of first observation preserved.
      * File hashes — (value, algorithm, filename) tuples from FTP/HTTP.
  - Filter private/reserved IP ranges so internal RFC 1918 addresses are not
    surfaced as external IOCs by default.  Callers can opt-in to include them.
  - Produce a JSON-serializable dict that maps exactly to the `iocs` block
    defined in the project README.
  - Reserve an `enrichment: null` slot on every IP and domain record so the
    enrichment plug-in can populate it without touching this module.

NOT done here:
  - Actual enrichment calls (VirusTotal, AbuseIPDB, Shodan) — those live in
    enrichment/stub.py and populate the `enrichment` field in-place.
  - CIDR / ASN lookups.
  - De-obfuscation of encoded URIs (percent-encoding is preserved as-is;
    callers should decode before observing if required).

Design notes:
  - All internal state is keyed by normalised value strings so lookups are O(1).
  - Timestamps are stored as Unix epoch floats and converted to ISO-8601 only
    in to_dict() — consistent with parser.py and session.py conventions.
  - `seen_in` for IPs is a set internally, sorted alphabetically on output
    so diffs and tests are deterministic.
  - IPv6 addresses are normalised with socket.inet_ntop(AF_INET6, ...) via
    ipaddress.ip_address(...).compressed so "::1" is always "::1", not
    "0:0:0:0:0:0:0:1".
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Source/protocol labels — used in seen_in fields
# ---------------------------------------------------------------------------

class Source:
    """String constants for the `seen_in` protocol labels."""
    HTTP  = "http"
    DNS   = "dns"
    FTP   = "ftp"
    TLS   = "tls"
    SMTP  = "smtp"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _epoch_to_iso(ts: float) -> str:
    """Unix epoch float → ISO-8601 UTC string (matches parser/session convention)."""
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalise_ip(raw: str) -> Optional[str]:
    """
    Validate and normalise an IP address string.

    Returns the compressed canonical form (e.g. '::1' for IPv6 loopback) or
    None if the input is not a valid IP address.
    """
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def _is_private(ip_str: str) -> bool:
    """
    Return True if the IP is private, loopback, link-local, multicast, or
    otherwise non-routable.  Uses the stdlib ipaddress module for correctness.

    Covers:
      - RFC 1918  : 10/8, 172.16/12, 192.168/16
      - Loopback  : 127.0.0.0/8, ::1
      - Link-local: 169.254.0.0/16, fe80::/10
      - Multicast : 224.0.0.0/4, ff00::/8
      - Unspecified: 0.0.0.0, ::
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


def _normalise_domain(raw: str) -> str:
    """
    Lowercase, strip trailing dot (FQDN → label), and strip whitespace.
    Returns empty string for blank input.
    """
    return raw.strip().rstrip(".").lower()


# ---------------------------------------------------------------------------
# Internal record types
# ---------------------------------------------------------------------------

@dataclass
class _IpRecord:
    value:      str
    seen_in:    Set[str]      = field(default_factory=set)
    first_seen: float         = float("inf")
    enrichment: None          = None   # reserved for enrichment plug-in


@dataclass
class _DomainRecord:
    value:        str
    query_types:  Set[str]    = field(default_factory=set)
    response_ips: Set[str]    = field(default_factory=set)
    first_seen:   float       = float("inf")
    enrichment:   None        = None


@dataclass
class _UriRecord:
    """
    Keyed by (method.upper(), host.lower(), uri_path) so the same path
    accessed via different methods or hosts appears as separate entries.
    """
    value:      str           # URI path (may include query string)
    method:     str
    host:       str
    user_agent: Optional[str]


@dataclass
class _FileHashRecord:
    value:     str            # hex digest
    algorithm: str            # e.g. "md5", "sha256"
    filename:  Optional[str]  # original filename if known
    source:    str            # protocol that produced it


# ---------------------------------------------------------------------------
# Public API — IOCContainer
# ---------------------------------------------------------------------------

class IOCContainer:
    """
    Central IOC collector for one PCAP analysis run.

    Each ``observe_*`` method is idempotent for the same value: calling it
    multiple times accumulates metadata (timestamps, seen_in sources, response
    IPs) without creating duplicate entries.

    Usage
    -----
    ::

        iocs = IOCContainer()

        # From HTTP extractor
        iocs.observe_ip("93.184.216.34", Source.HTTP, timestamp=pkt.timestamp)
        iocs.observe_uri("/wp-login.php", method="POST",
                         host="93.184.216.34", user_agent="curl/7.68",
                         timestamp=pkt.timestamp)

        # From DNS extractor
        iocs.observe_domain("update.evil.xyz", query_type="A",
                             response_ips=["185.220.101.47"],
                             timestamp=pkt.timestamp)

        report_block = iocs.to_dict()   # → goes directly into report["iocs"]
    """

    def __init__(self, include_private_ips: bool = False) -> None:
        """
        Parameters
        ----------
        include_private_ips:
            If True, RFC 1918 / loopback / link-local IPs are included in the
            ``ips`` output.  Default is False — internal IPs are usually noise
            for threat-intel purposes.  Set to True for internal threat hunting.
        """
        self._include_private = include_private_ips

        self._ips:         Dict[str, _IpRecord]       = {}
        self._domains:     Dict[str, _DomainRecord]   = {}
        # URI key is (method, host, uri_path)
        self._uris:        Dict[Tuple[str,str,str], _UriRecord] = {}
        self._user_agents: List[str]                  = []
        self._ua_seen:     Set[str]                   = set()
        self._file_hashes: List[_FileHashRecord]      = []
        self._hash_seen:   Set[str]                   = set()   # "algo:value"

    # ------------------------------------------------------------------
    # Observation methods — called by protocol extractors
    # ------------------------------------------------------------------

    def observe_ip(
        self,
        ip: str,
        source: str,
        timestamp: float,
        skip_private: Optional[bool] = None,
    ) -> None:
        """
        Record an IP address observed in traffic.

        Parameters
        ----------
        ip:
            Raw IP string (IPv4 dotted-decimal or IPv6 colon-hex).
        source:
            Protocol that observed this IP — one of the ``Source.*`` constants.
        timestamp:
            Unix epoch float from the packet header.
        skip_private:
            Override the container-level ``include_private_ips`` setting.
            Pass True to force-skip this specific IP even if the container
            would normally include private IPs.  Pass False to force-include.
            None (default) uses the container setting.
        """
        normalised = _normalise_ip(ip)
        if normalised is None:
            return   # silently drop malformed IPs

        # Private-IP filter
        if _is_private(normalised):
            force_skip = skip_private if skip_private is not None else not self._include_private
            if force_skip:
                return

        if normalised not in self._ips:
            self._ips[normalised] = _IpRecord(value=normalised)

        rec = self._ips[normalised]
        rec.seen_in.add(source)
        if timestamp < rec.first_seen:
            rec.first_seen = timestamp

    def observe_domain(
        self,
        domain: str,
        query_type: Optional[str],
        response_ips: Optional[List[str]],
        timestamp: float,
    ) -> None:
        """
        Record a DNS domain name.

        Parameters
        ----------
        domain:
            Raw domain string (will be lowercased and trailing-dot stripped).
        query_type:
            DNS RR type string e.g. "A", "AAAA", "MX", "TXT".  Pass None if
            this is a passive observation (e.g. Host header from HTTP).
        response_ips:
            List of IP strings returned in the DNS response.  Pass None or []
            if not available.
        timestamp:
            Unix epoch float.
        """
        normalised = _normalise_domain(domain)
        if not normalised:
            return

        if normalised not in self._domains:
            self._domains[normalised] = _DomainRecord(value=normalised)

        rec = self._domains[normalised]
        if query_type:
            rec.query_types.add(query_type.upper())
        if response_ips:
            for rip in response_ips:
                n = _normalise_ip(rip)
                if n:
                    rec.response_ips.add(n)
        if timestamp < rec.first_seen:
            rec.first_seen = timestamp

    def observe_uri(
        self,
        uri: str,
        method: str,
        host: str,
        user_agent: Optional[str],
        timestamp: float,
    ) -> None:
        """
        Record an HTTP request URI.

        Deduplication key is (method.upper(), host.lower(), uri).
        If the same triple is observed again only the first user_agent is kept.

        Parameters
        ----------
        uri:
            Path + optional query string (e.g. "/wp-login.php?redirect=1").
        method:
            HTTP verb ("GET", "POST", etc.).
        host:
            HTTP Host header value or destination IP string.
        user_agent:
            HTTP User-Agent header value, or None if not present.
        timestamp:
            Unused for deduplication but kept for API consistency with other
            observe_* methods (future: first_seen on URIs).
        """
        m = method.upper().strip()
        h = host.lower().strip()
        u = uri.strip()
        key = (m, h, u)

        if key not in self._uris:
            self._uris[key] = _UriRecord(
                value=u,
                method=m,
                host=h,
                user_agent=user_agent,
            )

        # Optionally register the UA as a standalone IOC too
        if user_agent:
            self.observe_user_agent(user_agent)

    def observe_user_agent(self, user_agent: str) -> None:
        """
        Record a unique HTTP User-Agent string.
        Insertion order is preserved for output stability.
        """
        ua = user_agent.strip()
        if ua and ua not in self._ua_seen:
            self._ua_seen.add(ua)
            self._user_agents.append(ua)

    def observe_file_hash(
        self,
        value: str,
        algorithm: str,
        filename: Optional[str],
        source: str,
    ) -> None:
        """
        Record a file hash extracted from a protocol payload.

        Parameters
        ----------
        value:
            Hex digest string.
        algorithm:
            Hash algorithm name ("md5", "sha1", "sha256", etc.).
        filename:
            Original filename if recoverable, else None.
        source:
            Protocol label (``Source.*`` constant).
        """
        v = value.strip().lower()
        a = algorithm.strip().lower()
        dedup_key = f"{a}:{v}"
        if dedup_key not in self._hash_seen:
            self._hash_seen.add(dedup_key)
            self._file_hashes.append(
                _FileHashRecord(value=v, algorithm=a, filename=filename, source=source)
            )

    # ------------------------------------------------------------------
    # Convenience bulk helpers — used by extractors that batch-emit IOCs
    # ------------------------------------------------------------------

    def observe_ips(
        self,
        ips: List[str],
        source: str,
        timestamp: float,
    ) -> None:
        """Batch version of ``observe_ip``."""
        for ip in ips:
            self.observe_ip(ip, source, timestamp)

    def observe_response_ips(
        self,
        domain: str,
        response_ips: List[str],
        timestamp: float,
        source: str = Source.DNS,
    ) -> None:
        """
        Register each IP in a DNS response both as a standalone IP IOC and
        as a response_ip on the domain record.  This avoids needing to call
        observe_ip and observe_domain separately for every DNS answer.
        """
        for rip in response_ips:
            self.observe_ip(rip, source, timestamp)
        self.observe_domain(domain, query_type=None, response_ips=response_ips,
                            timestamp=timestamp)

    # ------------------------------------------------------------------
    # Read-only accessors — for programmatic use by anomaly.py / tests
    # ------------------------------------------------------------------

    @property
    def ip_count(self) -> int:
        """Number of unique IP IOCs collected."""
        return len(self._ips)

    @property
    def domain_count(self) -> int:
        """Number of unique domain IOCs collected."""
        return len(self._domains)

    @property
    def uri_count(self) -> int:
        """Number of unique URI IOCs collected."""
        return len(self._uris)

    def has_ip(self, ip: str) -> bool:
        """Return True if this IP (normalised) is already recorded."""
        n = _normalise_ip(ip)
        return n is not None and n in self._ips

    def has_domain(self, domain: str) -> bool:
        """Return True if this domain (normalised) is already recorded."""
        return _normalise_domain(domain) in self._domains

    def get_ip(self, ip: str) -> Optional[_IpRecord]:
        """Return the raw _IpRecord for in-process inspection, or None."""
        n = _normalise_ip(ip)
        return self._ips.get(n) if n else None

    def get_domain(self, domain: str) -> Optional[_DomainRecord]:
        """Return the raw _DomainRecord for in-process inspection, or None."""
        return self._domains.get(_normalise_domain(domain))

    def iter_ips(self):
        """Iterate over all _IpRecord objects."""
        return iter(self._ips.values())

    def iter_domains(self):
        """Iterate over all _DomainRecord objects."""
        return iter(self._domains.values())

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """
        Serialize all collected IOCs to the ``iocs`` block of the JSON report.

        Output structure matches the README spec exactly:
        ::

            {
              "ips": [...],
              "domains": [...],
              "uris": [...],
              "user_agents": [...],
              "file_hashes": [...]
            }

        Records are sorted for output stability:
          - IPs by value (lexicographic — deterministic across runs)
          - Domains by value
          - URIs by (method, host, uri)
          - User-agents in insertion order (first-seen)
          - File hashes in insertion order
        """
        ips = [
            {
                "value":      rec.value,
                "seen_in":    sorted(rec.seen_in),
                "first_seen": _epoch_to_iso(rec.first_seen)
                              if rec.first_seen != float("inf") else None,
                "enrichment": rec.enrichment,
            }
            for rec in sorted(self._ips.values(), key=lambda r: r.value)
        ]

        domains = [
            {
                "value":        rec.value,
                "query_types":  sorted(rec.query_types),
                "response_ips": sorted(rec.response_ips),
                "first_seen":   _epoch_to_iso(rec.first_seen)
                                if rec.first_seen != float("inf") else None,
                "enrichment":   rec.enrichment,
            }
            for rec in sorted(self._domains.values(), key=lambda r: r.value)
        ]

        uris = [
            {
                "value":      rec.value,
                "method":     rec.method,
                "host":       rec.host,
                "user_agent": rec.user_agent,
            }
            for rec in sorted(
                self._uris.values(),
                key=lambda r: (r.method, r.host, r.value),
            )
        ]

        file_hashes = [
            {
                "value":     rec.value,
                "algorithm": rec.algorithm,
                "filename":  rec.filename,
                "source":    rec.source,
            }
            for rec in self._file_hashes
        ]

        return {
            "ips":         ips,
            "domains":     domains,
            "uris":        uris,
            "user_agents": list(self._user_agents),
            "file_hashes": file_hashes,
        }

    def __repr__(self) -> str:
        return (
            f"<IOCContainer ips={self.ip_count} domains={self.domain_count} "
            f"uris={self.uri_count} uas={len(self._user_agents)} "
            f"hashes={len(self._file_hashes)}>"
        )
