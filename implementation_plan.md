# PCAP Forensics Analyser — Implementation Roadmap

## Current State

| File | Status |
|---|---|
| `analyzer/parser.py` | ✅ Complete |
| `analyzer/session.py` | ✅ Complete |
| `analyzer/ioc.py` | ✅ Complete |
| `analyzer/extractors/http.py` | ✅ Complete |
| `analyzer/extractors/dns.py` | ❌ Stub (empty) |
| `analyzer/extractors/ftp.py` | ❌ Stub (empty) |
| `analyzer/extractors/tls.py` | ❌ Stub (empty) |
| `analyzer/anomaly.py` | ❌ Stub (TODO) |
| `report/report.py` | ❌ Stub (empty) |
| `enrichment/stub.py` | ❌ Stub (placeholder) |
| `cli.py` | ❌ Stub (one-liner comment) |
| `tests/test_extractors.py` | ❌ Empty |
| `tests/test_anomaly.py` | ❌ Empty |

The pipeline data-flow is:
```
cli.py
  └── PcapParser (parser.py)          → PacketRecord stream
        └── TCPSessionRebuilder         → Session list
        └── UDPFlowGrouper              → Session list
              ├── HttpExtractor          → HttpTransaction list → IOCContainer
              ├── DnsExtractor           → DnsTransaction list → IOCContainer
              ├── FtpExtractor           → FtpTransaction list → IOCContainer
              └── TlsExtractor           → TlsRecord list      → IOCContainer
                    └── AnomalyEngine   → Anomaly list
                          └── ReportBuilder → JSON output
```

---

## Phase 1 — Protocol Extractors (Core)

Build in this order — each extractor is independently testable from raw bytes.

---

### Step 1 · `analyzer/extractors/dns.py`

**What it does:** Parse DNS queries and responses from reassembled UDP sessions on port 53.

**Key responsibilities:**
- Parse DNS wire format (header → questions → answers) using `dpkt.dns.DNS`
- Extract per-query: `name`, `type` (A/AAAA/MX/TXT/CNAME/PTR), `src_ip`, `timestamp`
- Extract per-response: `name`, `type`, `TTL`, `response_ips`
- Compute **Shannon entropy** on each subdomain label to flag tunneling candidates
- Feed IOCs: `observe_domain(name, query_type, response_ips)` + `observe_ip` for each answer IP
- Dataclasses: `DnsQuery`, `DnsResponse`, `DnsTransaction`
- Return `List[DnsTransaction]` from `DnsExtractor.run(session, ioc_container)`

**Anomaly signals to surface (consumed by anomaly.py later):**
- Label entropy > 3.5 → possible DNS tunneling
- Response size > 512 bytes → possible data exfiltration
- Query for rare TLD (`.xyz`, `.top`, `.tk` etc.)
- High query rate to a single domain (beaconing indicator)

**Technique tag:** T1071.004 (Application Layer Protocol: DNS)

---

### Step 2 · `analyzer/extractors/ftp.py`

**What it does:** Parse FTP command/response dialogue from reassembled TCP sessions on port 21.

**Key responsibilities:**
- Split client→server stream into FTP commands (line-by-line, RFC 959 format)
- Split server→client stream into response codes + text
- Extract: `USER`, `PASS` (cleartext credentials — high-value IOC), `CWD`, `RETR`, `STOR` (transferred filenames), `PORT`/`PASV`/`EPSV` (data channel IPs)
- Pair commands with their response codes positionally (same model as HTTP pipelining)
- Feed IOCs: `observe_ip` for data channel IPs, `observe_file_hash` for `RETR`/`STOR` filenames if hash available
- Dataclasses: `FtpCommand`, `FtpResponse`, `FtpSession` (holds credential + file list)
- Return `FtpSession` (or `None` if no FTP found) from `FtpExtractor.run(session, ioc_container)`

**Anomaly signals:**
- `USER`/`PASS` observed → cleartext credentials (always flag)
- `RETR`/`STOR` of executable extensions (`.exe`, `.ps1`, `.sh`, `.bat`)
- Login failure codes (530) + retry pattern → brute force

**Technique tags:** T1078 (Valid Accounts), T1048 (Exfiltration over Alternative Protocol)

---

### Step 3 · `analyzer/extractors/tls.py`

**What it does:** Parse TLS ClientHello handshakes from TCP sessions on port 443/8443 and produce JA3 fingerprints.

**Key responsibilities:**
- Detect TLS record type 0x16 (Handshake), handshake type 0x01 (ClientHello)
- Manually parse ClientHello fields:
  - `version` (legacy record version)
  - `cipher_suites` list (exclude GREASE values `0x?A?A`)
  - `extensions` list (type codes, exclude GREASE)
  - `supported_groups` (extension 0x000A — elliptic curves, exclude GREASE)
  - `ec_point_formats` (extension 0x000B)
- Compute **JA3 string**: `version,ciphers,extensions,curves,point_formats` (comma-separated, dash-joined within fields)
- Compute **JA3 hash**: `md5(ja3_string).hexdigest()`
- Feed IOCs: `observe_ip` for the server IP with `Source.TLS`
- Dataclasses: `TlsRecord` holding `ja3`, `ja3_hash`, `dst_ip`, `dst_port`, `session_id`, `timestamp`
- Return `List[TlsRecord]` from `TlsExtractor.run(session, ioc_container)`

> [!NOTE]
> GREASE values (RFC 8701) — `0x0A0A`, `0x1A1A` ... `0xFAFA` — must be filtered from all JA3 fields or the hash won't match public blocklists.

**Technique tags:** T1573 (Encrypted Channel), T1071.001

---

## Phase 2 — Anomaly Engine

### Step 4 · `analyzer/anomaly.py`

**What it does:** Rule-based cross-session anomaly detection. Consumes the full `List[Session]` and `IOCContainer` after all extractors have run.

**Anomaly dataclass:**
```python
@dataclass
class Anomaly:
    rule: str          # e.g. "DNS_HIGH_ENTROPY_SUBDOMAIN"
    severity: str      # "low" | "medium" | "high" | "critical"
    description: str
    evidence: dict     # arbitrary k/v
    mitre_technique: str   # e.g. "T1071.004"
    session_id: Optional[str]
    src_ip: Optional[str]
    timestamp: Optional[float]
```

**Rules to implement (in priority order):**

| Rule ID | Trigger | Severity | MITRE |
|---|---|---|---|
| `PORT_SCAN` | Single src_ip → ≥15 distinct dst_ports in ≤60s | high | T1046 |
| `DNS_HIGH_ENTROPY_SUBDOMAIN` | Subdomain label Shannon entropy > 3.5 | high | T1071.004 |
| `DNS_LARGE_RESPONSE` | DNS response payload > 512 bytes | medium | T1048.003 |
| `HTTP_NON_STANDARD_PORT` | HTTP session on port ≠ 80, 8080, 8000 | medium | T1571 |
| `CLEARTEXT_AUTH_FTP` | FTP USER+PASS observed in session | high | T1078 |
| `CLEARTEXT_AUTH_TELNET` | TCP session on port 23 with data | high | T1078 |
| `HTTP_BASIC_AUTH` | `Authorization: Basic` header in HTTP request | medium | T1078 |
| `SUSPICIOUS_USER_AGENT` | Empty, curl-only, or known-bad UA strings | low | T1071.001 |
| `FTP_EXECUTABLE_TRANSFER` | RETR/STOR of `.exe/.ps1/.sh/.bat` filename | high | T1105 |
| `TLS_WEAK_CIPHER` | Cipher suite in known-weak list (RC4, DES, NULL, EXPORT) | medium | T1573 |

**`AnomalyEngine` class:**
```python
class AnomalyEngine:
    def run(self, sessions: List[Session], iocs: IOCContainer,
            dns_txns: List[DnsTransaction], ftp_sessions: List[FtpSession],
            http_txns: List[HttpTransaction], tls_records: List[TlsRecord]
    ) -> List[Anomaly]: ...
```

---

## Phase 3 — Report Builder & CLI

### Step 5 · `report/report.py`

**What it does:** Assembles all analyser outputs into the final JSON report structure.

**`ReportBuilder` class:**
```python
class ReportBuilder:
    def build(
        self,
        meta: CaptureMeta,
        sessions: List[Session],
        iocs: IOCContainer,
        anomalies: List[Anomaly],
        tls_records: List[TlsRecord],
        http_transactions: List[HttpTransaction],
    ) -> dict: ...

    def write_json(self, report: dict, output_path: str) -> None: ...
```

**Output structure** (matches README spec exactly):
```json
{
  "meta": { ... },
  "sessions": [ ... ],
  "iocs": { "ips": [], "domains": [], "uris": [], "user_agents": [], "file_hashes": [] },
  "anomalies": [ ... ],
  "tls": { "ja3_hashes": [ ... ] },
  "enrichment": null
}
```

**Notes:**
- `sessions[]` entries embed their `http_transactions` as a sub-list (optional, `--verbose` only)
- `meta` needs a `total_sessions` field added to `CaptureMeta` (minor `parser.py` addition)
- Write with `json.dump(indent=2, ensure_ascii=False)`

---

### Step 6 · `cli.py`

**What it does:** Argparse entry point that wires the full pipeline together.

**Flags** (per README):

| Flag | Type | Description |
|---|---|---|
| `--input` | str, required | Path to `.pcap` file |
| `--output` | str, required | Output path for JSON report |
| `--verbose` | bool flag | Print Rich live summary table to terminal |
| `--no-tls` | bool flag | Skip JA3 fingerprinting |
| `--include-private-ips` | bool flag | Include RFC 1918 IPs in IOC output |
| `--version` | | Print version and exit |

**Pipeline wiring order inside `main()`:**
1. `PcapParser` → feed all packets
2. `TCPSessionRebuilder.build()` + `UDPFlowGrouper.build()`
3. For each session: run `HttpExtractor`, `DnsExtractor`, `FtpExtractor`, `TlsExtractor`
4. `AnomalyEngine.run()`
5. `ReportBuilder.build()` + `write_json()`
6. If `--verbose`: print Rich summary table

**Rich summary table columns:** Sessions, HTTP txns, DNS queries, FTP sessions, TLS records, IOC IPs, IOC Domains, Anomalies

---

## Phase 4 — Enrichment Hook

### Step 7 · `enrichment/stub.py`

**What it does:** Defines the plug-in interface and a no-op stub. Real API keys slot in here later.

```python
class EnrichmentProvider(ABC):
    @abstractmethod
    def enrich_ip(self, ip: str) -> dict | None: ...

    @abstractmethod
    def enrich_domain(self, domain: str) -> dict | None: ...

class NullEnrichment(EnrichmentProvider):
    """Default stub — returns None for everything."""
    def enrich_ip(self, ip): return None
    def enrich_domain(self, domain): return None
```

Callers iterate `iocs.iter_ips()` and call `enrich_ip()`, writing results back to `rec.enrichment`. Zero changes to core modules.

---

## Phase 5 — Tests

### Step 8 · `tests/test_extractors.py`

Tests for all four extractors using synthetic raw bytes — no real PCAP required.

**Coverage targets:**

| Extractor | Test cases |
|---|---|
| HTTP | GET/POST parsing, chunked TE, pipelining, TLS rejection, Host IOC routing |
| DNS | A/AAAA query parsing, entropy scoring, NXDOMAIN handling |
| FTP | USER/PASS extraction, RETR filename, PORT address parsing |
| TLS | ClientHello parse, JA3 string, GREASE filtering |

### Step 9 · `tests/test_anomaly.py`

Tests for each anomaly rule using mock session/transaction objects.

---

## Build Order Summary

```
Step 1: dns.py          ← pure bytes, no deps beyond ioc.py
Step 2: ftp.py          ← pure bytes, no deps beyond ioc.py
Step 3: tls.py          ← pure bytes, needs hashlib + md5
Step 4: anomaly.py      ← depends on all extractor outputs
Step 5: report/report.py ← depends on anomaly.py + ioc.py
Step 6: cli.py          ← wires everything together
Step 7: enrichment/stub.py ← isolated, no cross-deps
Step 8: test_extractors.py
Step 9: test_anomaly.py
```

> [!IMPORTANT]
> Steps 1–3 can be built in parallel — each extractor is fully self-contained.
> Steps 4–6 must be sequential (anomaly needs all extractor outputs; CLI needs everything).
