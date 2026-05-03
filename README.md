# PCAP Forensics Analyzer

A command-line forensic analysis tool that dissects `.pcap` network capture files, reconstructs TCP sessions, extracts indicators of compromise (IOCs), detects protocol anomalies, and generates structured JSON reports ready for downstream tooling or threat intel pipelines.

Built for SOC analysts and detection engineers who need more than what Wireshark shows by default.

---

## What It Does

Most PCAP analysis is manual — open Wireshark, filter by protocol, dig through packets one by one. This tool automates the forensic pipeline:

- Reconstructs TCP sessions from raw packets (handles out-of-order and partial streams)
- Extracts IOCs across HTTP, DNS, FTP, and TLS — deduplicated and normalized
- Detects anomalies using rule-based heuristics (port scanning, DNS tunneling, cleartext auth, beaconing patterns)
- Fingerprints TLS ClientHello handshakes using **JA3** — a technique used by real EDR and NDR platforms to identify malware C2 communication
- Outputs a single clean JSON report, structured for piping into SIEM, threat intel, or custom detection pipelines

---

## Key Features

**Session Reconstruction**
Reassembles TCP streams from raw packets using sequence number ordering. Flags incomplete or truncated sessions rather than silently dropping them.

**Multi-Protocol Extraction**
- HTTP — methods, URIs, Host headers, User-Agents, response codes, POST body flags
- DNS — query names, types, response IPs, TTLs; flags long subdomains and rare TLDs
- FTP — commands, responses, filenames transferred; extracts cleartext credentials
- TLS — version, cipher suites, extension list; produces JA3 hash per ClientHello

**Anomaly Detection**
Rule-based engine with the following detections out of the box:
- Port scan detection (high port fan-out from a single source IP in a short window)
- DNS tunneling (Shannon entropy scoring on subdomain labels, threshold > 3.5)
- HTTP on non-standard ports (port ≠ 80/443)
- Cleartext authentication protocols (FTP, Telnet, HTTP Basic)
- Abnormally large DNS responses (potential data exfiltration indicator)

**JA3 TLS Fingerprinting**
Parses TLS ClientHello manually to extract the cipher suite list, extension types, elliptic curves, and point formats. Concatenates fields per the JA3 spec and produces an MD5 hash. Known malicious JA3 hashes can be compared against public blocklists.

**Enrichment-Ready Architecture**
Every IOC in the output carries an `enrichment: null` field. A plug-in enrichment module (VirusTotal, AbuseIPDB, Shodan) can populate these fields without touching any core analyzer code.

---

## Installation

```bash
git clone https://github.com/ashiii27/pcap-analyzer.git
cd pcap-analyzer
pip install -r requirements.txt
```

**Requirements:** Python 3.9+, `scapy`, `dpkt`, `rich`

```
scapy>=2.5.0
dpkt>=1.9.8
rich>=13.0.0
```

> On Linux, raw packet capture requires `sudo` or `CAP_NET_RAW` capability. For offline `.pcap` analysis (the primary use case), no elevated privileges are needed.

---

## Usage

**Basic analysis:**
```bash
python cli.py --input capture.pcap --output report.json
```

**Verbose terminal output while writing JSON:**
```bash
python cli.py --input capture.pcap --output report.json --verbose
```

**Skip TLS fingerprinting (faster on large captures):**
```bash
python cli.py --input capture.pcap --output report.json --no-tls
```

**CLI flags:**

| Flag | Description |
|---|---|
| `--input` | Path to the `.pcap` or `.pcapng` file |
| `--output` | Output path for the JSON report |
| `--verbose` | Print a live summary table to terminal while analyzing |
| `--no-tls` | Skip JA3 fingerprinting (useful for large captures) |

---

## Output Format

All findings are written to a single JSON file with the following top-level structure:

```json
{
  "meta": {
    "filename": "capture.pcap",
    "capture_duration_seconds": 312.4,
    "total_packets": 18472,
    "total_sessions": 204,
    "analyzer_version": "0.1.0"
  },
  "sessions": [
    {
      "session_id": "192.168.1.5:54321-93.184.216.34:80",
      "protocol": "HTTP",
      "src_ip": "192.168.1.5",
      "dst_ip": "93.184.216.34",
      "dst_port": 80,
      "start_time": "2024-11-03T14:22:01Z",
      "duration_seconds": 1.3,
      "bytes_transferred": 4821,
      "status": "complete"
    }
  ],
  "iocs": {
    "ips": [
      {
        "value": "93.184.216.34",
        "seen_in": ["http", "dns"],
        "first_seen": "2024-11-03T14:22:01Z",
        "enrichment": null
      }
    ],
    "domains": [
      {
        "value": "update.totally-legit-cdn.xyz",
        "query_types": ["A"],
        "response_ips": ["185.220.101.47"],
        "enrichment": null
      }
    ],
    "uris": [
      {
        "value": "/wp-login.php",
        "method": "POST",
        "host": "93.184.216.34",
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"
      }
    ],
    "user_agents": ["Mozilla/5.0 (compatible; Googlebot/2.1)"],
    "file_hashes": []
  },
  "anomalies": [
    {
      "rule": "DNS_HIGH_ENTROPY_SUBDOMAIN",
      "severity": "high",
      "description": "Subdomain label entropy 4.21 exceeds threshold 3.5 — possible DNS tunneling",
      "evidence": {
        "query": "aGVsbG8gd29ybGQ.update.totally-legit-cdn.xyz",
        "entropy": 4.21,
        "src_ip": "192.168.1.5"
      },
      "mitre_technique": "T1071.004"
    },
    {
      "rule": "CLEARTEXT_AUTH_FTP",
      "severity": "medium",
      "description": "Cleartext FTP credentials observed in session",
      "evidence": {
        "username": "admin",
        "password": "admin123",
        "dst_ip": "192.168.1.100"
      },
      "mitre_technique": "T1078"
    }
  ],
  "tls": {
    "ja3_hashes": [
      {
        "ja3": "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
        "ja3_hash": "e7d705a3286e19ea42f587b6e7359d6f",
        "dst_ip": "93.184.216.34",
        "dst_port": 443,
        "known_malicious": false
      }
    ]
  },
  "enrichment": null
}
```

Each anomaly maps to a **MITRE ATT&CK technique ID** — this is intentional. It makes the output directly usable in detection engineering workflows and demonstrates ATT&CK fluency in code, not just on a resume.

---

## Project Structure

```
pcap-analyzer/
├── analyzer/
│   ├── parser.py            # PCAP loading, raw packet iteration
│   ├── session.py           # TCP session reconstruction
│   ├── ioc.py               # IOC aggregation and normalization
│   ├── anomaly.py           # Rule-based anomaly detection engine
│   └── extractors/
│       ├── http.py          # HTTP request/response parsing
│       ├── dns.py           # DNS query/response parsing + entropy scoring
│       ├── ftp.py           # FTP command parsing + credential extraction
│       └── tls.py           # TLS handshake parsing + JA3 fingerprinting
├── enrichment/
│   └── stub.py              # Plug-in hooks for VT / AbuseIPDB / Shodan
├── cli.py                   # Argparse entry point
├── requirements.txt
└── README.md
```

The `enrichment/` module is intentionally isolated. Adding VirusTotal or AbuseIPDB integration requires only changes inside that directory — zero modifications to the core analyzer.

---

## Testing With Real Captures

The following sources provide real-world `.pcap` files for testing:

- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) — real malware PCAP samples with write-ups
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — protocol-specific captures
- [PacketTotal](https://packettotal.com/) — community-uploaded PCAPs with analysis

Running this tool against Malware Traffic Analysis samples and comparing output to the site's own write-ups is the best way to validate detections.

---

## Roadmap

- [ ] **VirusTotal enrichment** — batch IOC lookups via VT API v3, rate-limit aware, populates `enrichment` fields in output
- [ ] **AbuseIPDB enrichment** — confidence score + abuse category per IP
- [ ] **Shodan enrichment** — open ports and banners for external IPs
- [ ] **PCAPNG support** — currently handles classic `.pcap`; PCAPNG has wider adoption
- [ ] **HTML report mode** — human-readable investigation report alongside JSON
- [ ] **YARA rule matching** — scan reassembled TCP payloads against a user-supplied YARA ruleset
- [ ] **Beaconing detection** — time-delta analysis on repeated connections to identify C2 polling intervals
- [ ] **MITRE ATT&CK Navigator export** — generate a Navigator layer JSON from detected techniques

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

## Author

**Ash** — B.Tech CSE, MMMUT Gorakhpur
[GitHub](https://github.com/ashiii27) · [TryHackMe](https://tryhackme.com/p/ashiii27)
