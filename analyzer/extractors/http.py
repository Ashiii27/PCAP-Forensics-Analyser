"""
analyzer/extractors/http.py
---------------------------
HTTP/1.x request and response parser for reassembled TCP session payloads.

Responsibilities:
  - Detect whether a Session carries HTTP traffic (by protocol label or port).
  - Split pipelined HTTP messages in both client→server and server→client
    streams, handling HTTP/1.0 and HTTP/1.1 keep-alive correctly.
  - Parse per-message metadata:
      Requests  — method, URI, HTTP version, Host, User-Agent, Referer,
                  Content-Type, Content-Length, has_body flag.
      Responses — status code, reason phrase, Content-Type, Content-Length,
                  Server, Transfer-Encoding, Location (redirect target).
  - Pair each request with its corresponding response (positional matching
    within the same session — reliable for HTTP/1.1 with pipelining).
  - Feed parsed data into IOCContainer:
      * Destination IP → observe_ip (Source.HTTP)
      * Host header    → observe_domain (if domain) or observe_ip (if IP)
      * URI            → observe_uri
  - Return a list of HttpTransaction objects for anomaly detection and the
    JSON report.

NOT handled here:
  - HTTP/2 (binary framing — would need a separate HPACK decoder).
  - TLS decryption (sessions with protocol HTTPS/TLS are skipped unless
    payload is plaintext, which happens with MITM captures or test PCAPs).
  - GZIP/deflate body decompression (body_preview is raw bytes).
  - Full body storage (only the first _BODY_PREVIEW_BYTES are retained to
    bound memory usage; has_body flag indicates whether a body was present).

Design notes:
  - Pure stdlib — no dpkt dependency in the HTTP layer. dpkt is used only
    in parser.py for PCAP decoding. This makes the extractor independently
    testable with raw byte strings.
  - The manual parser handles the most common real-world quirks:
      * LF-only line endings (some old HTTP/1.0 servers)
      * Duplicate headers (last value wins except Set-Cookie)
      * Chunked transfer encoding (body boundaries computed from chunk sizes)
      * Missing Content-Length on responses (read until connection close →
        we read whatever payload_server_to_client contains)
  - parse_errors are counted but never raised — a partially-parsed session
    still yields whatever transactions were successfully decoded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from analyzer.ioc import IOCContainer, Source
from analyzer.session import Session


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ports where we attempt HTTP parsing
_HTTP_PORTS  = frozenset({80, 8080, 8000, 8888, 3000, 5000, 3128})
_HTTPS_PORTS = frozenset({443, 8443})

# Maximum body bytes kept in HttpRequest/HttpResponse for anomaly inspection.
_BODY_PREVIEW_BYTES = 512

# Canonical HTTP methods — used to validate the first token of a request line.
_HTTP_METHODS = frozenset({
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
    b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT",
})

# TLS record ContentType byte — if the stream starts with 0x16 it is TLS,
# not plaintext HTTP.  Avoids wasting time parsing encrypted payloads.
_TLS_RECORD_HANDSHAKE = 0x16

# Regex for a valid HTTP request line: METHOD SP Request-URI SP HTTP/x.y CRLF
_REQUEST_LINE_RE = re.compile(
    rb"^([A-Z]{3,10}) +(\S+) +(HTTP/\d\.\d)\r?\n",
    re.IGNORECASE,
)

# Regex for a valid HTTP status line: HTTP/x.y SP Status-Code SP Reason CRLF
_STATUS_LINE_RE  = re.compile(
    rb"^(HTTP/\d\.\d) +(\d{3})([ \t][^\r\n]*)?\r?\n",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HttpRequest:
    """
    One parsed HTTP request extracted from the client→server stream.

    Attributes
    ----------
    method:         HTTP verb in uppercase ("GET", "POST", …).
    uri:            Request-URI exactly as sent (path + query string).
    version:        HTTP version string ("HTTP/1.0" or "HTTP/1.1").
    host:           Value of the Host header, or None if absent.
    user_agent:     Value of the User-Agent header, or None.
    referer:        Value of the Referer header, or None.
    content_type:   Value of the Content-Type header, or None.
    content_length: Parsed integer from Content-Length header, or None.
    has_body:       True if a non-empty body was present (POST data, etc.).
    body_preview:   First _BODY_PREVIEW_BYTES of the request body.
    headers:        All request headers as {lowercase_name: value}.
    stream_offset:  Byte offset in payload_client_to_server where this
                    message started (useful for gap analysis).
    """
    method:         str
    uri:            str
    version:        str
    host:           Optional[str]
    user_agent:     Optional[str]
    referer:        Optional[str]
    content_type:   Optional[str]
    content_length: Optional[int]
    has_body:       bool
    body_preview:   bytes
    headers:        Dict[str, str]
    stream_offset:  int


@dataclass
class HttpResponse:
    """
    One parsed HTTP response extracted from the server→client stream.

    Attributes
    ----------
    version:           HTTP version string.
    status_code:       Numeric status code (200, 404, …).
    reason:            Reason phrase ("OK", "Not Found", …).
    content_type:      Content-Type header value, or None.
    content_length:    Parsed integer from Content-Length, or None.
    transfer_encoding: Transfer-Encoding header value, or None.
    server:            Server header value, or None.
    location:          Location header (redirect target), or None.
    headers:           All response headers as {lowercase_name: value}.
    stream_offset:     Byte offset in payload_server_to_client.
    """
    version:           str
    status_code:       int
    reason:            str
    content_type:      Optional[str]
    content_length:    Optional[int]
    transfer_encoding: Optional[str]
    server:            Optional[str]
    location:          Optional[str]
    headers:           Dict[str, str]
    stream_offset:     int


@dataclass
class HttpTransaction:
    """
    A matched HTTP request/response pair from the same TCP session.

    ``response`` is None when the session was cut off before the server
    replied (e.g. RST-terminated, or capture ended mid-stream).
    """
    request:    HttpRequest
    response:   Optional[HttpResponse]
    session_id: str
    src_ip:     str
    dst_ip:     str
    dst_port:   int
    timestamp:  float   # Session start_time — packet-level ts not available here

    def to_dict(self) -> dict:
        """Serialize for embedding in the sessions[] entries or a flat report."""
        req = self.request
        resp = self.response
        return {
            "session_id":    self.session_id,
            "src_ip":        self.src_ip,
            "dst_ip":        self.dst_ip,
            "dst_port":      self.dst_port,
            "method":        req.method,
            "uri":           req.uri,
            "host":          req.host,
            "user_agent":    req.user_agent,
            "referer":       req.referer,
            "content_type":  req.content_type,
            "has_body":      req.has_body,
            "status_code":   resp.status_code if resp else None,
            "resp_content_type": resp.content_type if resp else None,
            "server":        resp.server if resp else None,
            "location":      resp.location if resp else None,
        }


# ---------------------------------------------------------------------------
# Low-level stream parser — pure bytes, no session dependency
# ---------------------------------------------------------------------------

def _normalise_headers(raw_header_block: bytes) -> Dict[str, str]:
    """
    Parse raw HTTP header bytes (everything after the first line up to the
    blank line) into a {lowercase-name: value} dict.

    Duplicate headers: last value wins (except Set-Cookie which is joined
    with ", " — sufficient for IOC purposes; full cookie tracking is out
    of scope).  Folded headers (obs-fold, RFC 7230 §3.2.6) are unfolded.
    """
    headers: Dict[str, str] = {}
    # Unify CRLF and bare LF.
    normalized = raw_header_block.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    # Unfold obs-fold (continuation lines starting with SP or HT).
    unfolded = re.sub(rb"\n[ \t]+", b" ", normalized)

    for line in unfolded.split(b"\n"):
        if not line or b":" not in line:
            continue
        k, _, v = line.partition(b":")
        key = k.strip().decode("utf-8", errors="replace").lower()
        val = v.strip().decode("utf-8", errors="replace")
        if key == "set-cookie" and key in headers:
            headers[key] = headers[key] + ", " + val
        else:
            headers[key] = val
    return headers


def _parse_content_length(headers: Dict[str, str]) -> Optional[int]:
    """
    Extract and validate the Content-Length header value.

    Tolerates comma-folded duplicate values (e.g. "1024, 1024") which some
    proxies emit per RFC 7230 §3.3.2.  Returns None for conflicting duplicates
    or non-numeric values.
    """
    raw = headers.get("content-length", "").strip()
    if not raw:
        return None
    # Handle comma-folded duplicates — all parts must be identical digits.
    parts = [p.strip() for p in raw.split(",")]
    unique = set(parts)
    if len(unique) == 1 and next(iter(unique)).isdigit():
        return int(parts[0])
    return None


def _read_chunked_body(data: bytes, start: int) -> Tuple[bytes, int]:
    """
    Read a chunked-encoded body from ``data`` starting at ``start``.

    Returns (body_bytes_raw, end_offset) where end_offset points past the
    final ``0\r\n\r\n`` terminator.  If the terminator is not found (truncated
    capture), returns everything from start to end.

    Note: we concatenate raw chunk data without the size lines — sufficient
    for IOC extraction; full de-chunking (joining correctly) would require
    more complex state.
    """
    buf = bytearray()
    offset = start

    while offset < len(data):
        # Read chunk size line
        line_end = data.find(b"\r\n", offset)
        if line_end == -1:
            break
        size_line = data[offset:line_end].split(b";")[0].strip()  # strip chunk-ext
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            break
        offset = line_end + 2  # past CRLF

        if chunk_size == 0:
            # Final chunk — skip optional trailers and terminal CRLF
            term = data.find(b"\r\n", offset)
            offset = (term + 2) if term != -1 else len(data)
            break

        chunk_data = data[offset:offset + chunk_size]
        buf.extend(chunk_data)
        offset += chunk_size + 2  # past chunk data + CRLF

    return bytes(buf), offset


def _iter_http_requests(data: bytes) -> Iterator[Tuple[HttpRequest, int]]:
    """
    Yield (HttpRequest, end_offset) for each HTTP request found in ``data``.

    ``end_offset`` is the byte position in ``data`` immediately after the last
    byte consumed by this request (header + body).  Use it to advance to the
    next pipelined message.
    """
    offset = 0

    while offset < len(data):
        # Skip leading blank lines between pipelined messages.
        # Handles \r\n, \n\n, and lone \n (some HTTP/1.0 agents).
        while offset < len(data) and data[offset:offset+1] in (b"\r", b"\n"):
            if data[offset:offset+2] == b"\r\n":
                offset += 2
            else:
                offset += 1

        remaining = data[offset:]
        if not remaining:
            break

        # Locate header block boundary (\r\n\r\n or \n\n).
        header_end = remaining.find(b"\r\n\r\n")
        lf_header_end = remaining.find(b"\n\n")
        if header_end == -1 and lf_header_end == -1:
            break  # incomplete header — stop

        use_crlf = True
        if header_end == -1 or (lf_header_end != -1 and lf_header_end < header_end):
            header_end = lf_header_end
            use_crlf = False

        sep_len = 4 if use_crlf else 2
        header_block = remaining[:header_end]
        body_start   = offset + header_end + sep_len

        # Split header block into first line + rest.
        first_nl = header_block.find(b"\r\n") if use_crlf else header_block.find(b"\n")
        if first_nl == -1:
            break
        request_line_raw = header_block[:first_nl]
        rest_headers_raw = header_block[first_nl + (2 if use_crlf else 1):]

        # Validate request line.
        m = _REQUEST_LINE_RE.match(request_line_raw + (b"\r\n" if use_crlf else b"\n"))
        if not m:
            break  # not an HTTP request at this offset — give up

        method  = m.group(1).decode("utf-8", errors="replace").upper()
        uri     = m.group(2).decode("utf-8", errors="replace")
        version = m.group(3).decode("utf-8", errors="replace").upper()

        headers = _normalise_headers(rest_headers_raw)

        # Determine body extent.
        transfer_enc = headers.get("transfer-encoding", "").lower()
        content_len  = _parse_content_length(headers)

        if "chunked" in transfer_enc:
            body_raw, end_offset = _read_chunked_body(data, body_start)
        elif content_len is not None and content_len > 0:
            body_raw   = data[body_start:body_start + content_len]
            end_offset = body_start + content_len
        else:
            body_raw   = b""
            end_offset = body_start

        yield HttpRequest(
            method=method,
            uri=uri,
            version=version,
            host=headers.get("host"),
            user_agent=headers.get("user-agent"),
            referer=headers.get("referer"),
            content_type=headers.get("content-type"),
            content_length=content_len,
            has_body=bool(body_raw),
            body_preview=body_raw[:_BODY_PREVIEW_BYTES],
            headers=headers,
            stream_offset=offset,
        ), end_offset

        offset = end_offset


def _iter_http_responses(data: bytes) -> Iterator[Tuple[HttpResponse, int]]:
    """
    Yield (HttpResponse, end_offset) for each HTTP response in ``data``.

    Mirrors the logic of _iter_http_requests for the server→client stream.
    """
    offset = 0

    while offset < len(data):
        # Skip leading blank lines between pipelined messages (mirrors request loop).
        while offset < len(data) and data[offset:offset+1] in (b"\r", b"\n"):
            if data[offset:offset+2] == b"\r\n":
                offset += 2
            else:
                offset += 1

        remaining = data[offset:]
        if not remaining:
            break

        header_end = remaining.find(b"\r\n\r\n")
        lf_header_end = remaining.find(b"\n\n")
        if header_end == -1 and lf_header_end == -1:
            break

        use_crlf = True
        if header_end == -1 or (lf_header_end != -1 and lf_header_end < header_end):
            header_end = lf_header_end
            use_crlf = False

        sep_len      = 4 if use_crlf else 2
        header_block = remaining[:header_end]
        body_start   = offset + header_end + sep_len

        first_nl = header_block.find(b"\r\n") if use_crlf else header_block.find(b"\n")
        if first_nl == -1:
            break
        status_line_raw  = header_block[:first_nl]
        rest_headers_raw = header_block[first_nl + (2 if use_crlf else 1):]

        m = _STATUS_LINE_RE.match(status_line_raw + (b"\r\n" if use_crlf else b"\n"))
        if not m:
            break

        version     = m.group(1).decode("utf-8", errors="replace").upper()
        status_code = int(m.group(2))
        reason_raw  = m.group(3)
        reason      = reason_raw.strip().decode("utf-8", errors="replace") if reason_raw else ""

        headers = _normalise_headers(rest_headers_raw)

        transfer_enc = headers.get("transfer-encoding", "").lower()
        content_len  = _parse_content_length(headers)

        # Responses: Content-Length absent → body extends to stream end
        # (connection-close semantics common for HTTP/1.0).
        if "chunked" in transfer_enc:
            _, end_offset = _read_chunked_body(data, body_start)
        elif content_len is not None:
            end_offset = body_start + content_len
        else:
            # No Content-Length: consume remainder for 1xx/204/304, otherwise
            # assume connection-close and consume the whole remaining stream.
            if status_code in (204, 304) or 100 <= status_code < 200:
                end_offset = body_start
            else:
                end_offset = len(data)   # connection-close assumed

        yield HttpResponse(
            version=version,
            status_code=status_code,
            reason=reason,
            content_type=headers.get("content-type"),
            content_length=content_len,
            transfer_encoding=headers.get("transfer-encoding"),
            server=headers.get("server"),
            location=headers.get("location"),
            headers=headers,
            stream_offset=offset,
        ), end_offset

        offset = end_offset


# ---------------------------------------------------------------------------
# Public API — HttpExtractor
# ---------------------------------------------------------------------------

def _is_http_session(session: Session) -> bool:
    """
    Return True if this session should be attempted for HTTP parsing.

    Accepts:
      - Sessions whose protocol label starts with "HTTP" (port-inferred).
      - Sessions on any known HTTP port regardless of label.

    Rejects:
      - Sessions with a TLS payload signature (first byte == 0x16).
      - Sessions labeled HTTPS/TLS.
    """
    proto = session.protocol.upper()

    # Reject any TLS or HTTPS-labelled session (covers HTTPS/TLS, HTTPS-ALT, etc.)
    if "TLS" in proto or proto.startswith("HTTPS"):
        return False

    # Check for TLS record byte at stream start (handles mislabelled sessions).
    payload = session.payload_client_to_server
    if payload and payload[0] == _TLS_RECORD_HANDSHAKE:
        return False

    if proto.startswith("HTTP"):
        return True

    port = session.dst_port
    return port in _HTTP_PORTS


class HttpExtractor:
    """
    Parses HTTP transactions from a single TCP ``Session`` object.

    Usage
    -----
    ::

        extractor = HttpExtractor()
        transactions = extractor.extract(session)
        extractor.feed_iocs(transactions, ioc_container)

    Or the combined one-liner::

        transactions = HttpExtractor().run(session, ioc_container)
    """

    def __init__(self) -> None:
        # Pre-declare parse_errors so it is always accessible, even before
        # the first extract() call.
        self.parse_errors: int = 0

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def extract(self, session: Session) -> List[HttpTransaction]:
        """
        Parse and return all HTTP transactions found in ``session``.

        Returns an empty list if:
          - The session is not HTTP (TLS payload, wrong protocol label).
          - No valid HTTP messages could be parsed (malformed payload).

        Never raises — parse errors are swallowed and counted in
        ``self.parse_errors`` for diagnostic purposes.
        """
        self.parse_errors = 0

        if not _is_http_session(session):
            return []

        c2s = session.payload_client_to_server
        s2c = session.payload_server_to_client

        if not c2s:
            return []   # No client data — nothing to parse.

        # Parse all requests and responses in parallel.
        try:
            requests  = list(self._parse_requests(c2s))
        except Exception:
            self.parse_errors += 1
            requests = []

        try:
            responses = list(self._parse_responses(s2c))
        except Exception:
            self.parse_errors += 1
            responses = []

        # Zip into transactions (positional pairing — request[i] ↔ response[i]).
        transactions: List[HttpTransaction] = []
        for i, req in enumerate(requests):
            resp = responses[i] if i < len(responses) else None
            transactions.append(HttpTransaction(
                request=req,
                response=resp,
                session_id=session.session_id,
                src_ip=session.src_ip,
                dst_ip=session.dst_ip,
                dst_port=session.dst_port,
                timestamp=session.start_time,
            ))

        return transactions

    def feed_iocs(
        self,
        transactions: List[HttpTransaction],
        iocs: IOCContainer,
    ) -> None:
        """
        Register IOCs from a list of ``HttpTransaction`` objects.

        Observations made per transaction:
          - dst_ip     → observe_ip (Source.HTTP)
          - Host header (if it looks like an IP) → observe_ip (Source.HTTP)
          - Host header (if it looks like a domain) → observe_domain
          - URI + method + host + UA → observe_uri
        """
        for tx in transactions:
            req  = tx.request
            host = req.host or tx.dst_ip

            # Destination IP is always an IOC
            iocs.observe_ip(tx.dst_ip, Source.HTTP, tx.timestamp)

            # Host header: domain or IP?
            if req.host:
                # Strip port suffix if present (e.g. "example.com:8080")
                host_bare = req.host.split(":")[0].strip()
                if _looks_like_ip(host_bare):
                    iocs.observe_ip(host_bare, Source.HTTP, tx.timestamp)
                else:
                    iocs.observe_domain(
                        host_bare,
                        query_type=None,
                        response_ips=None,
                        timestamp=tx.timestamp,
                    )

            # URI
            iocs.observe_uri(
                uri=req.uri,
                method=req.method,
                host=host.split(":")[0],
                user_agent=req.user_agent,
                timestamp=tx.timestamp,
            )

    def run(
        self,
        session: Session,
        iocs: IOCContainer,
    ) -> List[HttpTransaction]:
        """
        Convenience method: extract transactions AND feed IOCs in one call.

        Returns the list of transactions (for anomaly detection / report).
        """
        txns = self.extract(session)
        if txns:
            self.feed_iocs(txns, iocs)
        return txns

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_requests(self, data: bytes) -> List[HttpRequest]:
        """Collect all HttpRequest objects from the c2s payload."""
        reqs = []
        for req, _ in _iter_http_requests(data):
            reqs.append(req)
        return reqs

    def _parse_responses(self, data: bytes) -> List[HttpResponse]:
        """Collect all HttpResponse objects from the s2c payload."""
        resps = []
        for resp, _ in _iter_http_responses(data):
            resps.append(resp)
        return resps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|"           # IPv4
    r"^\[?[0-9a-fA-F:]+\]?$"              # IPv6 (bare or bracket-wrapped)
)

def _looks_like_ip(s: str) -> bool:
    """Quick heuristic: does this string look like an IP rather than a hostname?"""
    return bool(_IP_RE.match(s.strip()))
