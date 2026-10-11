#!/usr/bin/env python3
"""
rat_h3.py v2 — overpowered HTTP/3 client for authorized security testing.

Bypasses TCP-only national middleboxes (DNS hijack + SNI MITM) via QUIC/UDP 443
direct to CDN edge IPs. Built for bug-bounty PoC validation inside program scope.

Requires: ~/workspace/rat-tools-venv  (aioquic, httpx, certifi, brotli)
    ~/workspace/rat-tools-venv/bin/python rat_h3.py

v2 upgrades over v1:
  - FIX: real edge-IP discovery via DNS-over-HTTPS (v1 shipped placeholder
    "CF_EDGE_IP_1" and could never connect).
  - FIX: removed dead code in request().
  - Multi-value header collection: every header pair is kept (v1's dict
    collapsed duplicate set-cookie — the exact bug the skill doc warns about).
  - Decompression: gzip + brotli + deflate.
  - H3Session: persistent QUIC connection, multiplexed concurrent streams,
    per-request timeout, retry with backoff + edge-IP failover.
  - Evidence capture: timestamped raw request/response transcripts for reports.
  - DoH resolver is stdlib-only (no extra deps); edge-IP cache per host.

Usage (library):
    from rat_h3 import H3Session, fetch, get_text
    async with H3Session("crypto.com") as s:
        r = await s.get("/robots.txt")
        print(r.status, len(r.body))
        print(r.get_all("set-cookie"))   # ALL values, not collapsed

Usage (one-shot, backward compatible):
    status, headers, body = await fetch("crypto.com", "/robots.txt")
"""
import asyncio
import gzip
import json
import os
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

import certifi
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

# ---------------------------------------------------------------- DoH

DOH_URL = "https://cloudflare-dns.com/dns-query"
_edge_cache: dict = {}


def doh_resolve(host: str, qtype: str = "A", timeout: float = 10.0) -> list:
    """Resolve via DNS-over-HTTPS (stdlib only). Returns list of answer strings."""
    qs = urllib.parse.urlencode({"name": host, "type": qtype})
    req = urllib.request.Request(
        f"{DOH_URL}?{qs}", headers={"accept": "application/dns-json",
                                    "user-agent": "rat-h3/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode())
    return [a["data"] for a in data.get("Answer", [])
            if a.get("type") in (1, 28)]  # A or AAAA


def discover_edge_ips(host: str, timeout: float = 10.0) -> list:
    """Edge IPs for a host via DoH. Cached per host. Env override: RAT_H3_EDGE_IPS."""
    env = os.environ.get("RAT_H3_EDGE_IPS", "").strip()
    if env:
        return [x.strip() for x in env.split(",") if x.strip()]
    if host not in _edge_cache:
        ips = doh_resolve(host, timeout=timeout)
        if not ips:
            raise RuntimeError(f"DoH returned no A/AAAA records for {host}")
        _edge_cache[host] = ips
    return _edge_cache[host]


# ---------------------------------------------------------------- protocol

class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = H3Connection(self._quic)
        self._req: dict = {}

    def quic_event_received(self, event: QuicEvent):
        for ev in self._http.handle_event(event):
            sid = ev.stream_id
            st = self._req.get(sid)
            if st is None:
                continue
            if isinstance(ev, HeadersReceived):
                for k, v in ev.headers:
                    st["headers"].append((k.decode().lower(), v.decode()))
            elif isinstance(ev, DataReceived):
                st["body"] += ev.data
                if ev.stream_ended and not st["done"].is_set():
                    st["done"].set()

    async def request(self, authority: str, path: str, method: str = "GET",
                      headers: Optional[dict] = None,
                      body: Optional[bytes] = None,
                      timeout: float = 30.0):
        sid = self._quic.get_next_available_stream_id()
        st = {"headers": [], "body": b"", "done": asyncio.Event()}
        self._req[sid] = st
        try:
            h = [(b":method", method.encode()),
                 (b":scheme", b"https"),
                 (b":authority", authority.encode()),
                 (b":path", path.encode())]
            if headers:
                for k, v in headers.items():
                    h.append((k.lower().encode(), str(v).encode()))
            # NOTE: never force content-length on H3 POST to Rails hosts —
            # Cloudflare re-chunks the body and Rails 400s. Only add when asked.
            self._http.send_headers(stream_id=sid, headers=h,
                                    end_stream=body is None)
            if body:
                self._http.send_data(stream_id=sid, data=body, end_stream=True)
            self.transmit()
            await asyncio.wait_for(st["done"].wait(), timeout=timeout)
        finally:
            self._req.pop(sid, None)
        return st["headers"], st["body"]


# ---------------------------------------------------------------- response

def _decompress(raw: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if "br" in enc:
            import brotli
            return brotli.decompress(raw)
        if "gzip" in enc:
            return gzip.decompress(raw)
        if "deflate" in enc:
            import zlib
            return zlib.decompress(raw)
    except Exception:
        pass
    return raw


@dataclass
class H3Response:
    status: int
    headers_multi: list = field(default_factory=list)  # ALL pairs, in order
    body: bytes = b""
    elapsed: float = 0.0
    edge_ip: str = ""

    @property
    def headers(self) -> dict:
        """First-wins dict view (convenience; use get_all for multi-values)."""
        d = {}
        for k, v in self.headers_multi:
            if not k.startswith(":") and k not in d:
                d[k] = v
        return d

    def get_all(self, name: str) -> list:
        """Every value for a header name (e.g. all set-cookie)."""
        n = name.lower()
        return [v for k, v in self.headers_multi if k == n]

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="replace")


# ---------------------------------------------------------------- session

class H3Session:
    """Persistent HTTP/3 session: one QUIC connection, many multiplexed streams."""

    def __init__(self, host: str, timeout: float = 30.0, retries: int = 2,
                 capture_dir: Optional[str] = None):
        self.host = host
        self.timeout = timeout
        self.retries = retries
        self.capture_dir = capture_dir
        self._proto = None
        self._cm = None
        self._edge_ip = ""

    async def __aenter__(self):
        ips = discover_edge_ips(self.host)
        last_err = None
        for ip in ips:
            try:
                cfg = QuicConfiguration(
                    is_client=True, alpn_protocols=H3_ALPN,
                    verify_mode=ssl.CERT_REQUIRED, cafile=certifi.where(),
                    server_name=self.host)
                self._cm = connect(ip, 443, configuration=cfg,
                                   create_protocol=H3ClientProtocol,
                                   wait_connected=True)
                self._proto = await self._cm.__aenter__()
                self._edge_ip = ip
                return self
            except Exception as e:  # fail over to next edge IP
                last_err = e
        raise RuntimeError(f"H3 connect failed for {self.host}: {last_err}")

    async def __aexit__(self, *a):
        if self._cm:
            await self._cm.__aexit__(*a)
        self._proto, self._cm = None, None

    async def request(self, path: str, method: str = "GET",
                      headers: Optional[dict] = None,
                      body: Optional[bytes] = None) -> H3Response:
        h = {"user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/131.0.0.0 Safari/537.36"),
             "accept": "*/*",
             "accept-encoding": "gzip, br"}
        if headers:
            h.update(headers)
        last_err = None
        for attempt in range(self.retries + 1):
            t0 = time.time()
            try:
                pairs, raw = await self._proto.request(
                    self.host, path, method, h, body, timeout=self.timeout)
                status = 0
                for k, v in pairs:
                    if k == ":status":
                        status = int(v)
                        break
                enc = ""
                for k, v in pairs:
                    if k == "content-encoding":
                        enc = v
                        break
                body_dec = _decompress(raw, enc)
                resp = H3Response(status=status, headers_multi=pairs,
                                  body=body_dec, elapsed=time.time() - t0,
                                  edge_ip=self._edge_ip)
                if self.capture_dir:
                    self._capture(method, path, h, body, resp)
                return resp
            except Exception as e:
                last_err = e
                await asyncio.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"H3 request {method} {path} failed: {last_err}")

    async def get(self, path: str, **kw) -> H3Response:
        return await self.request(path, "GET", **kw)

    async def post(self, path: str, body: bytes = b"",
                   headers: Optional[dict] = None) -> H3Response:
        h = {"content-type": "application/x-www-form-urlencoded"}
        if headers:
            h.update(headers)
        return await self.request(path, "POST", headers=h, body=body)

    def _capture(self, method, path, req_h, req_body, resp: H3Response):
        os.makedirs(self.capture_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        safe = "".join(c if c.isalnum() else "_" for c in path)[:40]
        fp = os.path.join(self.capture_dir, f"{ts}_{method}_{safe}.txt")
        with open(fp, "w") as f:
            f.write(f"===== {method} https://{self.host}{path} "
                    f"(edge {resp.edge_ip}, {resp.elapsed:.2f}s) =====\n")
            f.write("-- request headers --\n")
            for k, v in req_h.items():
                f.write(f"{k}: {v}\n")
            if req_body:
                f.write(f"-- request body ({len(req_body)}b) --\n")
                f.write(req_body[:2000].decode("utf-8", errors="replace") + "\n")
            f.write(f"-- response: HTTP {resp.status} --\n")
            for k, v in resp.headers_multi:
                if k == "set-cookie":
                    v = v[:120] + ("..." if len(v) > 120 else "")
                f.write(f"{k}: {v}\n")
            f.write(f"-- body ({len(resp.body)}b) --\n")
            f.write(resp.text()[:4000] + "\n")


# ---------------------------------------------------------------- one-shot API (backward compatible)

async def fetch(host: str, path: str, method: str = "GET",
                extra_headers: Optional[dict] = None,
                body: Optional[bytes] = None,
                ip: Optional[str] = None):
    """One-shot HTTP/3 request. Returns (status, headers_dict, raw_body)."""
    async with H3Session(host) as s:
        r = await s.request(path, method, headers=extra_headers, body=body)
    return r.status, r.headers, r.body


async def get_text(host: str, path: str, method: str = "GET",
                   extra_headers: Optional[dict] = None,
                   body: Optional[bytes] = None,
                   ip: Optional[str] = None):
    """fetch() + text decode. Returns (status, headers_dict, text)."""
    status, headers, raw = await fetch(host, path, method, extra_headers, body, ip)
    return status, headers, raw.decode("utf-8", errors="replace")


if __name__ == "__main__":
    async def t():
        # hermetic demo of header multi-collection (no network)
        pairs = [(b":status", b"200"), (b"set-cookie", b"a=1"),
                 (b"set-cookie", b"b=2"), (b"content-type", b"text/html")]
        r = H3Response(status=200,
                       headers_multi=[(k.decode(), v.decode()) for k, v in pairs])
        assert r.get_all("set-cookie") == ["a=1", "b=2"], "multi-collect broken"
        assert r.headers["set-cookie"] == "a=1"
        print("hermetic header test: OK")
    asyncio.run(t())
    print("live test: set RAT_H3_LIVE=1 to fetch via QUIC")
    if os.environ.get("RAT_H3_LIVE") == "1":
        async def live():
            async with H3Session("crypto.com") as s:
                r = await s.get("/robots.txt")
                print(f"status={r.status} edge={r.edge_ip} "
                      f"set-cookies={len(r.get_all('set-cookie'))}")
        asyncio.run(live())
