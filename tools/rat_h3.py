#!/usr/bin/env python3
"""
rat_h3.py — HTTP/3 client for crypto.com hunting (rebuilt 2026-10-11).
Bypasses Indonesia Kominfo TCP-only middlebox via QUIC/UDP 443 direct to CF edge.

Usage:
  from rat_h3 import fetch, get_text
  status, headers, body = await fetch("crypto.com", "/robots.txt")
  text = await get_text("crypto.com", "/robots.txt")
"""
import asyncio
import ssl
from typing import Optional
from urllib.parse import urlencode

import certifi
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

CF_EDGE_IPS = ["CF_EDGE_IP_1", "CF_EDGE_IP_2"]


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._http = H3Connection(self._quic)
        self._req = {}

    def quic_event_received(self, event: QuicEvent):
        for ev in self._http.handle_event(event):
            sid = ev.stream_id
            if sid not in self._req:
                continue
            st = self._req[sid]
            if isinstance(ev, HeadersReceived):
                for k, v in ev.headers:
                    lk = k.decode().lower()
                    st["headers"][lk] = v.decode()
            elif isinstance(ev, DataReceived):
                st["body"] += ev.data
                if ev.stream_ended:
                    st["done"].set()

    async def request(self, authority: str, path: str, method: str = "GET",
                      headers: Optional[dict] = None, body: Optional[bytes] = None):
        sid = self._quic.get_next_available_stream_id()
        st = {"headers": {}, "body": b"", "done": asyncio.Event()}
        self._req[sid] = st

        h = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ]
        if headers:
            for k, v in headers.items():
                h.append((k.lower().encode(), v.encode()))
        if body and not any(k.lower() == b"content-length" for k, _ in h):
            h.append((b"content-length", str(len(body)).encode()))

        self._http.send_headers(stream_id=sid, headers=h, end_stream=body is None)
        if body:
            self._http.send_data(stream_id=sid, data=body, end_stream=True)
        self.transmit()

        await asyncio.wait_for(st["done"].wait(), timeout=30)
        status = 0
        for k, v in h:
            pass
        status = int(st["headers"].get(":status", 0))
        # pop pseudo-header out of the dict users see
        hdrs = {k: v for k, v in st["headers"].items() if not k.startswith(":")}
        return status, hdrs, st["body"]


async def fetch(host: str, path: str, method: str = "GET",
                extra_headers: Optional[dict] = None,
                body: Optional[bytes] = None,
                ip: Optional[str] = None):
    """One-shot HTTP/3 request. Returns (status, headers_dict, raw_body)."""
    if ip is None:
        ip = CF_EDGE_IPS[0]
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                            verify_mode=ssl.CERT_REQUIRED,
                            cafile=certifi.where(),
                            server_name=host)
    cfg.quic_logger = None

    async with connect(ip, 443, configuration=cfg,
                       create_protocol=H3ClientProtocol,
                       wait_connected=True) as proto:
        h = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Safari/537.36",
             "accept": "*/*",
             "accept-encoding": "gzip"}
        if extra_headers:
            h.update(extra_headers)
        return await proto.request(host, path, method, h, body)


async def get_text(host: str, path: str, method: str = "GET",
                   extra_headers: Optional[dict] = None,
                   body: Optional[bytes] = None,
                   ip: Optional[str] = None):
    """fetch() + auto-decompress → text."""
    import gzip as _g
    status, headers, raw = await fetch(host, path, method, extra_headers, body, ip)
    if "gzip" in headers.get("content-encoding", ""):
        try:
            raw = _g.decompress(raw)
        except Exception:
            pass
    return status, headers, raw.decode("utf-8", errors="replace")


if __name__ == "__main__":
    async def t():
        s, h, b = await get_text("crypto.com", "/robots.txt")
        print(f"status={s} len={len(b)}")
        print(b[:300])
    asyncio.run(t())
