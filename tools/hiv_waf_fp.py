#!/usr/bin/env python3
"""
hiv_waf_fp.py — WAF Fingerprinter & Bypass Selector

HIV Analogy:
    Like HIV that first maps the immune landscape before replication
    (identifying CD4+ receptors, CCR5/CXCR4 co-receptors, and local
    cytokine concentrations), this tool maps the 'immune defences'
    of a target before attack. Just as HIV selects different tropism
    (T-tropic vs M-tropic strains) based on available co-receptors,
    the bypass selector recommends the right 'tropism' (HTTP/1.1 vs
    HTTP/2 vs HTTP/3, encoding vs timing vs header mutation) for the
    detected WAF phenotype.

Usage:
    python hiv_waf_fp.py --target URL
"""

import argparse
import json
import time
import urllib.request
import urllib.error
import urllib.parse
import sys
import re
import socket
import ssl
from collections import defaultdict


# ---------------------------------------------------------------------------
# WAF Signature Database
# ---------------------------------------------------------------------------
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {
            "server": ["cloudflare"],
            "cf-ray": [".*"],
            "cf-cache-status": [".*"],
        },
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "body_patterns": [
            r"cloudflare",
            r"Attention Required! \| Cloudflare",
            r"Ray ID:",
            r"DDoS protection by Cloudflare",
            r"www\.cloudflare\.com/5xx-error-landing",
        ],
        "status_triggers": {403: 0.9, 503: 0.7, 429: 0.5},
        "bypass_techniques": [
            {"name": "Origin IP Direct", "desc": "Find origin IP via DNS history / Shodan, bypass CDN layer", "success_rate": 0.85},
            {"name": "CF-Connecting-IP Spoof", "desc": "Header: CF-Connecting-IP: 127.0.0.1", "success_rate": 0.35},
            {"name": "HTTP/2 Smuggling", "desc": "H2.TE request smuggling desync", "success_rate": 0.45},
            {"name": "Unicode Normalization", "desc": "Use Ω (U+2126) for 'O', ﬁ (U+FB01) for 'fi'", "success_rate": 0.40},
            {"name": "Chunked Encoding", "desc": "Transfer-Encoding: chunked with payload split", "success_rate": 0.50},
            {"name": "Case Mutation + Comments", "desc": "SeLeCt/**/ instead of SELECT", "success_rate": 0.55},
        ],
        "recommended_protocol": "HTTP/2",
    },
    "Akamai": {
        "headers": {
            "server": ["akamai", "akamaighost"],
            "x-akamai-edgescape": [".*"],
            "x-check-cacheable": [".*"],
            "x-akamai-request-id": [".*"],
        },
        "cookies": ["AkamaiGHost", "ak_bmsc", "bm_sz"],
        "body_patterns": [
            r"Reference #\d+\.\w+\.\d+",
            r"Access Denied",
            r"akamai",
        ],
        "status_triggers": {403: 0.8, 400: 0.6},
        "bypass_techniques": [
            {"name": "X-Forwarded-For Chain", "desc": "X-Forwarded-For: 127.0.0.1, evil", "success_rate": 0.45},
            {"name": "Slow Drip (chunked)", "desc": "Send payload 1 byte/s via chunked transfer", "success_rate": 0.50},
            {"name": "Long URL padding", "desc": "Pad URL with 8192 null bytes before payload", "success_rate": 0.40},
            {"name": "Content-Type switching", "desc": "multipart/form-data boundary confusion", "success_rate": 0.55},
            {"name": "HTTP/1.0 downgrade", "desc": "Use HTTP/1.0 — older inspection paths", "success_rate": 0.35},
            {"name": "Nested encoding", "desc": "Double URL-encode payload chars", "success_rate": 0.60},
        ],
        "recommended_protocol": "HTTP/1.1",
    },
    "Imperva/Incapsula": {
        "headers": {
            "x-iinfo": [".*"],
            "x-cdn": ["Incapsula"],
        },
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
        "body_patterns": [
            r"incapsula incident id",
            r"Incapsula",
            r"Request unsuccessful\. Incapsula incident ID",
        ],
        "status_triggers": {403: 0.9},
        "bypass_techniques": [
            {"name": "Accept-Language mutation", "desc": "Vary Accept-Language header per request", "success_rate": 0.45},
            {"name": "Pipe character injection", "desc": "Use | as space in SQL context", "success_rate": 0.55},
            {"name": "HTTP Parameter Pollution", "desc": "param=good&param=evil (last wins)", "success_rate": 0.50},
            {"name": "ASP.NET HPP", "desc": "param=evil,good (comma-separated arrays)", "success_rate": 0.45},
            {"name": "IP reputation rotation", "desc": "Rotate source IPs via proxy pool", "success_rate": 0.70},
            {"name": "Browser fingerprint mimicry", "desc": "Full browser headers + real TLS fingerprint", "success_rate": 0.65},
        ],
        "recommended_protocol": "HTTP/2",
    },
    "AWS WAF": {
        "headers": {
            "x-amzn-requestid": [".*"],
            "x-amz-cf-id": [".*"],
            "x-amz-cf-pop": [".*"],
        },
        "cookies": ["aws-waf-token", "x-amzn-waf-token"],
        "body_patterns": [
            r"AWS WAF",
            r"Request blocked",
            r"\{\"message\":\"Forbidden\"\}",
        ],
        "status_triggers": {403: 0.85, 400: 0.4},
        "bypass_techniques": [
            {"name": "JSON body injection", "desc": "Wrap payload in JSON to bypass body parsers", "success_rate": 0.60},
            {"name": "SSRF via aws.* subdomain", "desc": "Use 169.254.169.254 decimal/hex forms", "success_rate": 0.55},
            {"name": "GraphQL introspection", "desc": "Move payload into GraphQL query field", "success_rate": 0.50},
            {"name": "X-Forwarded-For: 127.0.0.1", "desc": "Trigger IP allowlist bypass", "success_rate": 0.30},
            {"name": "Content-Encoding: gzip", "desc": "Compress payload body — some rules skip", "success_rate": 0.45},
            {"name": "Field name confusion", "desc": "Move payload to unexpected JSON key", "success_rate": 0.55},
        ],
        "recommended_protocol": "HTTP/2",
    },
    "ModSecurity": {
        "headers": {
            "server": ["mod_security", "modsecurity"],
        },
        "cookies": [],
        "body_patterns": [
            r"ModSecurity",
            r"Not Acceptable!",
            r"This error was generated by Mod_Security",
            r"406 Not Acceptable",
            r"mod_security",
        ],
        "status_triggers": {403: 0.7, 406: 0.95, 501: 0.6},
        "bypass_techniques": [
            {"name": "Paranoia level probe", "desc": "PL1 vs PL4 differences — try low-risk payloads", "success_rate": 0.65},
            {"name": "SQL comment variants", "desc": "/*! 50000 SELECT */ version comments", "success_rate": 0.70},
            {"name": "Whitespace alternatives", "desc": "Tab, newline, form-feed as space", "success_rate": 0.65},
            {"name": "PCRE recursion bypass", "desc": "Trigger PCRE backtracking limits with ReDoS", "success_rate": 0.40},
            {"name": "Chunked encoding", "desc": "Split payload across multiple chunks", "success_rate": 0.60},
            {"name": "Accept-Encoding confusion", "desc": "Send invalid encoding to confuse parser", "success_rate": 0.45},
        ],
        "recommended_protocol": "HTTP/1.1",
    },
    "F5 ASM": {
        "headers": {
            "server": ["BigIP", "F5"],
            "x-cnection": ["close"],
        },
        "cookies": ["TS", "BIGipServer"],
        "body_patterns": [
            r"F5 Networks",
            r"The requested URL was rejected",
            r"Please consult with your administrator",
            r"Your support ID is:",
        ],
        "status_triggers": {200: 0.3, 403: 0.8},
        "bypass_techniques": [
            {"name": "HTTP verb tampering", "desc": "X-HTTP-Method-Override: DELETE", "success_rate": 0.40},
            {"name": "BigIP cookie decode", "desc": "Decode BIGipServer cookie → internal IP", "success_rate": 0.75},
            {"name": "Long payload header", "desc": "Move payload into custom HTTP header", "success_rate": 0.55},
            {"name": "Multipart confusion", "desc": "Nested multipart boundaries with payload", "success_rate": 0.50},
            {"name": "Evasion via OPTIONS", "desc": "OPTIONS preflight leaks policy details", "success_rate": 0.45},
        ],
        "recommended_protocol": "HTTP/1.1",
    },
    "Barracuda": {
        "headers": {
            "server": ["barracuda"],
        },
        "cookies": ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
        "body_patterns": [
            r"Barracuda Networks",
            r"barracuda",
            r"You have been blocked",
        ],
        "status_triggers": {403: 0.75, 200: 0.3},
        "bypass_techniques": [
            {"name": "Referer header injection", "desc": "Move payload to Referer: header", "success_rate": 0.60},
            {"name": "Path confusion", "desc": "/api/..%2fendpoint instead of /api/../endpoint", "success_rate": 0.55},
            {"name": "Unicode path encoding", "desc": "Use %u002f for path separators", "success_rate": 0.50},
        ],
        "recommended_protocol": "HTTP/1.1",
    },
    "Sucuri": {
        "headers": {
            "server": ["sucuri"],
            "x-sucuri-id": [".*"],
            "x-sucuri-cache": [".*"],
        },
        "cookies": ["sucuri_cloudproxy"],
        "body_patterns": [
            r"Sucuri Website Firewall",
            r"Access Denied - Sucuri Website Firewall",
            r"sucuri\.net",
        ],
        "status_triggers": {403: 0.85, 200: 0.3},
        "bypass_techniques": [
            {"name": "WordPress-specific bypass", "desc": "/?p=1 vs /index.php?p=1 route confusion", "success_rate": 0.50},
            {"name": "Whitespace in tag", "desc": "<script > instead of <script>", "success_rate": 0.55},
            {"name": "IP allowlist probe", "desc": "X-Originating-IP: 127.0.0.1 bypass", "success_rate": 0.35},
        ],
        "recommended_protocol": "HTTP/1.1",
    },
    "Fortinet/FortiWeb": {
        "headers": {
            "server": ["fortiweb"],
            "x-waf-event-info": [".*"],
        },
        "cookies": ["FORTIWAFSID"],
        "body_patterns": [
            r"FortiWeb",
            r"Server Unavailable",
            r"FortiGuard",
        ],
        "status_triggers": {403: 0.80, 200: 0.35},
        "bypass_techniques": [
            {"name": "JSON unicode escapes", "desc": "\\u0053elect inside JSON body", "success_rate": 0.60},
            {"name": "Nested encoding", "desc": "Triple URL-encode sensitive chars", "success_rate": 0.55},
            {"name": "Content-Type: text/xml", "desc": "Switch to XML body parsing path", "success_rate": 0.45},
        ],
        "recommended_protocol": "HTTP/2",
    },
}


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------
class WAFDetector:
    """
    HIV Analogy — Viral Tropism Determination:
        HIV must determine cell type (T-cell vs macrophage) and receptor
        availability before committing to an infection pathway. WAFDetector
        performs the same 'tropism analysis' — probing response characteristics
        to determine which 'host' (WAF vendor) is present and which entry
        pathway (bypass) is viable.
    """

    def __init__(self, target: str, timeout: int = 10, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self._parsed = urllib.parse.urlparse(target)

    def _fetch(self, url: str, payload: str = None, method: str = 'GET',
               extra_headers: dict = None) -> dict:
        """Fetch URL and return structured response metadata."""
        result = {
            'url': url, 'status': 0, 'headers': {},
            'cookies': [], 'body': '', 'elapsed': 0, 'error': None,
        }
        try:
            if payload:
                sep = '&' if '?' in url else '?'
                url = url + sep + urllib.parse.urlencode({'q': payload})
            req = urllib.request.Request(url, method=method)
            req.add_header('User-Agent',
                           'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 Chrome/120.0')
            req.add_header('Accept', 'text/html,application/xhtml+xml,*/*;q=0.9')
            if extra_headers:
                for k, v in extra_headers.items():
                    req.add_header(k, v)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            t0 = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=ctx) as resp:
                result['status'] = resp.status
                result['headers'] = dict(resp.headers)
                set_cookie = resp.headers.get_all('Set-Cookie') or []
                result['cookies'] = set_cookie
                result['body'] = resp.read(8192).decode('utf-8', errors='replace')
                result['elapsed'] = time.time() - t0
        except urllib.error.HTTPError as e:
            result['status'] = e.code
            result['headers'] = dict(e.headers) if e.headers else {}
            try:
                result['body'] = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                pass
            result['elapsed'] = 0
        except Exception as ex:
            result['error'] = str(ex)
        return result

    def _probe_waf_trigger(self) -> dict:
        """Send a payload that should trigger any WAF."""
        trigger_payload = "' OR 1=1-- <script>alert(1)</script> ../../../../etc/passwd"
        return self._fetch(self.target, payload=trigger_payload)

    def _analyse_baseline(self) -> dict:
        """Fetch baseline (clean) response."""
        return self._fetch(self.target)

    def _check_timing(self) -> float:
        """Check if WAF introduces latency."""
        times = []
        for _ in range(3):
            r = self._fetch(self.target)
            if r['elapsed'] > 0:
                times.append(r['elapsed'])
            time.sleep(0.2)
        return sum(times) / len(times) if times else 0

    def _match_signatures(self, response: dict) -> dict:
        """Score each WAF vendor against observed response."""
        scores = defaultdict(float)
        headers_lower = {k.lower(): v.lower()
                         for k, v in response['headers'].items()}
        body_lower = response['body'].lower()
        cookie_str = ' '.join(response['cookies']).lower()

        for waf_name, sig in WAF_SIGNATURES.items():
            # Header matching
            for hdr_name, patterns in sig['headers'].items():
                if hdr_name.lower() in headers_lower:
                    val = headers_lower[hdr_name.lower()]
                    for pat in patterns:
                        if re.search(pat, val, re.IGNORECASE):
                            scores[waf_name] += 0.35

            # Cookie matching
            for cookie_name in sig['cookies']:
                if cookie_name.lower() in cookie_str:
                    scores[waf_name] += 0.30

            # Body pattern matching
            for pat in sig['body_patterns']:
                if re.search(pat, response['body'], re.IGNORECASE):
                    scores[waf_name] += 0.25

            # Status code matching
            status = response['status']
            if status in sig['status_triggers']:
                scores[waf_name] += sig['status_triggers'][status] * 0.10

        return dict(scores)

    def fingerprint(self) -> dict:
        """Full fingerprinting pipeline. Returns structured report."""
        print(f"[HIV-WAF-FP] Fingerprinting: {self.target}")
        print("-" * 60)

        # Step 1: Baseline
        print("  [1/4] Baseline request...")
        baseline = self._analyse_baseline()
        if self.verbose:
            print(f"        Status: {baseline['status']} | "
                  f"Elapsed: {baseline['elapsed']:.3f}s")

        # Step 2: Triggered probe
        print("  [2/4] WAF-trigger probe...")
        triggered = self._probe_waf_trigger()
        if self.verbose:
            print(f"        Status: {triggered['status']} | "
                  f"Elapsed: {triggered['elapsed']:.3f}s")

        # Step 3: Average timing
        print("  [3/4] Timing analysis (3 requests)...")
        avg_latency = self._check_timing()

        # Step 4: Score signatures against both baseline and triggered
        print("  [4/4] Signature matching...")
        baseline_scores = self._match_signatures(baseline)
        trigger_scores = self._match_signatures(triggered)

        # Merge scores
        all_wafs = set(list(baseline_scores.keys()) + list(trigger_scores.keys()))
        final_scores = {}
        for w in all_wafs:
            final_scores[w] = (baseline_scores.get(w, 0) +
                               trigger_scores.get(w, 0) * 1.5)  # triggered hits count more

        # Detect status code delta
        status_delta = triggered['status'] != baseline['status']

        # Build report
        detected = [(k, v) for k, v in final_scores.items() if v > 0]
        detected.sort(key=lambda x: -x[1])

        primary_waf = detected[0][0] if detected else "Unknown"
        primary_confidence = detected[0][1] if detected else 0.0

        # Normalise confidence to 0-100
        max_possible = 2.0
        confidence_pct = min(100, int(primary_confidence / max_possible * 100))

        # If no signatures matched but there was a block
        if primary_confidence < 0.1 and triggered['status'] in (403, 406, 503):
            primary_waf = "Generic WAF (unidentified)"
            confidence_pct = 25

        bypass_chain = []
        protocol_rec = "HTTP/1.1"
        if primary_waf in WAF_SIGNATURES:
            techniques = WAF_SIGNATURES[primary_waf]['bypass_techniques']
            bypass_chain = sorted(techniques, key=lambda x: -x['success_rate'])
            protocol_rec = WAF_SIGNATURES[primary_waf]['recommended_protocol']

        report = {
            "target": self.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "waf_detected": primary_waf,
            "confidence_pct": confidence_pct,
            "status_baseline": baseline['status'],
            "status_triggered": triggered['status'],
            "status_delta": status_delta,
            "avg_latency_s": round(avg_latency, 3),
            "response_headers_observed": list(triggered['headers'].keys()),
            "cookies_observed": triggered['cookies'],
            "all_candidates": [
                {"waf": k, "raw_score": round(v, 3)}
                for k, v in detected[:5]
            ],
            "recommended_protocol": protocol_rec,
            "bypass_chain": bypass_chain,
            "notes": self._build_notes(baseline, triggered, avg_latency),
        }
        return report

    def _build_notes(self, baseline: dict, triggered: dict,
                     avg_latency: float) -> list:
        notes = []
        if baseline['status'] == 0:
            notes.append("WARNING: Baseline request failed — check target URL")
        if triggered['status'] in (403, 406):
            notes.append(f"WAF actively blocking (HTTP {triggered['status']})")
        if triggered['status'] == 503:
            notes.append("Rate limiting or DDoS protection active")
        if avg_latency > 0.5:
            notes.append(f"High latency ({avg_latency:.2f}s avg) — CDN likely in path")
        if triggered['status'] == baseline['status']:
            notes.append("No status delta on trigger — WAF may be passive/logging only")
        return notes


# ---------------------------------------------------------------------------
# Report Printer
# ---------------------------------------------------------------------------
def print_report(report: dict, output_file: str = None):
    print("\n" + "=" * 60)
    print("[HIV-WAF-FP] Fingerprint Report")
    print("=" * 60)
    print(f"  Target         : {report['target']}")
    print(f"  WAF Detected   : {report['waf_detected']}")
    print(f"  Confidence     : {report['confidence_pct']}%")
    print(f"  Baseline Status: HTTP {report['status_baseline']}")
    print(f"  Triggered Status: HTTP {report['status_triggered']}")
    print(f"  Protocol Rec.  : {report['recommended_protocol']}")
    print(f"  Avg Latency    : {report['avg_latency_s']}s")

    if report.get('notes'):
        print("\n  Notes:")
        for note in report['notes']:
            print(f"    ⚠  {note}")

    if report['bypass_chain']:
        print(f"\n  Bypass Chain for {report['waf_detected']}:")
        print(f"  {'#':<3} {'Success Rate':<14} {'Technique':<30} Description")
        print("  " + "-" * 70)
        for i, bp in enumerate(report['bypass_chain'], 1):
            print(f"  {i:<3} {int(bp['success_rate']*100):>8}%      "
                  f"{bp['name']:<30} {bp['desc']}")

    if report['all_candidates']:
        print("\n  All Candidates (scored):")
        for c in report['all_candidates']:
            print(f"    {c['waf']:<30} score={c['raw_score']}")

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n  Full JSON report → {output_file}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='HIV WAF Fingerprinter — Detect WAF type and select bypass chain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--target', required=True, help='Target URL to fingerprint')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--output', default='hiv_waf_report.json',
                        help='Output JSON report file (default: hiv_waf_report.json)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output during probing')
    parser.add_argument('--list-wafs', action='store_true',
                        help='List all supported WAF signatures and exit')
    args = parser.parse_args()

    if args.list_wafs:
        print(f"[Supported WAF Signatures — {len(WAF_SIGNATURES)} total]")
        for name, sig in WAF_SIGNATURES.items():
            techs = len(sig['bypass_techniques'])
            print(f"  {name:<25} {techs} bypass techniques | "
                  f"proto: {sig['recommended_protocol']}")
        sys.exit(0)

    detector = WAFDetector(args.target, timeout=args.timeout,
                           verbose=args.verbose)
    report = detector.fingerprint()
    print_report(report, output_file=args.output)


if __name__ == '__main__':
    main()
