"""
PHAGE Middleware for Django
============================
Intercepts every request, detects attack patterns,
and sends real threat events to the PHAGE server.

Install: add 'phage_middleware.PhageMiddleware' to MIDDLEWARE in settings.py
"""
import re
import time
import threading
import requests
from collections import defaultdict, deque
from django.conf import settings

PHAGE_SERVER = getattr(settings, 'PHAGE_SERVER', 'http://localhost:8765')

# ── Attack signatures ──────────────────────────────────────────────────────────

SQL_PATTERNS = re.compile(
    r"('|--|;|/\*|\*/|xp_|union\s+select|select\s+.*\s+from|"
    r"insert\s+into|drop\s+table|or\s+1\s*=\s*1|and\s+1\s*=\s*1|"
    r"sleep\s*\(|benchmark\s*\(|char\s*\(|convert\s*\()",
    re.IGNORECASE
)

XSS_PATTERNS = re.compile(
    r"(<script|</script|javascript:|onerror\s*=|onload\s*=|"
    r"onclick\s*=|alert\s*\(|document\.cookie|window\.location|"
    r"<iframe|<img\s.*on\w+=)",
    re.IGNORECASE
)

PATH_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|"
    r"windows/system32|boot\.ini)",
    re.IGNORECASE
)

SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|"
    r"burpsuite|metasploit|nessus|openvas|acunetix)",
    re.IGNORECASE
)

SENSITIVE_PATHS = re.compile(
    r"^/(admin|wp-admin|phpmyadmin|\.env|\.git|config|backup|"
    r"shell|cmd|eval|passwd|shadow|htaccess)",
    re.IGNORECASE
)

# ── Rate limiting tracker ──────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._requests = defaultdict(deque)   # ip → deque of timestamps
        self._login_failures = defaultdict(int)  # ip → count

    def record(self, ip: str) -> int:
        """Returns request count in last 10 seconds."""
        now = time.time()
        with self._lock:
            dq = self._requests[ip]
            dq.append(now)
            while dq and dq[0] < now - 10:
                dq.popleft()
            return len(dq)

    def record_login_failure(self, ip: str) -> int:
        with self._lock:
            self._login_failures[ip] += 1
            return self._login_failures[ip]

    def reset_login(self, ip: str):
        with self._lock:
            self._login_failures[ip] = 0

_rate = RateLimiter()


# ── Middleware ─────────────────────────────────────────────────────────────────

class PhageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        events = self._analyze(request)
        response = self.get_response(request)

        # Detect brute force on login (POST with failed response)
        if request.path.startswith('/login/') and request.method == 'POST':
            if response.status_code == 200:
                body = getattr(response, 'content', b'').decode('utf-8', errors='ignore')
                if 'Invalid' in body:
                    ip = self._get_ip(request)
                    count = _rate.record_login_failure(ip)
                    if count >= 3:
                        events.append(self._event(
                            request, 'brute_force',
                            f'Brute force login: {count} failed attempts from {ip}',
                            severity='HIGH'
                        ))
                else:
                    _rate.reset_login(self._get_ip(request))

        if events:
            self._send(events)

        return response

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _analyze(self, request) -> list:
        events = []
        ip = self._get_ip(request)
        full_url = request.get_full_path()
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Collect all input to inspect
        inputs = [full_url, user_agent]
        for key, val in request.GET.items():
            inputs.append(f"{key}={val}")
        if request.method == 'POST':
            for key, val in request.POST.items():
                if key != 'csrfmiddlewaretoken':
                    inputs.append(f"{key}={val}")
        combined = ' '.join(inputs)

        # SQL Injection
        if SQL_PATTERNS.search(combined):
            events.append(self._event(
                request, 'sql_injection',
                f'SQL injection pattern in: {full_url}',
                severity='CRITICAL'
            ))

        # XSS
        if XSS_PATTERNS.search(combined):
            events.append(self._event(
                request, 'xss',
                f'XSS pattern detected in: {full_url}',
                severity='HIGH'
            ))

        # Path Traversal
        if PATH_TRAVERSAL.search(combined):
            events.append(self._event(
                request, 'path_traversal',
                f'Path traversal attempt: {full_url}',
                severity='HIGH'
            ))

        # Vulnerability Scanner
        if SCANNER_AGENTS.search(user_agent):
            events.append(self._event(
                request, 'scanner',
                f'Security scanner detected: {user_agent[:60]}',
                severity='MEDIUM'
            ))

        # Sensitive path access
        if SENSITIVE_PATHS.search(request.path):
            events.append(self._event(
                request, 'sensitive_path',
                f'Sensitive path accessed: {request.path}',
                severity='MEDIUM'
            ))

        # DDoS / Rate limiting (>20 req in 10s)
        count = _rate.record(ip)
        if count > 20:
            events.append(self._event(
                request, 'ddos',
                f'DDoS pattern: {count} requests in 10s from {ip}',
                severity='CRITICAL'
            ))

        return events

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_ip(self, request) -> str:
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '0.0.0.0')

    def _event(self, request, attack_type: str, description: str, severity: str = 'MEDIUM') -> dict:
        return {
            'type':        attack_type,
            'description': description,
            'severity':    severity,
            'ip':          self._get_ip(request),
            'method':      request.method,
            'path':        request.get_full_path(),
            'user_agent':  request.META.get('HTTP_USER_AGENT', '')[:200],
            'timestamp':   time.time(),
        }

    def _send(self, events: list):
        """Fire-and-forget — sends events to PHAGE without blocking the request."""
        def _post():
            try:
                requests.post(
                    f'{PHAGE_SERVER}/api/ingest',
                    json={'events': events},
                    timeout=2,
                )
            except Exception:
                pass  # PHAGE server not running — silently ignore
        threading.Thread(target=_post, daemon=True).start()
