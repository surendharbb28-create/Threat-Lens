"""
ThreatLens Scanning Engine
Performs file and URL threat analysis using multiple detection techniques.
"""
import os
import re
import math
import json
import hashlib
import mimetypes
from datetime import datetime
from urllib.parse import urlparse

# ── Threat Intelligence Signatures ──────────────────────────────────────────

MALWARE_PATTERNS = [
    (r'eval\s*\(\s*base64_decode', 'PHP webshell - base64 eval'),
    (r'exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', 'Remote code execution via user input'),
    (r'system\s*\(\s*\$_(GET|POST|REQUEST)', 'OS command injection'),
    (r'<script[^>]*>.*?document\.cookie', 'Cookie theft script'),
    (r'\.exe[\x00]', 'Null-byte executable injection'),
    (r'cmd\.exe|powershell\.exe|/bin/sh|/bin/bash', 'Shell command reference'),
    (r'EICAR-STANDARD-ANTIVIRUS-TEST-FILE', 'EICAR test signature'),
    (r'CreateObject\s*\(\s*["\']WScript\.Shell', 'WScript shell object'),
    (r'Scripting\.FileSystemObject', 'Filesystem access object'),
    (r'meterpreter|mimikatz|cobalt.?strike', 'Known exploit tool signature'),
    (r'<iframe[^>]+src=["\']javascript:', 'JavaScript iframe injection'),
    (r'document\.write\s*\(\s*unescape\s*\(', 'Obfuscated script injection'),
    (r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', 'Hex-encoded payload'),
]

SUSPICIOUS_EXTENSIONS = {
    '.exe': 'Windows executable',
    '.dll': 'Dynamic link library',
    '.bat': 'Batch script',
    '.cmd': 'Command script',
    '.ps1': 'PowerShell script',
    '.vbs': 'VBScript',
    '.js':  'JavaScript (standalone)',
    '.jar': 'Java archive',
    '.scr': 'Screen saver / executable',
    '.hta': 'HTML Application',
    '.pif': 'Program information file',
    '.com': 'DOS executable',
}

SAFE_EXTENSIONS = {'.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
                   '.txt', '.csv', '.png', '.jpg', '.jpeg', '.gif', '.webp',
                   '.mp4', '.mp3', '.zip', '.tar', '.gz'}

MALICIOUS_URL_PATTERNS = [
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Direct IP address URL'),
    (r'(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.link)', 'URL shortener'),
    (r'(\.ru|\.cn|\.tk|\.ml|\.ga|\.cf|\.gq)/.*\.(exe|zip|rar|bat|ps1)', 'Suspicious TLD with executable'),
    (r'@.*\.', 'URL contains @ (potential redirect)'),
    (r'[a-z0-9]{30,}\.', 'Unusually long subdomain (DGA pattern)'),
    (r'(paypal|apple|google|microsoft|amazon)[a-z0-9\-]*\.(xyz|top|club|icu)', 'Brand impersonation'),
    (r'(login|signin|account|verify|secure)[a-z0-9\-]*\.(xyz|top|club|icu|tk)', 'Phishing keyword + suspicious TLD'),
    (r'javascript:', 'JavaScript protocol'),
    (r'data:', 'Data URI scheme'),
    (r'vbscript:', 'VBScript protocol'),
    (r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}', 'Heavy URL encoding (obfuscation)'),
    (r'(admin|wp-admin|phpMyAdmin|\.env|config\.php)', 'Sensitive path exposure'),
]

PHISHING_KEYWORDS = [
    'verify your account', 'confirm your identity', 'your account has been suspended',
    'click here immediately', 'update payment', 'unusual activity detected',
    'your password will expire', 'action required', 'account verification needed',
]

# ── File Scanner ──────────────────────────────────────────────────────────────

def scan_file(file_obj, filename):
    """
    Analyse an uploaded file for threats.
    Returns a structured scan result dict.
    """
    findings = []
    risk_score = 0
    content_sample = b""

    # Read file content
    file_obj.seek(0)
    raw = file_obj.read()
    file_size = len(raw)

    # Hash
    md5 = hashlib.md5(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()

    # Extension check
    ext = os.path.splitext(filename)[1].lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        findings.append({
            "type": "SUSPICIOUS_EXTENSION",
            "severity": "HIGH",
            "detail": f"File extension '{ext}' — {SUSPICIOUS_EXTENSIONS[ext]}",
        })
        risk_score += 40

    # MIME type
    mime, _ = mimetypes.guess_type(filename)
    detected_mime = _detect_mime(raw)

    if mime and detected_mime and mime != detected_mime:
        findings.append({
            "type": "MIME_MISMATCH",
            "severity": "HIGH",
            "detail": f"Extension suggests '{mime}' but content looks like '{detected_mime}'",
        })
        risk_score += 35

    # Entropy (packed/encrypted content)
    entropy = _calc_entropy(raw[:65536])
    if entropy > 7.5:
        findings.append({
            "type": "HIGH_ENTROPY",
            "severity": "MEDIUM",
            "detail": f"Content entropy {entropy:.2f}/8.0 — may be packed, encrypted, or obfuscated",
        })
        risk_score += 20

    # Pattern matching on text content
    try:
        text = raw.decode('utf-8', errors='replace')
        for pattern, desc in MALWARE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                findings.append({
                    "type": "MALWARE_SIGNATURE",
                    "severity": "CRITICAL",
                    "detail": desc,
                })
                risk_score += 60

        # Phishing keywords in documents
        text_lower = text.lower()
        for kw in PHISHING_KEYWORDS:
            if kw in text_lower:
                findings.append({
                    "type": "PHISHING_KEYWORD",
                    "severity": "MEDIUM",
                    "detail": f"Phishing-associated phrase detected: '{kw}'",
                })
                risk_score += 15
    except Exception:
        pass

    # Embedded executable check
    if b'MZ' in raw and ext not in ('.exe', '.dll', '.com'):
        findings.append({
            "type": "EMBEDDED_EXECUTABLE",
            "severity": "CRITICAL",
            "detail": "MZ header (Windows PE executable) found inside non-executable file",
        })
        risk_score += 70

    # Macro check in Office files
    if ext in ('.doc', '.xls', '.ppt') and b'VBA' in raw:
        findings.append({
            "type": "MACRO_DETECTED",
            "severity": "HIGH",
            "detail": "VBA macro code found in Office document",
        })
        risk_score += 45

    risk_score = min(risk_score, 100)
    threat_level = _score_to_level(risk_score)

    return {
        "scan_type": "file",
        "target": filename,
        "file_size": file_size,
        "file_size_human": _human_size(file_size),
        "md5": md5,
        "sha256": sha256,
        "entropy": round(entropy, 2),
        "mime_type": mime or detected_mime or "unknown",
        "risk_score": risk_score,
        "threat_level": threat_level,
        "findings": findings,
        "findings_count": len(findings),
        "summary": _build_summary("file", filename, threat_level, findings),
        "created_at": datetime.utcnow(),
        "scan_duration_ms": 0,  # will be set by view
    }


# ── URL Scanner ───────────────────────────────────────────────────────────────

def scan_url(url):
    """
    Analyse a URL for threats.
    Returns a structured scan result dict.
    """
    findings = []
    risk_score = 0

    # Normalise
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "Invalid URL format"}

    domain = parsed.netloc.lower()
    path = parsed.path
    full_url = url

    # Protocol check
    if parsed.scheme == 'http':
        findings.append({
            "type": "INSECURE_PROTOCOL",
            "severity": "LOW",
            "detail": "URL uses HTTP (unencrypted) instead of HTTPS",
        })
        risk_score += 10

    # URL length
    if len(url) > 200:
        findings.append({
            "type": "LONG_URL",
            "severity": "LOW",
            "detail": f"Unusually long URL ({len(url)} chars) — common obfuscation technique",
        })
        risk_score += 15

    # Subdomain depth
    subdomain_parts = domain.split('.')
    if len(subdomain_parts) > 5:
        findings.append({
            "type": "DEEP_SUBDOMAIN",
            "severity": "MEDIUM",
            "detail": f"Excessive subdomain depth ({len(subdomain_parts)} levels) — typosquatting indicator",
        })
        risk_score += 25

    # Pattern matching
    for pattern, desc in MALICIOUS_URL_PATTERNS:
        if re.search(pattern, full_url, re.IGNORECASE):
            sev = "HIGH" if "phishing" in desc.lower() or "impersonation" in desc.lower() else "MEDIUM"
            findings.append({
                "type": "SUSPICIOUS_URL_PATTERN",
                "severity": sev,
                "detail": desc,
            })
            risk_score += 30 if sev == "HIGH" else 20

    # Homoglyph / typosquatting check
    homoglyph = _check_homoglyph(domain)
    if homoglyph:
        findings.append({
            "type": "HOMOGLYPH_ATTACK",
            "severity": "HIGH",
            "detail": f"Domain '{domain}' resembles '{homoglyph}' — possible homoglyph/typosquatting attack",
        })
        risk_score += 50

    # Suspicious file in path
    if re.search(r'\.(exe|bat|ps1|vbs|jar|scr|hta)(\?|$)', path, re.IGNORECASE):
        findings.append({
            "type": "EXECUTABLE_IN_PATH",
            "severity": "HIGH",
            "detail": "URL path points to an executable file type",
        })
        risk_score += 40

    # Query string injection
    if re.search(r'[<>\'";]|--|\bOR\b|\bAND\b|\bUNION\b', parsed.query, re.IGNORECASE):
        findings.append({
            "type": "INJECTION_IN_QUERY",
            "severity": "HIGH",
            "detail": "Query string contains potential SQL/XSS injection characters",
        })
        risk_score += 45

    # Domain entropy (DGA detection)
    d_entropy = _calc_entropy(domain.split('.')[0].encode())
    if d_entropy > 3.8:
        findings.append({
            "type": "HIGH_DOMAIN_ENTROPY",
            "severity": "MEDIUM",
            "detail": f"Domain entropy {d_entropy:.2f} — possible Domain Generation Algorithm (DGA)",
        })
        risk_score += 20

    risk_score = min(risk_score, 100)
    threat_level = _score_to_level(risk_score)

    return {
        "scan_type": "url",
        "target": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "path": path,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "findings": findings,
        "findings_count": len(findings),
        "domain_entropy": round(d_entropy, 2),
        "url_length": len(url),
        "summary": _build_summary("url", url, threat_level, findings),
        "created_at": datetime.utcnow(),
        "scan_duration_ms": 0,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _detect_mime(raw: bytes) -> str:
    sigs = {
        b'\x50\x4b\x03\x04': 'application/zip',
        b'\x4d\x5a': 'application/x-msdownload',
        b'\x7f\x45\x4c\x46': 'application/x-elf',
        b'\x89PNG': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'%PDF': 'application/pdf',
        b'PK': 'application/zip',
        b'Rar!': 'application/x-rar',
    }
    for sig, mime in sigs.items():
        if raw.startswith(sig):
            return mime
    return ''


KNOWN_DOMAINS = [
    'google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal',
    'netflix', 'twitter', 'instagram', 'linkedin', 'github',
]

def _check_homoglyph(domain: str) -> str:
    homoglyphs = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g'}
    clean = domain.split('.')[0]
    normalized = ''.join(homoglyphs.get(c, c) for c in clean)
    for legit in KNOWN_DOMAINS:
        if normalized != legit and _levenshtein(normalized, legit) <= 2 and len(clean) >= len(legit) - 1:
            return f"{legit}.com"
    return ''


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            dp[j] = prev[j - 1] if a[i - 1] == b[j - 1] else 1 + min(prev[j], dp[j - 1], prev[j - 1])
    return dp[n]


def _score_to_level(score: int) -> str:
    if score == 0:
        return "CLEAN"
    elif score < 20:
        return "LOW"
    elif score < 45:
        return "MEDIUM"
    elif score < 70:
        return "HIGH"
    else:
        return "CRITICAL"


def _human_size(n: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _build_summary(scan_type: str, target: str, level: str, findings: list) -> str:
    count = len(findings)
    critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')

    if level == "CLEAN":
        return f"No threats detected. The {scan_type} appears safe."
    elif level == "LOW":
        return f"Minor indicators found ({count} issue(s)). Low risk."
    elif level == "MEDIUM":
        return f"{count} suspicious indicator(s) found. Exercise caution."
    elif level == "HIGH":
        return f"{count} threat(s) detected ({high} high severity). Potentially dangerous."
    else:
        return f"CRITICAL THREAT: {critical} critical + {high} high severity findings. Do not proceed."
