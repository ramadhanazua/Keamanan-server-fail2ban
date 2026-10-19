import re
from datetime import datetime

from models.security_event import SecurityEvent
from extensions import db


# ============================================================
# SQL INJECTION
# ============================================================

SQLI_PATTERNS = [

    r"'\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",

    r"'\s*and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",

    r"\bor\s+1\s*=\s*1\b",

    r"\band\s+1\s*=\s*1\b",

    r"\bunion\s+(all\s+)?select\b",

    r"\bselect\s+.+\s+from\b",

    r"\binsert\s+into\b",

    r"\bupdate\s+.+\s+set\b",

    r"\bdelete\s+from\b",

    r"\bdrop\s+(table|database)\b",

    r"--",

    r"/\*",

    r"\*/",

    r";\s*(select|insert|update|delete|drop)\b",
]


# ============================================================
# XSS
# ============================================================

XSS_PATTERNS = [

    r"<script\b",

    r"</script>",

    r"javascript\s*:",

    r"onerror\s*=",

    r"onload\s*=",

    r"onclick\s*=",

    r"onmouseover\s*=",

    r"<iframe\b",

    r"<svg\b",

    r"<img\b[^>]*onerror",

]


# ============================================================
# DETECTOR SQL INJECTION
# ============================================================

def detect_sql_injection(value):

    if not value:
        return False

    value = str(value).lower()

    for pattern in SQLI_PATTERNS:

        if re.search(
            pattern,
            value,
            re.IGNORECASE
        ):
            return True

    return False


def detect_sqli(value):

    return detect_sql_injection(value)


# ============================================================
# DETECTOR XSS
# ============================================================

def detect_xss(value):

    if not value:
        return False

    value = str(value).lower()

    for pattern in XSS_PATTERNS:

        if re.search(
            pattern,
            value,
            re.IGNORECASE
        ):
            return True

    return False


# ============================================================
# DETECTOR LOGIN ATTACK
# ============================================================

def detect_login_attack(username, password):

    return (
        detect_sqli(username)
        or
        detect_sqli(password)
        or
        detect_xss(username)
        or
        detect_xss(password)
    )


# ============================================================
# RISK
# ============================================================

RISK_LEVELS = {

    "Reconnaissance & Service Enumeration": "MEDIUM",

    "Standard Dictionary Attack": "HIGH",

    "Simple Brute Force": "HIGH",

    "SQL Injection": "CRITICAL",

    "Cross-Site Scripting (XSS)": "HIGH",

    "Phishing (Social Engineering)": "HIGH",

    "MITM / ARP Spoofing": "CRITICAL",

    "Denial of Service (DoS)": "HIGH",

    "Privilege Escalation": "CRITICAL",

    "Flask Web Dashboard Login Brute Force": "HIGH",
}


# ============================================================
# CREATE SECURITY EVENT
# ============================================================

def create_event(
    attack_type,
    source_ip="-",
    endpoint="-",
    username="-",
    payload="-",
    action="BLOCKED",
    status="DETECTED",
    file="-",
    process="-",
    syscall="-",
    access="DENIED",
    risk=None
):

    if risk is None:

        risk = RISK_LEVELS.get(
            attack_type,
            "MEDIUM"
        )

    event = SecurityEvent(

        tanggal=datetime.now(),

        username=username,

        ip=source_ip,

        attack_type=attack_type,

        endpoint=endpoint,

        payload=payload,

        file=file,

        process=process,

        syscall=syscall,

        access=access,

        status=status,

        action=action,

        risk=risk
    )

    db.session.add(event)

    db.session.commit()

    return event
