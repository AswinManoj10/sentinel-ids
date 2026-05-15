"""
Threat Engine
─────────────
Computes a composite risk score and classifies threat level.
"""

import random
from collections import defaultdict

_FAILED_LOGIN_TRACKER: dict[str, int] = defaultdict(int)

_SUSPICIOUS_USERS = {
    "root", "admin", "administrator", "test", "guest",
    "oracle", "postgres", "mysql", "ubuntu", "pi",
}

_ATTACK_ORIGINS = [
    "Moscow, Russia",
    "Unknown VPN Tunnel",
    "Dark Web Exit Node",
    "Anonymous Proxy — TOR",
    "Beijing, China",
    "Lagos, Nigeria",
    "Bogotá, Colombia",
    "Sao Paulo, Brazil",
    "Tehran, Iran",
    "Dnipro, Ukraine",
    "Seoul, South Korea",
    "Singapore (Anonymized)",
]

_LOCAL_ORIGINS = [
    "Local Network",
    "Corporate Intranet",
    "Localhost",
]


class ThreatEngine:

    def compute_risk(
        self,
        username: str,
        ip: str,
        is_valid: bool,
        ml_score: float,
    ) -> int:
        """Returns risk score 0-100."""
        score = 0

        # Failed login history
        key = f"{username}:{ip}"
        if not is_valid:
            _FAILED_LOGIN_TRACKER[key] += 1

        fails = _FAILED_LOGIN_TRACKER.get(key, 0)
        score += min(fails * 15, 45)

        # Suspicious username
        if username.lower() in _SUSPICIOUS_USERS:
            score += 20

        # ML anomaly contribution
        score += int(ml_score * 35)

        # Randomised intelligence noise (±5)
        score += random.randint(-5, 5)

        # Valid credential with anomaly pattern
        if is_valid and ml_score > 0.6:
            score += 15

        return min(max(score, 5), 100)

    def classify_threat(self, risk_score: int) -> str:
        if risk_score >= 75:
            return "CRITICAL"
        if risk_score >= 50:
            return "HIGH"
        if risk_score >= 25:
            return "MEDIUM"
        return "LOW"

    def get_attack_origin(self, ip: str) -> str:
        if ip in ("127.0.0.1", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
            return random.choice(_LOCAL_ORIGINS)
        return random.choice(_ATTACK_ORIGINS)
