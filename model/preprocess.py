"""
Feature Extractor — converts raw login event → numeric feature vector
for unsupervised anomaly detection.
"""

import hashlib
import math
from datetime import datetime


_SUSPICIOUS_USERS = {
    "root", "admin", "administrator", "test", "guest",
    "oracle", "postgres", "mysql", "ubuntu", "pi", "user",
}

_SUSPICIOUS_PATTERNS = ["'", '"', ";", "--", "/*", "*/", "drop", "select", "union"]


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


class FeatureExtractor:
    """
    Builds a 10-dimensional feature vector per login attempt.

    Features:
      0  hour_sin          — cyclical time-of-day (sine)
      1  hour_cos          — cyclical time-of-day (cosine)
      2  username_len      — length of username
      3  password_len      — length of password
      4  pwd_entropy       — password entropy
      5  username_risk     — 1 if known suspicious username else 0
      6  sql_injection     — 1 if SQL-like pattern detected
      7  ip_octet_var      — variance across IP octets (normalised)
      8  ua_len_norm       — normalised user-agent length
      9  weekend_flag      — 1 if weekend login
    """

    def extract(
        self,
        username: str,
        password: str,
        ip: str,
        user_agent: str,
        timestamp: datetime,
    ) -> list[float]:

        hour       = timestamp.hour
        hour_sin   = math.sin(2 * math.pi * hour / 24)
        hour_cos   = math.cos(2 * math.pi * hour / 24)

        uname_risk = 1.0 if username.lower() in _SUSPICIOUS_USERS else 0.0

        sql_flag = 1.0 if any(p in (username + password).lower() for p in _SUSPICIOUS_PATTERNS) else 0.0

        try:
            octets   = [int(o) for o in ip.split(".")]
            mean_o   = sum(octets) / len(octets)
            var_o    = sum((o - mean_o) ** 2 for o in octets) / len(octets)
            ip_var   = var_o / 16384.0          # normalise to [0,1] approx
        except Exception:
            ip_var   = 0.5

        ua_len_norm  = min(len(user_agent) / 500.0, 1.0)
        weekend_flag = 1.0 if timestamp.weekday() >= 5 else 0.0

        return [
            hour_sin,
            hour_cos,
            min(len(username) / 32.0, 1.0),
            min(len(password) / 64.0, 1.0),
            min(_entropy(password) / 6.0, 1.0),
            uname_risk,
            sql_flag,
            ip_var,
            ua_len_norm,
            weekend_flag,
        ]
