"""
Mobile Notifier — sends Pushover push notification on threat detection.
Set PUSHOVER_USER and PUSHOVER_TOKEN environment variables to enable.
"""

import os
import threading


PUSHOVER_USER  = os.environ.get("PUSHOVER_USER",  "")
PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "")


class MobileNotifier:

    def send(self, username: str, threat: str, risk_score: int, origin: str):
        if not PUSHOVER_USER or not PUSHOVER_TOKEN:
            return   # not configured — skip silently
        threading.Thread(
            target=self._push,
            args=(username, threat, risk_score, origin),
            daemon=True,
        ).start()

    def _push(self, username: str, threat: str, risk_score: int, origin: str):
        try:
            import urllib.request, urllib.parse
            payload = urllib.parse.urlencode({
                "token":    PUSHOVER_TOKEN,
                "user":     PUSHOVER_USER,
                "title":    f"🚨 {threat} THREAT DETECTED",
                "message":  (
                    f"Username : {username}\n"
                    f"Risk     : {risk_score}%\n"
                    f"Threat   : {threat}\n"
                    f"Origin   : {origin}"
                ),
                "priority": 1 if threat == "CRITICAL" else 0,
                "sound":    "siren",
            }).encode()

            req = urllib.request.Request(
                "https://api.pushover.net/1/messages.json",
                data=payload,
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
