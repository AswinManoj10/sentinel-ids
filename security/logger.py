"""Security Logger — JSON-lines + CSV storage with live-stream support."""

import json, os, csv
from datetime import datetime
from collections import defaultdict

LOG_FILE = "outputs/threat_logs.jsonl"
CSV_FILE = "outputs/suspicious_logins.csv"
os.makedirs("outputs", exist_ok=True)


class SecurityLogger:

    def __init__(self):
        self._events: list[dict] = []
        self._load_existing()

    def _load_existing(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                for line in f:
                    try:
                        self._events.append(json.loads(line.strip()))
                    except Exception:
                        pass

    def log(self, event: dict):
        self._events.append(event)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
        self._write_csv(event)

    def update_last_snapshot(self, snap: str):
        if self._events:
            self._events[-1]["snapshot"] = snap

    def _write_csv(self, event: dict):
        write_header = not os.path.exists(CSV_FILE)
        with open(CSV_FILE, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["timestamp","username","ip","source","valid",
                             "risk_score","ml_score","threat","origin","snapshot"])
            w.writerow([
                event.get("timestamp"), event.get("username"),
                event.get("ip"),        event.get("source","admin"),
                event.get("valid"),     event.get("risk_score"),
                event.get("ml_score"),  event.get("threat"),
                event.get("origin"),    event.get("snapshot",""),
            ])

    def get_stats(self) -> dict:
        total    = len(self._events)
        failed   = sum(1 for e in self._events if not e.get("valid"))
        anomalies= sum(1 for e in self._events if e.get("ml_label") == "ANOMALY")
        critical = sum(1 for e in self._events if e.get("threat") == "CRITICAL")
        honeypot = sum(1 for e in self._events if e.get("source") == "decoy")
        simulated= sum(1 for e in self._events if e.get("source") == "simulated")

        threat_dist  = defaultdict(int)
        origin_dist  = defaultdict(int)
        source_dist  = defaultdict(int)
        for e in self._events:
            threat_dist[e.get("threat","LOW")] += 1
            origin_dist[e.get("origin","Unknown")] += 1
            source_dist[e.get("source","admin")] += 1

        top_origins = sorted(origin_dist.items(), key=lambda x: x[1], reverse=True)[:6]

        return {
            "total_events":       total,
            "failed_logins":      failed,
            "anomalies":          anomalies,
            "critical_threats":   critical,
            "honeypot_hits":      honeypot,
            "simulated_attacks":  simulated,
            "success_rate":       round((total - failed) / max(total, 1) * 100, 1),
            "threat_distribution": dict(threat_dist),
            "source_distribution": dict(source_dist),
            "top_origins": [{"origin": o, "count": c} for o, c in top_origins],
        }

    def get_recent(self, n: int = 30) -> list[dict]:
        return list(reversed(self._events[-n:]))

    def get_timeline(self) -> list[dict]:
        from datetime import timedelta
        now     = datetime.now()
        buckets = defaultdict(int)
        for e in self._events:
            try:
                ts = datetime.fromisoformat(e["timestamp"])
                if (now - ts).total_seconds() < 86400:
                    buckets[ts.strftime("%H:00")] += 1
            except Exception:
                pass
        return [{"hour": h, "count": c} for h, c in sorted(buckets.items())]
