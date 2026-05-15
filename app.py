"""SENTINEL IDS v4 — Dashboard-first, no login required"""
import os, json, time, random
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   redirect, Response, send_from_directory)
from model.anomaly_detector import AnomalyDetector
from model.preprocess import FeatureExtractor
from security.threat_engine import ThreatEngine
from security.logger import SecurityLogger
from security.camera import CameraCapture
from security.voice_alert import VoiceAlert
from notifications.notifier import MobileNotifier

app = Flask(__name__)
app.secret_key = "sentinel-open-v4"

detector  = AnomalyDetector()
extractor = FeatureExtractor()
engine    = ThreatEngine()
logger    = SecurityLogger()
camera    = CameraCapture()
voice     = VoiceAlert()
notifier  = MobileNotifier()

DEMO_USERS     = {"demo": "Demo@2026", "guest": "Guest#123"}
HONEYPOT_USERS = {"admin": "Admin@2026", "sysop": "Sysop#123"}
DEMO_MAX       = 3

def _process(username, password, ip, ua, source="direct"):
    ts = datetime.now()
    feat = extractor.extract(username, password, ip, ua, ts)
    ml_score, ml_label = detector.predict(feat)
    is_valid = DEMO_USERS.get(username) == password and source == "demo"
    risk   = engine.compute_risk(username, ip, is_valid, ml_score)
    origin = engine.get_attack_origin(ip)
    threat = engine.classify_threat(risk)
    event  = {"timestamp": ts.isoformat(), "username": username, "ip": ip,
              "source": source, "valid": is_valid, "risk_score": risk,
              "ml_score": round(float(ml_score), 3), "ml_label": ml_label,
              "threat": threat, "origin": origin, "ua": ua, "snapshot": None}
    logger.log(event)
    detector.update(feat)
    return event, is_valid, risk, threat, origin, ml_score, ml_label

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/analytics")
def analytics():
    return render_template("analytics.html")

@app.route("/alert")
def alert():
    return render_template("alert.html")

@app.route("/portal")
def portal():
    return render_template("decoy.html")

# ── Demo login (max 3 attempts, always captures) ──────────────────────────────
@app.route("/api/demo-login", methods=["POST"])
def demo_login():
    d = request.get_json()
    u = d.get("username", "").strip()
    p = d.get("password", "").strip()
    attempt = int(d.get("attempt", 1))
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    event, valid, risk, threat, origin, ml_score, ml_label = _process(u, p, ip, ua, "demo")
    if valid:
        return jsonify({"status": "success", "username": u, "risk": risk, "threat": threat})
    snap = camera.capture(u, risk)
    if snap:
        logger.update_last_snapshot(snap)
    locked = attempt >= DEMO_MAX
    if locked:
        voice.warn_async()
    return jsonify({
        "status": "fail", "locked": locked, "attempt": attempt,
        "risk": risk, "threat": threat, "origin": origin,
        "ml_label": ml_label, "ml_score": round(float(ml_score) * 100, 1),
        "snapshot": snap, "username": u
    })

# ── Honeypot portal ───────────────────────────────────────────────────────────
@app.route("/portal/login", methods=["POST"])
def portal_login():
    d = request.get_json()
    u = d.get("username", "unknown").strip()
    p = d.get("password", "").strip()
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    event, _, risk, threat, origin, ml_score, ml_label = _process(u, p, ip, ua, "decoy")
    is_valid = HONEYPOT_USERS.get(u) == p
    snap = camera.capture(u, risk)
    if snap:
        logger.update_last_snapshot(snap)
    if is_valid:
        return jsonify({
            "status": "success", "username": u,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    voice.warn_async()
    notifier.send(f"[HONEYPOT] {u}", threat, risk, origin)
    return jsonify({
        "status": "threat", "redirect": "/alert",
        "risk_score": risk, "ml_score": round(float(ml_score) * 100, 1),
        "ml_label": ml_label, "threat": threat, "origin": origin,
        "username": u, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "snapshot": snap, "source": "HONEYPOT PORTAL"
    })

# ── Simulate attack ───────────────────────────────────────────────────────────
@app.route("/api/simulate", methods=["POST"])
def simulate():
    u   = random.choice(["admin","root","test","oracle","sa","pi","postgres","mysql"])
    ip  = random.choice(["185.220.101.45","94.102.49.180","45.33.32.156","92.118.160.10"])
    pwd = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789!@#", k=9))
    event, _, risk, threat, origin, ml_score, ml_label = _process(u, pwd, ip, "python-requests/2.28", "simulated")
    snap = camera.capture(u, risk)
    if snap:
        logger.update_last_snapshot(snap)
    return jsonify({"ok": True, "username": u, "ip": ip, "risk": risk,
                    "threat": threat, "origin": origin, "snapshot": snap})

# ── Delete snapshot ───────────────────────────────────────────────────────────
@app.route("/api/snapshots/<path:filename>", methods=["DELETE"])
def delete_snapshot(filename):
    safe = os.path.basename(filename)
    stem = safe.rsplit(".", 1)[0]
    for ext in [".jpg", ".png", ".svg", ".json"]:
        fp = os.path.join("outputs", stem + ext)
        if os.path.exists(fp):
            try: os.remove(fp)
            except: pass
    return jsonify({"deleted": True})

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():     return jsonify(logger.get_stats())

@app.route("/api/recent-events")
def api_recent():    return jsonify(logger.get_recent(40))

@app.route("/api/ml-analytics")
def api_ml():        return jsonify(detector.get_analytics())

@app.route("/api/threat-timeline")
def api_timeline():  return jsonify(logger.get_timeline())

@app.route("/api/cluster-data")
def api_cluster():   return jsonify(detector.get_cluster_data())

@app.route("/api/snapshots")
def api_snaps():     return jsonify(camera.list_snapshots())

@app.route("/outputs/<path:filename>")
def serve_output(filename):
    return send_from_directory("outputs", filename)

# ── Server-Sent Events ────────────────────────────────────────────────────────
@app.route("/api/live")
def api_live():
    def gen():
        seen = set()
        while True:
            events = logger.get_recent(50)
            new = [e for e in events if e.get("timestamp") not in seen]
            if new:
                for e in new:
                    seen.add(e["timestamp"])
                yield f"data: {json.dumps({'events': new, 'stats': logger.get_stats()})}\n\n"
            else:
                yield ": hb\n\n"
            time.sleep(2)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)