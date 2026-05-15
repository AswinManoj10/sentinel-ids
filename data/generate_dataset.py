"""
Synthetic Login Dataset Generator
──────────────────────────────────
Generates realistic login event data for training and evaluation.
Run once: python data/generate_dataset.py
"""

import csv, json, math, random, os
from datetime import datetime, timedelta

random.seed(42)
os.makedirs(os.path.dirname(__file__) + "/../outputs", exist_ok=True)

OUT_CSV  = os.path.join(os.path.dirname(__file__), "login_events.csv")
OUT_JSON = os.path.join(os.path.dirname(__file__), "attack_patterns.json")

# ── Feature vectors ──────────────────────────────────────────────────────────
LEGIT_USERNAMES   = ["alice","bob","charlie","diana","emily","frank","grace","henry"]
ATTACK_USERNAMES  = ["root","admin","administrator","test","oracle","sa","pi","guest",
                     "postgres","mysql","ubuntu","user","manager","support"]
LEGIT_IPS         = [f"10.0.{random.randint(0,10)}.{random.randint(1,254)}" for _ in range(20)]
ATTACK_IPS        = ["185.220.101.45","94.102.49.180","45.33.32.156",
                     "198.20.69.74","92.118.160.10","195.206.105.217",
                     "103.230.143.5","91.108.4.0","5.188.62.140"]
LEGIT_UAS         = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
]
ATTACK_UAS        = [
    "python-requests/2.28.0",
    "curl/7.88.1",
    "Hydra v9.4",
    "sqlmap/1.7",
    "Nikto/2.1.6",
    "",
]

def _entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def _make_feature(uname, pwd, ip, ua, ts, label):
    hour     = ts.hour
    hs       = math.sin(2*math.pi*hour/24)
    hc       = math.cos(2*math.pi*hour/24)
    sus_u    = 1.0 if uname.lower() in ATTACK_USERNAMES else 0.0
    sql_flag = 1.0 if any(p in (uname+pwd).lower() for p in ["'",'"',";","--","select","drop","union"]) else 0.0
    try:
        octs = [int(o) for o in ip.split(".")]
        mean_o = sum(octs)/len(octs)
        var_o  = sum((o-mean_o)**2 for o in octs)/len(octs)
        ip_var = var_o/16384.0
    except: ip_var = 0.5
    ua_len   = min(len(ua)/500.0,1.0)
    weekend  = 1.0 if ts.weekday()>=5 else 0.0
    return [
        round(hs,4), round(hc,4),
        round(min(len(uname)/32,1.0),4),
        round(min(len(pwd)/64,1.0),4),
        round(min(_entropy(pwd)/6,1.0),4),
        sus_u, sql_flag,
        round(ip_var,4), round(ua_len,4), weekend,
        label,
    ]

rows = []
base = datetime(2026,1,1,0,0,0)

# ── Normal logins (700 events) ─────────────────────────────────────────────
for i in range(700):
    ts      = base + timedelta(hours=random.gauss(10,3)+i*0.5)
    uname   = random.choice(LEGIT_USERNAMES)
    pwd     = "".join(random.choices("ABCDEFabcdef0123456789!@#",k=random.randint(8,16)))
    ip      = random.choice(LEGIT_IPS)
    ua      = random.choice(LEGIT_UAS)
    rows.append(_make_feature(uname,pwd,ip,ua,ts,0))

# ── Brute-force attacks (150) ──────────────────────────────────────────────
for i in range(150):
    ts    = base + timedelta(hours=random.choice([2,3,4,23,0,1])+random.random(), days=random.randint(0,90))
    uname = random.choice(ATTACK_USERNAMES)
    pwd   = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789",k=random.randint(4,10)))
    ip    = random.choice(ATTACK_IPS)
    ua    = random.choice(ATTACK_UAS)
    rows.append(_make_feature(uname,pwd,ip,ua,ts,1))

# ── SQL injection attempts (50) ────────────────────────────────────────────
for i in range(50):
    ts    = base + timedelta(hours=random.uniform(0,23), days=random.randint(0,90))
    uname = random.choice(["admin","' OR '1'='1","admin'--"]) 
    pwd   = random.choice(["' OR 1=1--","password' OR 'x'='x","'; DROP TABLE users--"])
    ip    = random.choice(ATTACK_IPS)
    ua    = random.choice(ATTACK_UAS)
    rows.append(_make_feature(uname,pwd,ip,ua,ts,1))

# ── Off-hours legitimate access (100) ─────────────────────────────────────
for i in range(100):
    ts    = base + timedelta(hours=random.choice([22,23,0,1,6,7])+random.random(), days=random.randint(0,90))
    uname = random.choice(LEGIT_USERNAMES)
    pwd   = "StrongPass@2026!"
    ip    = random.choice(LEGIT_IPS)
    ua    = random.choice(LEGIT_UAS)
    rows.append(_make_feature(uname,pwd,ip,ua,ts,0))

random.shuffle(rows)

# ── Write CSV ──────────────────────────────────────────────────────────────
HEADERS = ["hour_sin","hour_cos","uname_len","pwd_len","pwd_entropy",
           "uname_risk","sql_flag","ip_var","ua_len","weekend","label"]

with open(OUT_CSV,"w",newline="") as f:
    w = csv.writer(f)
    w.writerow(HEADERS)
    w.writerows(rows)

# ── Attack patterns meta ───────────────────────────────────────────────────
patterns = {
    "total_events": len(rows),
    "normal_count": sum(1 for r in rows if r[-1]==0),
    "attack_count": sum(1 for r in rows if r[-1]==1),
    "attack_types": {
        "brute_force": 150,
        "sql_injection": 50,
        "credential_stuffing": 0,
    },
    "top_attack_ips": ATTACK_IPS[:5],
    "top_attack_usernames": ATTACK_USERNAMES[:8],
    "generated_at": datetime.now().isoformat(),
}

with open(OUT_JSON,"w") as f:
    json.dump(patterns,f,indent=2)

print(f"✅  Dataset: {OUT_CSV}  ({len(rows)} rows)")
print(f"✅  Patterns: {OUT_JSON}")
