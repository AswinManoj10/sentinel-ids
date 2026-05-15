# SENTINEL IDS v3 — AI Intrusion Detection System

## Quick Start (VSCode)

```bash
# Terminal 1 — create venv
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

pip install flask Pillow
pip install opencv-python    # optional (real webcam)

# Generate the 1,000-row training dataset
python data/generate_dataset.py

# Run
python app.py
# → http://localhost:5000
```

## Pages & Credentials

| URL | Page |
|-----|------|
| `/` | **Admin login** — `admin / Admin@2026` |
| `/dashboard` → Overview | Live feed, snapshots, stats |
| `/dashboard` → Intruders | Gallery + delete controls |
| `/dashboard` → Demo | 3-attempt lockout simulator |
| `/analytics` | Full ML metrics + charts |
| `/portal` | **Honeypot** — fake Nexora Corp portal |
| `/alert` | Threat response page |

## Demo Tab Credentials

| Username | Password |
|----------|----------|
| `demo` | `Demo@2026` |
| `guest` | `Guest#123` |

Use **any other credentials** to trigger the full threat pipeline.
After **3 failed attempts**, the demo locks and flags the intruder.

## Admin Can

- View all intruder snapshots with metadata
- **Delete individual snapshots** (hover over card → trash icon)
- **Delete all snapshots** at once
- Simulate attacks via ⚡ button
- Open the honeypot decoy portal

## ML Models

| Model | Role | Details |
|-------|------|---------|
| Isolation Forest | Primary real-time scoring | 80 trees, online-retrained every 30 events |
| DBSCAN | Cluster analysis | ε=1.5, min_pts=4, silhouette scoring |
| LOF | Cross-validation | k=8 nearest neighbors |
| Welford Scaler | Online normalization | Streaming mean/variance |

All models are **pure Python** — no sklearn or numpy required.
Bootstrapped on 1,000 labeled synthetic events (700 normal, 300 attacks).
