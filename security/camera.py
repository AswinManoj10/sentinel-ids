"""
IoT Camera Capture — robust, zero-dependency fallback.
Priority: OpenCV webcam → PIL placeholder → pure-Python PNG → SVG fallback
Always produces a displayable file before returning.
"""
import os, json, struct, zlib, math, threading, random
from datetime import datetime

SNAP_DIR = "outputs"
SNAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "outputs")
SNAP_DIR = os.path.normpath(SNAP_DIR)


# ── Pure-Python PNG generator ─────────────────────────────────────────────────

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


def _make_png(width: int, height: int, username: str, risk: int, ts: str) -> bytes:
    """Create a visually rich PNG placeholder — pure Python, no deps."""
    pixels = bytearray()

    r_accent = (220, 40, 60)     # red
    bg_dark   = (8, 5, 12)
    bg_mid    = (14, 10, 22)
    line_col  = (25, 18, 40)
    border_c  = (200, 35, 55)
    white_dim = (180, 160, 180)

    # Risk drives intensity
    intensity = min(risk / 100.0, 1.0)
    ra = (
        int(180 + 70 * intensity),
        int(30 - 20 * intensity),
        int(55 - 30 * intensity),
    )

    for y in range(height):
        pixels.append(0)  # filter byte
        for x in range(width):
            # Scanlines
            if y % 4 == 0:
                r, g, b = line_col
            else:
                # Vignette darkening toward edges
                ex = 1 - abs(x / width - 0.5) * 1.4
                ey = 1 - abs(y / height - 0.5) * 1.4
                vig = max(0.2, ex * ey)
                r = int(bg_mid[0] * vig)
                g = int(bg_mid[1] * vig)
                b = int(bg_mid[2] * vig)

            # Red border strips
            border = 4
            if x < border or x >= width - border or y < border or y >= height - border:
                r, g, b = ra

            # Corner L-brackets (16 px arms)
            arm = 16
            tick = 3
            in_corner = (
                (x < arm and y < tick) or (x < tick and y < arm) or     # TL
                (x >= width - arm and y < tick) or (x >= width - tick and y < arm) or  # TR
                (x < arm and y >= height - tick) or (x < tick and y >= height - arm) or  # BL
                (x >= width - arm and y >= height - tick) or (x >= width - tick and y >= height - arm)  # BR
            )
            if in_corner:
                r, g, b = ra

            # Center crosshair
            cx, cy = width // 2, height // 2
            ch_size = 30
            ch_thick = 1
            if abs(x - cx) < ch_size and abs(y - cy) <= ch_thick:
                r, g, b = (int(ra[0] * 0.6), int(ra[1] * 0.6), int(ra[2] * 0.6))
            if abs(y - cy) < ch_size and abs(x - cx) <= ch_thick:
                r, g, b = (int(ra[0] * 0.6), int(ra[1] * 0.6), int(ra[2] * 0.6))

            # Center circle
            dist = math.sqrt((x - cx) ** 2 + (y - cy) ** 2)
            if abs(dist - 45) < 1.5:
                r, g, b = ra
            if abs(dist - 20) < 1.2:
                r, g, b = (int(ra[0] * 0.7), 20, 30)

            # Horizontal scan bands
            band_y = int(y / height * 12)
            if band_y % 3 == 0 and random.random() < 0.005:
                r = min(255, r + 40)

            pixels.extend([
                max(0, min(255, r)),
                max(0, min(255, g)),
                max(0, min(255, b)),
            ])

    compressed = zlib.compress(bytes(pixels), 6)

    png  = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += _png_chunk(b"IDAT", compressed)
    png += _png_chunk(b"IEND", b"")
    return png


def _make_svg(username: str, risk: int, ts: str) -> str:
    """SVG fallback — always works, rendered natively by browsers."""
    intensity = min(risk / 100.0, 1.0)
    red_h = int(0 + 10 * intensity)
    red_s = int(80 + 15 * intensity)
    red_l = int(45 + 5 * intensity)
    red_css = f"hsl({red_h},{red_s}%,{red_l}%)"

    lines = "\n".join(
        f'<line x1="0" y1="{y}" x2="640" y2="{y}" stroke="rgba(255,255,255,0.03)" stroke-width="1"/>'
        for y in range(0, 480, 4)
    )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="640" height="480" viewBox="0 0 640 480">
  <defs>
    <radialGradient id="vg" cx="50%" cy="50%" r="70%">
      <stop offset="0%" stop-color="#1a0810" stop-opacity="1"/>
      <stop offset="100%" stop-color="#050208" stop-opacity="1"/>
    </radialGradient>
    <radialGradient id="cg" cx="50%" cy="50%" r="30%">
      <stop offset="0%" stop-color="{red_css}" stop-opacity="0.2"/>
      <stop offset="100%" stop-color="transparent" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="640" height="480" fill="url(#vg)"/>
  <rect width="640" height="480" fill="url(#cg)"/>
  {lines}
  <!-- Border -->
  <rect x="3" y="3" width="634" height="474" fill="none" stroke="{red_css}" stroke-width="2" opacity="0.8"/>
  <!-- Corner brackets TL -->
  <polyline points="3,30 3,3 30,3" fill="none" stroke="{red_css}" stroke-width="2.5"/>
  <!-- TR -->
  <polyline points="610,3 637,3 637,30" fill="none" stroke="{red_css}" stroke-width="2.5"/>
  <!-- BL -->
  <polyline points="3,450 3,477 30,477" fill="none" stroke="{red_css}" stroke-width="2.5"/>
  <!-- BR -->
  <polyline points="610,477 637,477 637,450" fill="none" stroke="{red_css}" stroke-width="2.5"/>
  <!-- Crosshair -->
  <line x1="290" y1="240" x2="350" y2="240" stroke="{red_css}" stroke-width="1" opacity="0.5"/>
  <line x1="320" y1="210" x2="320" y2="270" stroke="{red_css}" stroke-width="1" opacity="0.5"/>
  <circle cx="320" cy="240" r="45" fill="none" stroke="{red_css}" stroke-width="1.5" opacity="0.6"/>
  <circle cx="320" cy="240" r="20" fill="none" stroke="{red_css}" stroke-width="1" opacity="0.4"/>
  <!-- Alert label -->
  <rect x="180" y="60" width="280" height="36" rx="4" fill="{red_css}" opacity="0.9"/>
  <text x="320" y="84" font-family="-apple-system,sans-serif" font-size="14" font-weight="700"
        fill="white" text-anchor="middle" letter-spacing="2">INTRUDER CAPTURED</text>
  <!-- Metadata -->
  <rect x="40" y="360" width="560" height="90" rx="6" fill="rgba(0,0,0,0.5)" stroke="{red_css}" stroke-width="0.5" opacity="0.8"/>
  <text x="60" y="385" font-family="-apple-system,monospace" font-size="11" fill="rgba(255,255,255,0.4)" letter-spacing="1">USERNAME</text>
  <text x="60" y="403" font-family="-apple-system,sans-serif" font-size="15" font-weight="600" fill="white">{username}</text>
  <text x="320" y="385" font-family="-apple-system,monospace" font-size="11" fill="rgba(255,255,255,0.4)" letter-spacing="1">RISK SCORE</text>
  <text x="320" y="403" font-family="-apple-system,sans-serif" font-size="15" font-weight="700" fill="{red_css}">{risk}%</text>
  <text x="60" y="430" font-family="-apple-system,monospace" font-size="10" fill="rgba(255,255,255,0.35)">{ts[:19]}</text>
  <!-- Scan animation hint -->
  <rect x="0" y="0" width="640" height="2" fill="{red_css}" opacity="0.3"/>
</svg>"""


class CameraCapture:

    def capture(self, username: str = "unknown", risk: int = 50) -> str | None:
        ts     = datetime.now()
        ts_str = ts.strftime("%Y%m%d_%H%M%S")
        safe_u = "".join(c for c in username if c.isalnum() or c in "-_")[:20] or "unknown"
        base   = f"snap_{ts_str}_{safe_u}"
        meta   = {
            "timestamp": ts.isoformat(),
            "username":  username,
            "risk":      risk,
        }

        # Try webcam first (synchronous for reliability)
        img_path = self._try_webcam(base, meta) or \
                   self._try_pil(base, username, risk, ts.strftime("%Y-%m-%d %H:%M:%S"), meta) or \
                   self._png_placeholder(base, username, risk, ts.strftime("%Y-%m-%d %H:%M:%S"), meta) or \
                   self._svg_placeholder(base, username, risk, ts.strftime("%Y-%m-%d %H:%M:%S"), meta)

        return img_path

    # ── Attempt 1: real webcam ────────────────────────────────────────────────

    def _try_webcam(self, base: str, meta: dict) -> str | None:
        try:
            import cv2
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return None
            for _ in range(5):          # discard warm-up frames
                cap.read()
            ret, frame = cap.read()
            cap.release()
            if not ret or frame is None:
                return None
            img_path = os.path.join(SNAP_DIR, base + ".jpg")
            cv2.imwrite(img_path, frame)
            meta["file"] = img_path
            meta["url"]  = "/" + img_path.replace("\\", "/")
            self._write_meta(base, meta)
            return img_path
        except Exception:
            return None

    # ── Attempt 2: PIL placeholder ────────────────────────────────────────────

    def _try_pil(self, base: str, username: str, risk: int, ts_str: str, meta: dict) -> str | None:
        try:
            from PIL import Image, ImageDraw, ImageFilter
            W, H = 640, 480
            img  = Image.new("RGB", (W, H), (8, 5, 12))
            draw = ImageDraw.Draw(img)

            # Scanlines
            for y in range(0, H, 4):
                draw.line([(0, y), (W, y)], fill=(20, 14, 32), width=1)

            # Red vignette glow center
            for r_px in range(180, 0, -20):
                alpha = int(risk / 100 * 30 * (1 - r_px / 180))
                draw.ellipse([W//2 - r_px, H//2 - r_px, W//2 + r_px, H//2 + r_px],
                             outline=(200, 30, 50, alpha), width=1)

            red = (min(255, 180 + int(risk * 0.75)), 30, 50)

            # Border
            draw.rectangle([2, 2, W-3, H-3], outline=red, width=2)

            # Corner brackets
            arm = 20
            for ax, ay, dx, dy in [(3,3,1,0),(3,3,0,1),(W-3,3,-1,0),(W-3,3,0,1),
                                    (3,H-3,1,0),(3,H-3,0,-1),(W-3,H-3,-1,0),(W-3,H-3,0,-1)]:
                draw.line([(ax, ay), (ax + dx*arm, ay + dy*arm)], fill=red, width=3)

            # Crosshair
            cx, cy = W//2, H//2
            draw.line([(cx-50, cy), (cx+50, cy)], fill=(*red, 120), width=1)
            draw.line([(cx, cy-50), (cx, cy+50)], fill=(*red, 120), width=1)
            draw.ellipse([cx-40, cy-40, cx+40, cy+40], outline=red, width=1)
            draw.ellipse([cx-15, cy-15, cx+15, cy+15], outline=(*red, 80), width=1)

            # Alert banner
            draw.rectangle([150, 55, W-150, 95], fill=red)
            draw.text((W//2 - 80, 68), "INTRUDER CAPTURED", fill=(255, 255, 255))

            # Metadata area
            draw.rectangle([30, 355, W-30, 460], fill=(0, 0, 0, 160), outline=(*red, 80))
            draw.text((50, 370), "USERNAME", fill=(120, 100, 130))
            draw.text((50, 388), username, fill=(230, 220, 235))
            draw.text((W//2, 370), "RISK SCORE", fill=(120, 100, 130))
            draw.text((W//2, 388), f"{risk}%", fill=red)
            draw.text((50, 420), ts_str, fill=(80, 70, 100))

            img_path = os.path.join(SNAP_DIR, base + ".jpg")
            img.save(img_path, quality=88)
            meta["file"] = img_path
            meta["url"]  = "/" + img_path.replace("\\", "/")
            self._write_meta(base, meta)
            return img_path
        except Exception:
            return None

    # ── Attempt 3: pure-Python PNG ────────────────────────────────────────────

    def _png_placeholder(self, base: str, username: str, risk: int, ts_str: str, meta: dict) -> str | None:
        try:
            png_bytes = _make_png(640, 480, username, risk, ts_str)
            img_path  = os.path.join(SNAP_DIR, base + ".png")
            with open(img_path, "wb") as f:
                f.write(png_bytes)
            meta["file"] = img_path
            meta["url"]  = "/" + img_path.replace("\\", "/")
            self._write_meta(base, meta)
            return img_path
        except Exception:
            return None

    # ── Attempt 4: SVG fallback — always works ────────────────────────────────

    def _svg_placeholder(self, base: str, username: str, risk: int, ts_str: str, meta: dict) -> str | None:
        try:
            svg_str  = _make_svg(username, risk, ts_str)
            img_path = os.path.join(SNAP_DIR, base + ".svg")
            with open(img_path, "w", encoding="utf-8") as f:
                f.write(svg_str)
            meta["file"] = img_path
            meta["url"]  = "/" + img_path.replace("\\", "/")
            self._write_meta(base, meta)
            return img_path
        except Exception:
            return None

    def _write_meta(self, base: str, meta: dict):
        import json
        with open(os.path.join(SNAP_DIR, base + ".json"), "w") as f:
            json.dump(meta, f, indent=2)

    def list_snapshots(self) -> list[dict]:
        snaps = []
        for fn in sorted(os.listdir(SNAP_DIR), reverse=True):
            if fn.endswith(".json") and fn.startswith("snap_"):
                try:
                    with open(os.path.join(SNAP_DIR, fn)) as f:
                        meta = json.load(f)
                    img = meta.get("file", "")
                    if img and os.path.exists(img):
                        snaps.append(meta)
                except Exception:
                    pass
        return snaps[:30]

import json  # needed for list_snapshots at module level
