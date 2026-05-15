/**
 * Liquid Background — animated mesh gradient orbs
 * Creates fluid, slowly drifting color blobs behind the UI
 */

(function () {
  const canvas = document.getElementById("liquid-canvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  let W, H, orbs;

  // Color palette
  const COLORS = [
    [0, 212, 255],    // cyan
    [155, 89, 255],   // violet
    [255, 45, 122],   // magenta
    [0, 100, 200],    // deep blue
    [60, 0, 180],     // indigo
  ];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    initOrbs();
  }

  function initOrbs() {
    orbs = COLORS.map((color, i) => ({
      x:    Math.random() * W,
      y:    Math.random() * H,
      r:    Math.random() * 280 + 180,
      vx:   (Math.random() - 0.5) * 0.35,
      vy:   (Math.random() - 0.5) * 0.35,
      color,
      alpha: 0.06 + Math.random() * 0.07,
      phase: Math.random() * Math.PI * 2,
    }));
  }

  function draw(t) {
    ctx.clearRect(0, 0, W, H);

    // Dark base
    ctx.fillStyle = "rgba(2, 6, 16, 1)";
    ctx.fillRect(0, 0, W, H);

    // Orbs
    orbs.forEach(o => {
      o.phase += 0.004;
      o.x += o.vx + Math.sin(o.phase) * 0.4;
      o.y += o.vy + Math.cos(o.phase) * 0.3;

      // Wrap
      if (o.x < -o.r) o.x = W + o.r;
      if (o.x > W + o.r) o.x = -o.r;
      if (o.y < -o.r) o.y = H + o.r;
      if (o.y > H + o.r) o.y = -o.r;

      const grad = ctx.createRadialGradient(o.x, o.y, 0, o.x, o.y, o.r);
      const [r, g, b] = o.color;
      grad.addColorStop(0,   `rgba(${r},${g},${b},${o.alpha})`);
      grad.addColorStop(0.5, `rgba(${r},${g},${b},${o.alpha * 0.4})`);
      grad.addColorStop(1,   `rgba(${r},${g},${b},0)`);

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.ellipse(o.x, o.y, o.r, o.r * 0.7, o.phase * 0.3, 0, Math.PI * 2);
      ctx.fill();
    });

    // Subtle noise grain overlay via tiny dots
    // (skipped for perf — CSS noise fallback handles it)

    requestAnimationFrame(draw);
  }

  window.addEventListener("resize", resize);
  resize();
  requestAnimationFrame(draw);
})();
