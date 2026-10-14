import React, { useEffect, useRef } from "react";
import "./AnimatedGearBackground.css";

/* ============================================================
   Gear SVG builder
   Generates a precise mechanical gear path with beveled teeth.
   ============================================================ */
function buildGearPath(cx, cy, outerR, innerR, toothW, numTeeth) {
  const pts = [];
  const step = (2 * Math.PI) / numTeeth;

  for (let i = 0; i < numTeeth; i++) {
    const base = i * step;
    const a0 = base - toothW * 0.55;
    const a1 = base - toothW * 0.28;
    const a2 = base + toothW * 0.28;
    const a3 = base + toothW * 0.55;

    pts.push(
      [cx + innerR * Math.cos(a0), cy + innerR * Math.sin(a0)],
      [cx + outerR * Math.cos(a1), cy + outerR * Math.sin(a1)],
      [cx + outerR * Math.cos(a2), cy + outerR * Math.sin(a2)],
      [cx + innerR * Math.cos(a3), cy + innerR * Math.sin(a3)]
    );
  }

  return (
    pts
      .map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(2)},${p[1].toFixed(2)}`)
      .join(" ") + " Z"
  );
}

/* ============================================================
   GearSVG
   Renders a high-detail cyber-mechanical gear with concentric rings,
   circuit traces, tech nodes, spokes, and illuminated glowing edges.
   ============================================================ */
function GearSVG({ id, numTeeth, primaryColor, midColor, brightColor, glowColor }) {
  const cx = 120;
  const cy = 120;
  const outerR = 104;
  const innerR = 80;
  const holeR = 26;
  const toothW = (2 * Math.PI) / numTeeth / 2;

  const path = buildGearPath(cx, cy, outerR, innerR, toothW, numTeeth);

  // Circuit trace node coordinates along radius r=64
  const nodeAngles = [30, 90, 150, 210, 270, 330];
  const traceNodes = nodeAngles.map((deg) => {
    const rad = (deg * Math.PI) / 180;
    return {
      x: cx + 64 * Math.cos(rad),
      y: cy + 64 * Math.sin(rad),
      deg,
    };
  });

  return (
    <svg
      viewBox="0 0 240 240"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        {/* Dark Metallic Face Gradient */}
        <radialGradient id={`grad-face-${id}`} cx="38%" cy="32%" r="75%">
          <stop offset="0%" stopColor={glowColor} stopOpacity="0.9" />
          <stop offset="25%" stopColor={brightColor} stopOpacity="0.85" />
          <stop offset="60%" stopColor={midColor} stopOpacity="0.85" />
          <stop offset="85%" stopColor={primaryColor} stopOpacity="0.95" />
          <stop offset="100%" stopColor="#040914" stopOpacity="0.98" />
        </radialGradient>

        {/* Inner Ring Gradient */}
        <radialGradient id={`grad-ring-${id}`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#061222" stopOpacity="0.95" />
          <stop offset="70%" stopColor={primaryColor} stopOpacity="0.75" />
          <stop offset="100%" stopColor={midColor} stopOpacity="0.9" />
        </radialGradient>
      </defs>

      {/* 1. Main Metallic Gear Body & Teeth */}
      <path
        d={path}
        fill={`url(#grad-face-${id})`}
        stroke={glowColor}
        strokeWidth="1.6"
        strokeOpacity="0.9"
      />

      {/* 2. Outer Tooth Root Inset Rim */}
      <circle
        cx={cx}
        cy={cy}
        r={innerR - 2}
        fill="none"
        stroke="#030812"
        strokeWidth="3"
        strokeOpacity="0.85"
      />

      {/* 3. Outer Concentric Tech Ring */}
      <circle
        cx={cx}
        cy={cy}
        r={innerR - 5}
        fill={`url(#grad-ring-${id})`}
        stroke={midColor}
        strokeWidth="1.2"
        strokeOpacity="0.8"
      />

      {/* 4. Concentric HUD Tick Mark Ring */}
      <circle
        cx={cx}
        cy={cy}
        r={73}
        fill="none"
        stroke={glowColor}
        strokeWidth="1.2"
        strokeDasharray="2 6"
        strokeOpacity="0.75"
      />

      {/* 5. Outer Circuit Trace Arc Ring */}
      <circle
        cx={cx}
        cy={cy}
        r={64}
        fill="none"
        stroke={brightColor}
        strokeWidth="1.8"
        strokeDasharray="38 14 20 14"
        strokeOpacity="0.85"
      />

      {/* 6. Circuit Trace Nodes & Radial Stub Traces */}
      {traceNodes.map((node, i) => {
        const rad = (node.deg * Math.PI) / 180;
        const xOuter = cx + 73 * Math.cos(rad);
        const yOuter = cy + 73 * Math.sin(rad);
        return (
          <g key={i}>
            {/* Trace stub line */}
            <line
              x1={node.x}
              y1={node.y}
              x2={xOuter}
              y2={yOuter}
              stroke={glowColor}
              strokeWidth="1.2"
              strokeOpacity="0.8"
            />
            {/* Glowing Tech Node */}
            <circle
              cx={node.x}
              cy={node.y}
              r="2.8"
              fill={glowColor}
              stroke="#040914"
              strokeWidth="0.8"
            />
          </g>
        );
      })}

      {/* 7. 6 Mechanical Spokes connecting Hub to Outer Ring */}
      {[0, 60, 120, 180, 240, 300].map((angle) => {
        const rad = (angle * Math.PI) / 180;
        const x1 = cx + (holeR + 4) * Math.cos(rad);
        const y1 = cy + (holeR + 4) * Math.sin(rad);
        const x2 = cx + 56 * Math.cos(rad);
        const y2 = cy + 56 * Math.sin(rad);
        return (
          <g key={angle}>
            {/* Heavy Spoke Beam */}
            <line
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={primaryColor}
              strokeWidth="5"
              strokeOpacity="0.8"
              strokeLinecap="round"
            />
            {/* Spoke Center Glow Line */}
            <line
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={glowColor}
              strokeWidth="1.4"
              strokeOpacity="0.9"
              strokeLinecap="round"
            />
          </g>
        );
      })}

      {/* 8. Inner Concentric Circuit Arc Ring */}
      <circle
        cx={cx}
        cy={cy}
        r={48}
        fill="none"
        stroke={glowColor}
        strokeWidth="1.4"
        strokeDasharray="18 10 35 10"
        strokeOpacity="0.8"
      />

      {/* 9. Concentric Inner HUD Tick Ring */}
      <circle
        cx={cx}
        cy={cy}
        r={38}
        fill="none"
        stroke={midColor}
        strokeWidth="1"
        strokeDasharray="1.5 4"
        strokeOpacity="0.75"
      />

      {/* 10. Illuminated Inner Hub Bevel Ring */}
      <circle
        cx={cx}
        cy={cy}
        r={holeR + 4}
        fill="none"
        stroke={glowColor}
        strokeWidth="1.6"
        strokeOpacity="0.85"
      />

      {/* 11. Dark Core Hub Hole */}
      <circle cx={cx} cy={cy} r={holeR} fill="#040914" fillOpacity="0.96" />

      {/* 12. Sci-Fi Reticle / Crosshair Center Detailing */}
      <circle cx={cx} cy={cy} r={holeR - 8} fill="none" stroke={midColor} strokeWidth="1" strokeOpacity="0.6" />
      <line
        x1={cx - 10} y1={cy}
        x2={cx + 10} y2={cy}
        stroke={glowColor} strokeWidth="1.5" strokeOpacity="0.85"
      />
      <line
        x1={cx} y1={cy - 10}
        x2={cx} y2={cy + 10}
        stroke={glowColor} strokeWidth="1.5" strokeOpacity="0.85"
      />
      <circle cx={cx} cy={cy} r="3" fill={glowColor} />
    </svg>
  );
}

/* ============================================================
   AnimatedGearBackground
   Renders 3 gears globally with scroll-velocity-driven speed.
   Animation uses requestAnimationFrame + refs (no state updates
   on each frame) for performance.
   ============================================================ */
export default function AnimatedGearBackground() {
  const leftRef  = useRef(null);
  const rightRef = useRef(null);
  const botRef   = useRef(null);

  useEffect(() => {
    // Idle rotation speeds (degrees per second)
    const IDLE_SPEED_LEFT  =  8;   // clockwise
    const IDLE_SPEED_RIGHT = -6;   // counter-clockwise
    const IDLE_SPEED_BOT   =  11;  // clockwise

    // Scroll boost multiplier ceiling
    const MAX_VELOCITY_BOOST = 6;

    // Smooth speed decay (0–1 per frame)
    const DECAY = 0.04;

    let angLeft  = 0;
    let angRight = 0;
    let angBot   = 0;

    let currentBoost = 1;
    let targetBoost  = 1;

    let lastScrollY   = window.scrollY;
    let lastScrollTime = performance.now();
    let scrollVelocity = 0; // px/s

    const onScroll = () => {
      const now = performance.now();
      const dt  = (now - lastScrollTime) / 1000;
      if (dt > 0) {
        const dy = Math.abs(window.scrollY - lastScrollY);
        scrollVelocity = dy / dt;
      }
      lastScrollY   = window.scrollY;
      lastScrollTime = now;
    };

    window.addEventListener("scroll", onScroll, { passive: true });

    let rafId;
    let lastFrameTime = performance.now();

    const tick = (now) => {
      const dt = Math.min((now - lastFrameTime) / 1000, 0.1);
      lastFrameTime = now;

      // Decay scroll velocity
      scrollVelocity *= 0.90;

      // Calculate speed boost
      targetBoost = 1 + Math.min(scrollVelocity / 200, MAX_VELOCITY_BOOST - 1);

      // Interpolate current boost smoothly
      currentBoost += (targetBoost - currentBoost) * DECAY * 60 * dt;
      if (currentBoost < 1) currentBoost = 1;

      const boost = currentBoost;

      angLeft  += IDLE_SPEED_LEFT  * boost * dt;
      angRight += IDLE_SPEED_RIGHT * boost * dt;
      angBot   += IDLE_SPEED_BOT   * boost * dt;

      if (leftRef.current) {
        leftRef.current.style.transform = `rotate(${angLeft}deg)`;
      }
      if (rightRef.current) {
        rightRef.current.style.transform = `rotate(${angRight}deg)`;
      }
      if (botRef.current) {
        botRef.current.style.transform = `rotate(${angBot}deg)`;
      }

      rafId = requestAnimationFrame(tick);
    };

    rafId = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  return (
    <div className="gear-bg" aria-hidden="true">
      {/* ── Gear 1: Left, Orange/Gold ── */}
      <div className="gear-wrap gear-wrap--left" ref={leftRef}>
        <div className="gear-glow-container">
          <GearSVG
            id="left"
            numTeeth={18}
            primaryColor="#7C3F00"
            midColor="#D97706"
            brightColor="#F59E0B"
            glowColor="#FBBF24"
          />
        </div>
      </div>

      {/* ── Gear 2: Right, Teal/Cyan ── */}
      <div className="gear-wrap gear-wrap--right" ref={rightRef}>
        <div className="gear-glow-container">
          <GearSVG
            id="right"
            numTeeth={14}
            primaryColor="#064E5B"
            midColor="#0891B2"
            brightColor="#06B6B4"
            glowColor="#22D3EE"
          />
        </div>
      </div>

      {/* ── Gear 3: Bottom-Left, Purple ── */}
      <div className="gear-wrap gear-wrap--bottomleft" ref={botRef}>
        <div className="gear-glow-container">
          <GearSVG
            id="bot"
            numTeeth={12}
            primaryColor="#3B1D78"
            midColor="#7C3AED"
            brightColor="#8B5CF6"
            glowColor="#A78BFA"
          />
        </div>
      </div>
    </div>
  );
}
