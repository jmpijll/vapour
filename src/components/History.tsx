import { isAppHidden } from "../utils/visibility";
import { useEffect, useRef } from "react";
export type Sample = { time: number; down: number; up: number };
// Values stay attached to timestamps. The viewport moves, the samples do not morph.
export function History({ history }: { history: Sample[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const samples = useRef(history);
  const resumeRef = useRef<(() => void) | null>(null);
  useEffect(() => {
    samples.current = history;
    resumeRef.current?.();
  }, [history]);
  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const reduced = matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0,
      scale = 102400,
      lastFrame = performance.now(),
      lastReducedSample = -1;
    const draw = (tick: number) => {
      const data = samples.current,
        latest = data.at(-1);
      if (reduced.matches && latest?.time === lastReducedSample) return;
      lastReducedSample = latest?.time ?? -1;
      const end = reduced.matches
        ? (latest?.time ?? Date.now())
        : Math.min(Date.now() - 1000, (latest?.time ?? Date.now()) + 1000);
      const start = end - 30000,
        points = data.filter((p) => p.time >= start - 2000);
      const target =
        Math.max(102400, ...points.flatMap((p) => [p.down, p.up])) * 1.08;
      const delta = Math.min(100, tick - lastFrame);
      lastFrame = tick;
      scale +=
        (target - scale) * (reduced.matches ? 1 : 1 - Math.exp(-delta / 650));
      const w = canvas.clientWidth,
        h = canvas.clientHeight,
        dpr = devicePixelRatio || 1;
      if (
        canvas.width !== Math.round(w * dpr) ||
        canvas.height !== Math.round(h * dpr)
      ) {
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(h * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const css = getComputedStyle(canvas);
      ctx.strokeStyle = css.getPropertyValue("--line");
      ctx.lineWidth = 0.6;
      for (let i = 1; i < 4; i++) {
        ctx.beginPath();
        ctx.moveTo(0, (h * i) / 4);
        ctx.lineTo(w, (h * i) / 4);
        ctx.stroke();
      }
      (["down", "up"] as const).forEach((key, index) => {
        ctx.beginPath();
        ctx.strokeStyle = css.getPropertyValue(index ? "--muted" : "--accent");
        ctx.lineWidth = index ? 1.2 : 1.7;
        ctx.lineJoin = "round";
        ctx.lineCap = "round";
        ctx.setLineDash(index ? [3, 4] : []);
        points.forEach((p, i) => {
          const x = ((p.time - start) / 30000) * w,
            y = h - 3 - (p[key] / scale) * (h - 8);
          if (!i) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();
        ctx.setLineDash([]);
      });
      if (
        !isAppHidden() &&
        !reduced.matches &&
        Date.now() - (latest?.time || 0) < 4000
      )
        frame = requestAnimationFrame(draw);
    };
    const resume = () => {
      cancelAnimationFrame(frame);
      lastReducedSample = -1;
      if (!isAppHidden()) frame = requestAnimationFrame(draw);
    };
    resumeRef.current = resume;
    const theme = new MutationObserver(resume);
    theme.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    document.addEventListener("visibilitychange", resume);
    reduced.addEventListener("change", resume);
    resume();
    return () => {
      resumeRef.current = null;
      cancelAnimationFrame(frame);
      theme.disconnect();
      document.removeEventListener("visibilitychange", resume);
      reduced.removeEventListener("change", resume);
    };
  }, []);
  return (
    <div className="history">
      <canvas
        ref={canvasRef}
        role="img"
        aria-label="30 seconds of download and upload activity"
      />
      <div className="chart-caption">
        <span>30s</span>
        <span>Now</span>
      </div>
    </div>
  );
}
