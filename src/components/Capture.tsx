import { useEffect, useRef, useState } from "react";
import {
  AppWindow,
  ArrowLeft,
  Check,
  ChevronDown,
  Circle,
  FolderOpen,
  HardDrive,
  Layers,
  Link2,
  Network,
  Save,
  ShieldCheck,
  Square,
  Timer,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  captureInterfaces,
  type CaptureControl,
  type CaptureInterface,
} from "../hooks/useCapture";
import type { InterfaceInfo } from "../types";

type CaptureProps = {
  capture: CaptureControl;
  back: () => void;
  elevated: boolean;
  elevate: () => void;
  networkInterfaces: InterfaceInfo[];
  showUnavailable: boolean;
  sessionAvailable: boolean;
  appAvailable: boolean;
};

export function Capture({
  capture,
  back,
  elevated,
  elevate,
  networkInterfaces,
  showUnavailable,
  sessionAvailable,
  appAvailable,
}: CaptureProps) {
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const selected = capture.interfaceId;
  const picker = useRef<HTMLDivElement>(null);
  const { status, busy } = capture;
  const appTarget = capture.appTarget;
  const session = capture.session;
  const bytes =
    status.bytes < 1048576
      ? `${(status.bytes / 1024).toFixed(1)} KiB`
      : `${(status.bytes / 1048576).toFixed(1)} MiB`;
  const canStart =
    capture.native &&
    !busy &&
    !status.active &&
    !status.finalizing &&
    (appTarget
      ? appAvailable
      : interfaces.some((item) => item.id === selected) && sessionAvailable);

  useEffect(() => {
    if (!capture.native || !elevated || appTarget) return;
    let disposed = false;
    captureInterfaces()
      .then((value) => {
        if (!disposed) setInterfaces(value);
      })
      .catch((e) => {
        if (!disposed) setError(String(e));
      });
    return () => {
      disposed = true;
    };
  }, [capture.native, elevated, appTarget]);

  useEffect(() => {
    const outside = (event: PointerEvent) => {
      if (!picker.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", outside);
    return () => document.removeEventListener("pointerdown", outside);
  }, []);

  const labels = new Map(
    interfaces.map((item) => [
      item.id,
      networkInterfaces.find((network) => network.name === item.name)?.alias ||
        item.name,
    ]),
  );
  const unsupported = networkInterfaces.filter(
    (network) =>
      !interfaces.some(
        (item) => item.name === network.name || item.name === network.alias,
      ),
  );
  const startLabel = status.finalizing
    ? "Finalizing capture"
    : status.active
      ? "Stop capture"
      : "Start capture";

  return (
    <section className="settings-view capture-view view-enter">
      <div className="page-heading">
        <button
          className="back-button"
          aria-label="Back"
          title="Back"
          onClick={back}
        >
          <ArrowLeft size={15} />
        </button>
        <h1>Capture</h1>
      </div>

      {(appTarget || session) && (
        <div
          className="capture-target"
          title={appTarget?.path || session?.address}
        >
          {appTarget ? <AppWindow size={14} /> : <Link2 size={14} />}
          <span>{appTarget?.label || session?.label}</span>
          {appTarget && !appAvailable && <small>Closed</small>}
          {session && !sessionAvailable && <small>Closed</small>}
          {status.partial && (
            <small title="Only new connections with verified process evidence">
              Partial
            </small>
          )}
          <button
            className="icon-button"
            aria-label="Capture entire interface"
            title="Capture entire interface"
            disabled={status.active || status.finalizing || busy}
            onClick={capture.clearTarget}
          >
            <X size={13} />
          </button>
        </div>
      )}

      {!elevated && capture.native ? (
        <button className="measurement-prompt" onClick={elevate}>
          <ShieldCheck size={14} />
          Enable capture
        </button>
      ) : (
        <>
          {!appTarget && (
            <div
              className="capture-picker"
              ref={picker}
              onBlur={(event) => {
                if (!event.currentTarget.contains(event.relatedTarget))
                  setOpen(false);
              }}
              onKeyDown={(event) => {
                if (event.key === "Escape" && open) {
                  event.stopPropagation();
                  setOpen(false);
                }
                if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
                  event.preventDefault();
                  setOpen(true);
                  requestAnimationFrame(() => {
                    const items = Array.from(
                      picker.current?.querySelectorAll<HTMLButtonElement>(
                        '[role="menuitemradio"]:not(:disabled)',
                      ) || [],
                    );
                    const current = items.indexOf(
                      document.activeElement as HTMLButtonElement,
                    );
                    const next =
                      event.key === "Home"
                        ? 0
                        : event.key === "End"
                          ? items.length - 1
                          : (current +
                              (event.key === "ArrowUp" ? -1 : 1) +
                              items.length) %
                            items.length;
                    items[next]?.focus();
                  });
                }
              }}
            >
              <button
                className="capture-interface"
                aria-label="Capture interface"
                aria-haspopup="menu"
                aria-expanded={open}
                disabled={status.active || status.finalizing || busy || !capture.native}
                onClick={() => setOpen(!open)}
              >
                <Network size={14} />
                <span>
                  {(selected !== null ? labels.get(selected) : null) ||
                    "Interface"}
                </span>
                <ChevronDown size={13} />
              </button>
              {open && (
                <div className="capture-menu" role="menu" aria-label="Capture interface">
                  {interfaces.map((item) => (
                    <button
                      key={item.id}
                      role="menuitemradio"
                      aria-checked={selected === item.id}
                      onClick={() => {
                        capture.setInterfaceId(item.id);
                        setOpen(false);
                      }}
                    >
                      <span title={item.name}>{labels.get(item.id)}</span>
                      {selected === item.id && <Check size={14} />}
                    </button>
                  ))}
                  {showUnavailable &&
                    unsupported.map((item) => (
                      <button
                        key={item.id}
                        role="menuitemradio"
                        aria-checked={false}
                        disabled
                        title="Capture unavailable"
                      >
                        <span>{item.alias || item.name}</span>
                      </button>
                    ))}
                </div>
              )}
            </div>
          )}

          <div className="capture-metrics">
            <div title="Packets" aria-label="Packets">
              <Layers size={16} />
              <strong>{appTarget && status.active ? "—" : status.packets.toLocaleString()}</strong>
            </div>
            <div title="File size" aria-label="File size">
              <HardDrive size={16} />
              <strong>{appTarget && status.active ? "—" : bytes}</strong>
            </div>
            <div title="Duration" aria-label="Duration">
              <Timer size={16} />
              <strong>{Math.floor(status.duration_ms / 1000)} s</strong>
            </div>
          </div>

          <details className="advanced-only capture-diagnostics"><summary>Diagnostics</summary>
            <p className="detail-note">Native loss counters: {status.native_loss_available === undefined ? "Unavailable" : status.native_loss_available ? "Available" : "Unavailable"}</p>
            {status.loss_details && <dl>{Object.entries(status.loss_details).map(([key,value])=><div className="counter-pair" key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{value}</dd></div>)}</dl>}
            {status.path && <p className="detail-note">{status.path}</p>}
          </details>
          <div className="capture-actions">
            <button
              className="icon-button speedtest-run"
              disabled={
                busy ||
                !capture.native ||
                status.finalizing ||
                (!status.active && !canStart)
              }
              aria-label={startLabel}
              title={
                status.finalizing
                  ? "Finalizing capture"
                  : status.active
                    ? "Stop capture"
                    : appTarget ? "Start app capture · 60 s" : "Start capture · 60 s / 64 MiB"
              }
              onClick={() => {
                if (status.active) void capture.stop();
                else if (appTarget) void capture.startApp();
                else if (selected !== null) void capture.startInterface(selected);
              }}
            >
              {status.active ? <Square size={19} /> : <Circle size={19} />}
            </button>
            {status.path && !status.active && !status.finalizing && (
              <button
                className="icon-button speedtest-run"
                aria-label="Save PCAPNG"
                title="Save PCAPNG"
                disabled={busy}
                onClick={() => void capture.save()}
              >
                <Save size={19} />
              </button>
            )}
            <button
              className="icon-button speedtest-run"
              disabled={busy || !capture.native}
              aria-label="Open capture folder"
              title="Open capture folder"
              onClick={() => void capture.folder()}
            >
              <FolderOpen size={19} />
            </button>
          </div>

          {status.dropped > 0 && (
            <p className="capture-warning" role="status">
              <TriangleAlert size={14} />
              {status.dropped.toLocaleString()} missed
            </p>
          )}
        </>
      )}

      {(error || capture.error || status.error) && (
        <p role="alert" className="detail-note">
          {error || capture.error || status.error}
        </p>
      )}
    </section>
  );
}
