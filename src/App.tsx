import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowDownWideNarrow,
  ChevronRight,
  Search,
  X,
  Pin,
  Settings,
  Monitor,
  Sun,
  Moon,
  AppWindow,
  SlidersHorizontal,
  ShieldBan,
  ShieldCheck,
  RefreshCw,
  Gauge,
  Circle,
  ChartNoAxesCombined,
  Layers,
} from "lucide-react";
import { useNetworkTelemetry } from "./hooks/useNetworkTelemetry";
import { Capture } from "./components/Capture";
import { useCapture } from "./hooks/useCapture";
import { useFirewall, appTarget } from "./hooks/useFirewall";
import { groupProcesses } from "./utils/processNames";
import type { GroupedProcess } from "./utils/processNames";
import { formatSpeed } from "./utils/format";
import { History } from "./components/History";
import { Endpoint } from "./components/Endpoint";
import { InterfacePicker } from "./components/InterfacePicker";
import { Rate } from "./components/Rate";
import { InterfaceStatistics } from "./components/InterfaceStatistics";
import { Speedtest } from "./components/Speedtest";

type Preferences = {
  theme: "system" | "light" | "dark";
  transparent: boolean;
  appsOnly: boolean;
  colorIcons: boolean;
  showUnavailableInterfaces: boolean;
  advanced: boolean;
};
const native = "__TAURI_INTERNALS__" in window;
function loadPreferences(): Preferences {
  try {
    const p = JSON.parse(localStorage.getItem("vapour.appearance.v2") || "{}");
    return {
      theme: ["light", "dark", "system"].includes(p.theme) ? p.theme : "system",
      transparent: p.transparent !== false,
      appsOnly: p.appsOnly !== false,
      colorIcons: p.colorIcons === true,
      showUnavailableInterfaces: p.showUnavailableInterfaces === true,
      advanced: p.advanced === true,
    };
  } catch {
    return {
      theme: "system",
      transparent: true,
      appsOnly: true,
      colorIcons: false,
      showUnavailableInterfaces: false,
      advanced: false,
    };
  }
}
function Mark() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M6 20C1 14 11 10 6 4M12 20C7 14 17 10 12 4M18 20C13 14 23 10 18 4"
        stroke="currentColor"
        strokeWidth="1.65"
        strokeLinecap="round"
      />
    </svg>
  );
}
function ProcessIcon({ app }: { app: GroupedProcess }) {
  return (
    <span className="process-icon">
      {app.icon_data_url ? (
        <img src={app.icon_data_url} alt="" />
      ) : (
        <AppWindow size={21} strokeWidth={1.5} />
      )}
    </span>
  );
}
function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <div className="setting-row">
      <h2>{label}</h2>
      <button
        className="switch"
        role="switch"
        aria-label={label}
        aria-checked={checked}
        onClick={onChange}
      >
        <span />
      </button>
    </div>
  );
}

export function App() {
  const {
    snapshot,
    history,
    histories,
    isPinned,
    error,
    togglePin,
    hideWindow,
  } = useNetworkTelemetry();
  const firewall = useFirewall();
  const capture = useCapture();
  const [accessDismissed, setAccessDismissed] = useState(false);
  const [prefs, setPrefs] = useState(loadPreferences),
    [systemDark, setSystemDark] = useState(
      () => matchMedia("(prefers-color-scheme: dark)").matches,
    );
  const [view, setView] = useState<"list" | "detail" | "settings" | "speedtest" | "capture" | "firewall" | "interfaces">("list");
  const [selected, setSelected] = useState<string | null>(null),
    [selectedApp, setSelectedApp] = useState<GroupedProcess | null>(null);
  const [query, setQuery] = useState(""),
    [interfaceId, setInterfaceId] = useState("all"),
    [filter, setFilter] = useState<"all" | "external" | "local">("all");
  const [ranking, setRanking] = useState<string[]>([]),
    [now, setNow] = useState(Date.now);
  const searchRef = useRef<HTMLInputElement>(null),
    contentRef = useRef<HTMLDivElement>(null);
  const theme =
    prefs.theme === "system" ? (systemDark ? "dark" : "light") : prefs.theme;
  const apps = useMemo(
    () =>
      groupProcesses(snapshot?.processes || []).sort((a, b) =>
        a.displayName.localeCompare(b.displayName),
      ),
    [snapshot],
  );
  const captureAppAvailable = capture.appTarget
    ? apps.some(
        (app) =>
          !!app.path &&
          app.path.toLowerCase() === capture.appTarget?.path.toLowerCase(),
      )
    : true;
  const liveApp = apps.find((a) => a.groupKey === selected);
  const activeApp =
    liveApp ||
    (selectedApp
      ? {
          ...selectedApp,
          sockets: [],
          download_speed_bps: 0,
          upload_speed_bps: 0,
          active_sockets_count: 0,
        }
      : null);
  const measured = !native || snapshot?.measurement_status === "measured";
  const visible = useMemo(
    () =>
      [...apps]
        .sort((a, b) =>
          ranking.length
            ? (ranking.indexOf(a.groupKey) < 0
                ? 9999
                : ranking.indexOf(a.groupKey)) -
              (ranking.indexOf(b.groupKey) < 0
                ? 9999
                : ranking.indexOf(b.groupKey))
            : 0,
        )
        .filter((app) => {
          const q = query.trim().toLowerCase();
          if (!q) return !prefs.appsOnly || !app.is_system;
          return [
            app.displayName,
            app.name,
            app.path,
            ...app.pids.map(String),
            ...app.sockets.flatMap((s) => [s.remote_ip, s.remote_host || ""]),
          ].some((v) => v.toLowerCase().includes(q));
        }),
    [apps, query, prefs.appsOnly, ranking],
  );
  const adapter = snapshot?.interfaces.find((i) => i.id === interfaceId);
  const stale = !!snapshot && now - snapshot.timestamp > 5000;
  const update = (patch: Partial<Preferences>) =>
    setPrefs((old) => ({ ...old, ...patch }));
  const back = () => {
    setView("list");
    requestAnimationFrame(() => {
      contentRef.current
        ?.querySelectorAll<HTMLButtonElement>("[data-app]")
        .forEach((row) => {
          if (row.dataset.app === selected) row.focus();
        });
    });
  };
  useEffect(() => {
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const change = () => setSystemDark(mq.matches);
    mq.addEventListener("change", change);
    return () => mq.removeEventListener("change", change);
  }, []);
  useEffect(() => {
    const timer = setInterval(() => {
      if (!document.hidden) setNow(Date.now());
    }, 2000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.material = prefs.transparent
      ? "glass"
      : "solid";
    document.documentElement.dataset.icons = prefs.colorIcons
      ? "color"
      : "mono";
    document.documentElement.style.colorScheme = theme;
    try {
      localStorage.setItem("vapour.appearance.v2", JSON.stringify(prefs));
    } catch {
      /* session preference still works */
    }
  }, [prefs, theme]);
  useEffect(() => {
    if (native)
      import("@tauri-apps/api/core")
        .then(({ invoke }) =>
          invoke("set_appearance", {
            dark: theme === "dark",
            transparent: prefs.transparent,
          }),
        )
        .catch(console.error);
  }, [theme, prefs.transparent]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.defaultPrevented) return;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
        e.preventDefault();
        setView("list");
        requestAnimationFrame(() => searchRef.current?.focus());
      }
      if (e.key === "Escape") {
        if (view !== "list") back();
        else if (query) setQuery("");
        else void hideWindow();
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  });
  const largest = Math.max(
    1,
    ...apps.map((a) => a.download_speed_bps + a.upload_speed_bps),
  );
  if (native && !accessDismissed && (!firewall.elevationChecked || !firewall.elevated)) {
    return <main className="vapour-shell native">
      <header className="titlebar"><div className="wordmark" data-tauri-drag-region><Mark /><span data-tauri-drag-region>Vapour</span></div></header>
      <section className="access-welcome" aria-busy={!firewall.elevationChecked}>
        <ShieldCheck size={36} strokeWidth={1.3}/>
        {firewall.elevationChecked && <>
          <h1>App measurements</h1>
          <button className="access-enable" disabled={firewall.elevating} onClick={() => void firewall.elevate()}><ShieldCheck size={16}/>Enable app measurements</button>
        </>}
        <button className="text-button" onClick={() => setAccessDismissed(true)}>Not now</button>
        {firewall.error && <p role="alert">{firewall.error}</p>}
      </section>
    </main>;
  }
  return (
    <main data-mode={prefs.advanced ? "advanced" : "basic"} className={"vapour-shell " + (native ? "native" : "preview")}>
      <header className="titlebar">
        <div className="wordmark" data-tauri-drag-region>
          <Mark />
          <span data-tauri-drag-region>Vapour</span>
        </div>
        <div className="toolbar">
          <button className={"icon-button " + (prefs.advanced ? "selected" : "")} aria-label="Advanced mode" aria-pressed={prefs.advanced} title={prefs.advanced ? "Advanced" : "Basic"} onClick={() => update({advanced: !prefs.advanced})}><Layers size={16}/></button>
          <button
            className={"icon-button " + (isPinned ? "selected" : "")}
            aria-label={isPinned ? "Unpin window" : "Pin window"}
            title="Keep open"
            aria-pressed={isPinned}
            onClick={() => void togglePin()}
          >
            <Pin size={16} />
          </button>
          <button className={"icon-button " + (capture.status.active ? "capture-recording" : "")} aria-label={capture.status.active ? "Capture recording" : "Capture"} title={capture.status.active ? "Capture recording" : "Capture"} onClick={()=>setView("capture")}><Circle size={16}/></button>
          <button className="icon-button" aria-label="Speedtest" title="Speedtest" onClick={()=>setView("speedtest")}><Gauge size={17}/></button>
          <button className={"icon-button " + (view === "interfaces" ? "selected" : "")} aria-label="Interface statistics" title="Interfaces" onClick={() => setView(view === "interfaces" ? "list" : "interfaces")}><ChartNoAxesCombined size={17}/></button>
          <button className={"icon-button " + (view === "firewall" ? "selected" : "")} aria-label="Firewall" title="Firewall" aria-pressed={view === "firewall"} onClick={() => setView(view === "firewall" ? "list" : "firewall")}><ShieldCheck size={17}/></button>
          <button
            className={"icon-button " + (view === "settings" ? "selected" : "")}
            aria-label="Settings"
            title="Settings"
            onClick={() => setView(view === "settings" ? "list" : "settings")}
          >
            <Settings size={17} />
          </button>
          {native && (
            <button
              className="icon-button"
              aria-label="Hide Vapour"
              onClick={() => void hideWindow()}
            >
              <X size={16} />
            </button>
          )}
        </div>
      </header>
      {view === "list" && (
        <section className="overview" aria-label="Network activity">
          <div className="speeds">
            <Rate
              value={
                adapter?.download_speed_bps ??
                snapshot?.total_download_speed_bps ??
                0
              }
            />
            <Rate
              up
              value={
                adapter?.upload_speed_bps ??
                snapshot?.total_upload_speed_bps ??
                0
              }
            />
          </div>
          <History
            history={
              interfaceId === "all"
                ? history
                : histories["interface:" + interfaceId] || []
            }
          />
        </section>
      )}
      {!native && (
        <div className="demo-note">
          Design preview · sample data · simulated blocks
        </div>
      )}
      {(error || firewall.error) && (
        <div className="status-message" role="alert">
          {error || firewall.error}
        </div>
      )}
      {stale && (
        <div className="status-message" role="status">
          Updates paused
        </div>
      )}
      <div className="content" ref={contentRef}>
        {view === "list" && (
          <section className="list-view view-enter">
            <div className="search-line">
              <label className="search">
                <Search size={16} />
                <input
                  ref={searchRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Find an app or address"
                  aria-label="Find an app or address"
                />
                {query && (
                  <button
                    className="icon-button"
                    aria-label="Clear search"
                    onClick={() => {
                      setQuery("");
                      searchRef.current?.focus();
                    }}
                  >
                    <X size={14} />
                  </button>
                )}
              </label>
              <button
                className={"icon-button " + (!prefs.appsOnly ? "selected" : "")}
                aria-label={
                  prefs.appsOnly
                    ? "Show system processes"
                    : "Hide system processes"
                }
                title="System processes"
                aria-pressed={!prefs.appsOnly}
                onClick={() => update({ appsOnly: !prefs.appsOnly })}
              >
                <SlidersHorizontal size={16} />
              </button>
              <button
                className={"icon-button " + (ranking.length ? "selected" : "")}
                aria-label="Sort by activity"
                title="Sort by current activity"
                aria-pressed={!!ranking.length}
                disabled={!measured}
                onClick={() =>
                  setRanking(
                    ranking.length
                      ? []
                      : [...apps]
                          .sort(
                            (a, b) =>
                              b.download_speed_bps +
                              b.upload_speed_bps -
                              (a.download_speed_bps + a.upload_speed_bps),
                          )
                          .map((a) => a.groupKey),
                  )
                }
              >
                <ArrowDownWideNarrow size={16} />
              </button>
            </div>
            {native && firewall.elevationChecked && !firewall.elevated && (
              <button
                className="measurement-prompt"
                disabled={firewall.elevating}
                onClick={() => native && !firewall.elevated ? void firewall.elevate() : setView("settings")}
              >
                <ShieldCheck size={14} />
                <span>Enable app measurements</span>
                <ChevronRight size={13} />
              </button>
            )}
            {native && firewall.elevated && snapshot?.measurement_status === "unavailable" && <p className="detail-note" role="status">App measurements unavailable</p>}
            <div className="process-list">
              {visible.map((app) => (
                <button
                  key={app.groupKey}
                  data-app={app.groupKey}
                  className="process-row"
                  onClick={() => {
                    setSelected(app.groupKey);
                    setSelectedApp(app);
                    setFilter("all");
                    setView("detail");
                    if (contentRef.current) contentRef.current.scrollTop = 0;
                  }}
                >
                  <ProcessIcon app={app} />
                  <span className="process-info">
                    <span className="process-name">{app.displayName}</span>
                    <small className="advanced-only muted">{app.pids.length} processes · {app.active_sockets_count} connections</small>
                    {measured && (
                      <span className="usage-track">
                        <span
                          style={{
                            width:
                              ((app.download_speed_bps + app.upload_speed_bps) /
                                largest) *
                                100 +
                              "%",
                          }}
                        />
                      </span>
                    )}
                  </span>
                  {firewall.isBlocked(appTarget(app.path)) && (
                    <ShieldBan size={13} aria-label="Blocked" />
                  )}
                  <span
                    className="row-usage"
                    title={
                      measured
                        ? "Download / upload"
                        : "App measurement unavailable"
                    }
                  >
                    {measured ? (
                      <>
                        <span>
                          ↓ {formatSpeed(app.download_speed_bps).value}{" "}
                          <small>
                            {formatSpeed(app.download_speed_bps).unit}
                          </small>
                        </span>
                        <span>
                          ↑ {formatSpeed(app.upload_speed_bps).value}{" "}
                          <small>
                            {formatSpeed(app.upload_speed_bps).unit}
                          </small>
                        </span>
                      </>
                    ) : (
                      <span>—</span>
                    )}
                  </span>
                  <ChevronRight className="chevron" size={15} />
                </button>
              ))}
              {!visible.length && (
                <div className="empty-state">
                  <Search size={24} />
                  <p>
                    {query
                      ? "No matching apps or addresses"
                      : snapshot
                        ? "No applications to show"
                        : "Connecting…"}
                  </p>
                </div>
              )}
            </div>
          </section>
        )}
        {view === "detail" && activeApp && (
          <section className="detail-view view-enter">
            <button className="back-button" onClick={back}>
              <ArrowLeft size={15} />
              Applications
            </button>
            <div className="detail-heading">
              <ProcessIcon app={activeApp} />
              <div>
                <h1>{activeApp.displayName}</h1>
                <span>
                  {activeApp.sockets.filter((s) => !s.closed_at).length} active
                  · {activeApp.sockets.filter((s) => s.closed_at).length} recent
                </span>
              </div>
              <button
                className="icon-button"
                aria-label="Capture new app connections"
                title="Capture new app connections"
                disabled={
                  capture.busy ||
                  capture.status.active ||
                  capture.status.finalizing ||
                  !capture.native ||
                  !activeApp.path
                }
                onClick={() => {
                  if (!activeApp.path) return;
                  capture.selectApp({
                    path: activeApp.path,
                    label: activeApp.displayName,
                  });
                  setView("capture");
                }}
              >
                <Circle size={18} />
              </button>
              <button
                className={
                  "icon-button " +
                  (firewall.isBlocked(appTarget(activeApp.path))
                    ? "selected"
                    : "")
                }
                disabled={firewall.busy || !activeApp.path}
                aria-label={
                  firewall.isBlocked(appTarget(activeApp.path))
                    ? "Unblock app"
                    : "Block app"
                }
                title={
                  firewall.isBlocked(appTarget(activeApp.path))
                    ? "Unblock outgoing traffic"
                    : "Block outgoing traffic for this app"
                }
                onClick={() =>
                  firewall.elevated
                    ? void firewall.change(
                        appTarget(activeApp.path),
                        !firewall.isBlocked(appTarget(activeApp.path)),
                      )
                    : setView("settings")
                }
              >
                <ShieldBan size={18} />
              </button>
            </div>
            <div className="app-activity">
              {measured ? (
                <>
                  <div className="speeds">
                    <Rate value={activeApp.download_speed_bps} />
                    <Rate up value={activeApp.upload_speed_bps} />
                  </div>
                  <History
                    history={histories["app:" + activeApp.groupKey] || []}
                  />
                </>
              ) : (
                native && firewall.elevationChecked && !firewall.elevated ? <button
                  className="measurement-prompt"
                  disabled={firewall.elevating}
                  onClick={() => native && !firewall.elevated ? void firewall.elevate() : setView("settings")}
                >
                  <ShieldCheck size={14} />
                  Enable app measurements
                  <ChevronRight size={13} />
                </button> : <span className="detail-note" role="status">App measurements unavailable</span>
              )}
            </div>
            <div className="path advanced-only">{activeApp.path || activeApp.name}</div>
            <div className="detail-tabs" aria-label="Filter connections">
              {(["all", "external", "local"] as const).map((value) => (
                <button
                  key={value}
                  aria-pressed={filter === value}
                  className={filter === value ? "active" : ""}
                  onClick={() => setFilter(value)}
                >
                  {value[0].toUpperCase() + value.slice(1)}
                </button>
              ))}
            </div>
            <div className="endpoints">
              {activeApp.sockets
                .filter(
                  (s) =>
                    filter === "all" ||
                    (filter === "local"
                      ? s.is_local && s.remote_ip !== "*"
                      : !s.is_local && s.remote_ip !== "*"),
                )
                .map((s) => {
                  const target = {
                    ...appTarget(activeApp.path),
                    remote_ip: s.remote_ip,
                    remote_port: s.remote_port,
                    local_ip: s.local_ip,
                    local_port: s.local_port,
                    protocol: s.protocol,
                  };
                  return (
                    <Endpoint
                      key={s.id}
                      socket={s}
                      blocked={firewall.isBlocked(target)}
                      busy={firewall.busy}
                      captureBusy={capture.busy||capture.status.active||capture.status.finalizing}
                      canCapture={!s.closed_at&&s.protocol==="TCP"&&s.state==="ESTABLISHED"&&s.remote_ip!=="*"&&s.remote_port>0&&s.local_port>0&&s.local_ip!=="0.0.0.0"&&s.local_ip!=="::"}
                      onCapture={()=>{capture.setSession({socketId:s.id,label:`${s.remote_host||(s.remote_ip.includes(":")?"["+s.remote_ip+"]":s.remote_ip)}:${s.remote_port}`,address:`${s.local_ip}:${s.local_port} ↔ ${s.remote_ip}:${s.remote_port}`});setView("capture");}}
                      canBlock={
                        !!activeApp.path &&
                        s.remote_ip !== "*" &&
                        s.remote_port > 0 &&
                        s.local_port > 0 &&
                        s.local_ip !== "0.0.0.0" &&
                        s.local_ip !== "::"
                      }
                      onBlock={() =>
                        firewall.elevated
                          ? void firewall.change(
                              target,
                              !firewall.isBlocked(target),
                            )
                          : setView("settings")
                      }
                    />
                  );
                })}
            </div>
            {!activeApp.sockets.length && (
              <p className="detail-note">No active or recent connections</p>
            )}
          </section>
        )}
        {view === "capture" && <Capture sessionAvailable={!capture.session||!!snapshot?.processes.some(p=>p.sockets.some(s=>s.id===capture.session?.socketId&&!s.closed_at&&s.state==="ESTABLISHED"))} appAvailable={captureAppAvailable} showUnavailable={prefs.showUnavailableInterfaces} capture={capture} networkInterfaces={snapshot?.interfaces||[]} back={()=>((capture.session||capture.appTarget)&&selected?setView("detail"):back())} elevated={firewall.elevated} elevate={()=>void firewall.elevate()}/> }
        {view === "speedtest" && <Speedtest back={back} />}
        {view === "interfaces" && <InterfaceStatistics interfaces={snapshot?.interfaces || []} advanced={prefs.advanced} back={back}/>}
        {view === "firewall" && (
          <section className="settings-view view-enter">
            <div className="page-heading">
              <button className="back-button" onClick={back} aria-label="Back" title="Back"><ArrowLeft size={15}/></button>
              <h1>Firewall</h1>
            </div>
            <div className="blocks-heading">
              <h2>Blocks</h2>
              <button
                className="icon-button"
                aria-label="Refresh firewall rules"
                title="Refresh"
                disabled={firewall.busy}
                onClick={() => void firewall.refresh()}
              >
                <RefreshCw size={14} />
              </button>
            </div>
            {firewall.enforcementReason && <p role="status" className="error-banner">{firewall.enforcementReason}</p>}
            {firewall.rules.length ? (
              <div className="block-list">
                {firewall.rules.map((rule) => (
                  <div key={rule.id} className="block-row">
                    <div>
                      <span title={rule.target.path}>{rule.target.path.split(/[\\/]/).pop()}</span>
                      <small className="advanced-only">{rule.target.path}</small>
                      <small>
                        {rule.target.remote_ip
                          ? `${rule.target.protocol} · ${rule.target.remote_ip}:${rule.target.remote_port}`
                          : "All outgoing traffic"}
                      </small>
                    </div>
                    <button
                      className="icon-button"
                      aria-label={
                        "Unblock " +
                        rule.target.path +
                        (rule.target.remote_ip
                          ? " " + rule.target.remote_ip
                          : "")
                      }
                      disabled={firewall.busy}
                      title="Remove block"
                      onClick={() =>
                        firewall.elevated
                          ? void firewall.change(rule.target, false)
                          : void firewall.elevate()
                      }
                    >
                      <X size={15} />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="detail-note">No Vapour blocks</p>
            )}
          </section>
        )}
        {view === "settings" && (
          <section className="settings-view view-enter">
            <div className="page-heading">
              <button className="back-button" onClick={back} aria-label="Back" title="Back"><ArrowLeft size={15}/></button>
              <h1>Settings</h1>
            </div>
            <div className="setting-group">
              <div className="theme-options">
                {(
                  [
                    { value: "light", label: "Light", icon: Sun },
                    { value: "dark", label: "Dark", icon: Moon },
                    { value: "system", label: "System", icon: Monitor },
                  ] as const
                ).map(({ value, label, icon: Icon }) => (
                  <button
                    key={value}
                    className={prefs.theme === value ? "active" : ""}
                    onClick={() => update({ theme: value })}
                    aria-pressed={prefs.theme === value}
                  >
                    <span className={"theme-preview " + value}>
                      <span />
                      <span />
                      <span />
                    </span>
                    <span>
                      <Icon size={13} />
                      {label}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            <Toggle
              label="Translucent background"
              checked={prefs.transparent}
              onChange={() => update({ transparent: !prefs.transparent })}
            />
            <Toggle
              label="Color app icons"
              checked={prefs.colorIcons}
              onChange={() => update({ colorIcons: !prefs.colorIcons })}
            />
            <Toggle
              label="Include system processes"
              checked={!prefs.appsOnly}
              onChange={() => update({ appsOnly: !prefs.appsOnly })}
            />
            <Toggle label="Show unavailable capture interfaces" checked={prefs.showUnavailableInterfaces} onChange={() => update({showUnavailableInterfaces: !prefs.showUnavailableInterfaces})}/>
            {native && !firewall.elevated && (
              <div className="access-card">
                <ShieldCheck size={20} />
                <div>
                  <h2>App measurements & firewall</h2>
                  <p>Administrator access is needed.</p>
                  <button
                    className="text-button"
                    disabled={firewall.elevating}
                    onClick={() => void firewall.elevate()}
                  >
                    Restart as administrator
                  </button>
                </div>
              </div>
            )}
            {native && firewall.elevated && !measured && (
              <p role="status" className="detail-note">
                The network event collector could not start. App rates are
                unavailable.
              </p>
            )}
            <div className="advanced-only"><p className="detail-note">Native telemetry · Windows x64</p></div>
            <div className="about">
              <Mark />
              <span>
                Vapour <span className="muted">0.1.0 · Preview</span>
              </span>
            </div>
          </section>
        )}
      </div>
      {view === "list" && (
        <footer className="footer">
          <InterfacePicker
            interfaces={snapshot?.interfaces || []}
            value={interfaceId}
            onChange={setInterfaceId}
          />
          <span className="footer-count">{visible.length} apps</span>
        </footer>
      )}
    </main>
  );
}
export default App;
