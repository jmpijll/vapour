import {useEffect, useRef, useState} from "react";
import {ArrowDown, ArrowUp, ArrowLeft, Timer, Activity, Play, Square, RotateCcw, Globe, Check, X} from "lucide-react";
import {runSpeedtest, speedtestAvailable, updateSpeedValues, type SpeedEvent, type SpeedValues, type SpeedPhase} from "../utils/speedtest";
const metrics = [
  {key:"download",label:"Download",Icon:ArrowDown,unit:"Mbps"},
  {key:"upload",label:"Upload",Icon:ArrowUp,unit:"Mbps"},
  {key:"latency",label:"Latency",Icon:Timer,unit:"ms"},
  {key:"jitter",label:"Jitter",Icon:Activity,unit:"ms"},
] as const;
const order: SpeedPhase[] = ["latency","jitter","download","upload"];
export function Speedtest({back}:{back:()=>void}) {
  const [values,setValues] = useState<SpeedValues>({});
  const [event,setEvent] = useState<SpeedEvent|null>(null);
  const [running,setRunning] = useState(false);
  const [server,setServer] = useState("");
  const [serverUrl,setServerUrl] = useState("");
  const [editingServer,setEditingServer] = useState(false);
  const [completedAt,setCompletedAt] = useState<number|null>(null);
  const [error,setError] = useState("");
  const controller = useRef<AbortController|null>(null);
  useEffect(()=>()=>{controller.current?.abort();controller.current=null;},[]);
  const start = async () => {
    if (controller.current) return;
    const run = new AbortController(); controller.current=run;
    setValues({});setEvent(null);setError("");setCompletedAt(null);setServer("");setEditingServer(false);setRunning(true);
    const deadline = setTimeout(()=>run.abort(),120000);
    try {
      await runSpeedtest(run.signal,next=>{
        if(controller.current!==run) return;
        setEvent(next); setValues(previous=>updateSpeedValues(previous,next));
        if(next.server) setServer(next.server.name);
        if(next.event==="complete") setCompletedAt(Date.now());
      },serverUrl);
    } catch(e) { if (!run.signal.aborted && controller.current===run) setError(e instanceof Error ? e.message : String(e)); }
    finally { clearTimeout(deadline);if(controller.current===run){controller.current=null;setRunning(false);} }
  };
  const phaseIndex = event?.phase ? order.indexOf(event.phase) : 0;
  const fraction = event?.warmup ? 0 : Math.min(1,(event?.elapsed_ms ?? 0)/(event?.duration_ms || 10000));
  const progress = completedAt ? 100 : ((phaseIndex+fraction)/4)*100;
  const action = running ? "Cancel" : completedAt || error ? "Test again" : "Start";
  return <section className="settings-view speedtest-view view-enter">
  <div className="page-heading"><button className="back-button" onClick={back} aria-label="Back" title="Back"><ArrowLeft size={15}/></button>
    <h1>Speedtest</h1></div>
    {editingServer ? <form className="speedtest-server-edit" onSubmit={e=>{e.preventDefault();setEditingServer(false);setServer("");}}>
      <Globe size={13}/><input aria-label="Speedtest server URL" type="url" placeholder="https://server/" value={serverUrl} onChange={e=>setServerUrl(e.target.value)} autoFocus/>
      <button className="icon-button" aria-label="Use server" title="Use server"><Check size={14}/></button>
      <button className="icon-button" type="button" aria-label="Automatic server" title="Automatic server" onClick={()=>{setServerUrl("");setServer("");setEditingServer(false);}}><X size={14}/></button>
    </form> : <button className="speedtest-server" disabled={running} aria-label="Choose speedtest server" title={server || serverUrl || "Automatic server"} onClick={()=>setEditingServer(true)}><Globe size={13}/><span>{server || serverUrl || "Auto"}</span></button>}
    <div className="speedtest-results">
      {metrics.map(({key,label,Icon,unit})=><div key={key} className={running && event?.phase===key ? "is-measuring" : ""} aria-label={label} title={label}>
        <Icon size={18}/><strong>{values[key]===undefined ? "—" : values[key].toFixed(1)}</strong><span>{unit}</span>
      </div>)}
    </div>
    <div className={`speedtest-progress${running && !event?.phase ? " is-connecting" : ""}`} role="progressbar" aria-label="Speedtest" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress)}><span style={{width:`${progress}%`}}/></div>
    <p className="speedtest-status" role="status">{running ? event?.phase ? metrics.find(metric=>metric.key===event.phase)?.label : "Connecting" : completedAt ? new Date(completedAt).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}) : ""}</p>
    <div className="speedtest-actions">
      <button className="icon-button speedtest-run" disabled={!speedtestAvailable()} aria-label={action} title={speedtestAvailable() ? action : "Open in Vapour"} onClick={()=>running ? controller.current?.abort() : void start()}>{running ? <Square size={20}/> : completedAt || error ? <RotateCcw size={20}/> : <Play size={20}/>}</button>
    </div>
    <details className="advanced-only"><summary>Measurement</summary><p className="detail-note">HTTP · 10 s per phase</p>{event?.phase && <p className="detail-note">{event.phase} · {event.warmup ? "Warmup" : `${Math.round((event.elapsed_ms || 0) / 1000)} s`}</p>}{serverUrl && <p className="detail-note">{serverUrl}</p>}</details>
    {error && <p role="alert">{error}</p>}
  </section>;
}
