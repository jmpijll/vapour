import {useCallback, useEffect, useRef, useState} from "react";
import {RefreshCw, ShieldCheck} from "lucide-react";
import {isAppHidden} from "../utils/visibility";
const native = "__TAURI_INTERNALS__" in window;
type Status = {
  update_error?:string|null;
  rules: {enabled:boolean; cleanup_pending:boolean; owned_rule_count:number; generation:string|null};
  feed: {refreshing:boolean; available:boolean; stale:boolean; retrieved_at:number|null; endpoint_count:number; last_error:string|null};
};
const demo:Status={rules:{enabled:false,cleanup_pending:false,owned_rule_count:0,generation:null},feed:{refreshing:false,available:false,stale:false,retrieved_at:null,endpoint_count:0,last_error:null}};
export function ThreatProtection({elevated,elevate}:{elevated:boolean;elevate:()=>void}) {
  const [status,setStatus]=useState<Status|null>(native?null:demo);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState<string|null>(null);
  const pending=useRef(false);
  const refreshStatus=useCallback(async()=>{
    if(!native||pending.current)return;
    pending.current=true;
    try {const {invoke}=await import("@tauri-apps/api/core");setStatus(await invoke<Status>("get_threat_protection_status"));}
    catch(e){setError(String(e));}finally{pending.current=false;}
  },[]);
  useEffect(()=>{queueMicrotask(()=>void refreshStatus());const timer=setInterval(()=>{if(!isAppHidden())void refreshStatus();},15000);return()=>clearInterval(timer);},[refreshStatus]);
  const change=async(refreshOnly=false)=>{
    if(busy)return;
    if(!refreshOnly&&!elevated){elevate();return;}
    setBusy(true);setError(null);
    try {
      if(native){const {invoke}=await import("@tauri-apps/api/core");
        if(refreshOnly) await invoke("refresh_threat_feed");
        else setStatus(await invoke<Status>("set_threat_protection",{enabled:!status?.rules.enabled}));
        await refreshStatus();
      } else if(!refreshOnly) setStatus({...demo,rules:{...demo.rules,enabled:!status?.rules.enabled}});
    }catch(e){setError(String(e));await refreshStatus();}finally{setBusy(false);}
  };
  return <div className="threat-protection">
    <div className="setting-row"><h2><ShieldCheck size={15}/> Threat protection</h2><div className="threat-actions">
      <button className="icon-button" aria-label="Refresh threat feed" title="Refresh" disabled={busy||status?.feed.refreshing} onClick={()=>void change(true)}><RefreshCw size={14}/></button>
      <button className="switch" role="switch" aria-label="Threat protection" aria-checked={status?.rules.enabled||false} disabled={busy||!status} onClick={()=>void change()}><span/></button>
    </div></div>
    {(error||status?.update_error||status?.feed.last_error||status?.rules.cleanup_pending||status?.feed.stale)&&<p role="status" className="error-banner">{error||status?.update_error||status?.feed.last_error||(status?.rules.cleanup_pending?"Rule cleanup pending":"Threat feed is out of date")}</p>}
    <div className="advanced-only detail-note">Feodo Tracker{status?.feed.retrieved_at&&<> · {new Date(status.feed.retrieved_at*1000).toLocaleString()}</>} · {status?.rules.owned_rule_count??0} rules</div>
  </div>;
}
