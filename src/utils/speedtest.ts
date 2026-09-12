export type SpeedPhase = "latency" | "jitter" | "download" | "upload";
export type SpeedEvent = {
  run_id: string;
  event: "selected" | "progress" | "phase_complete" | "complete" | "cancelled" | "error";
  phase?: SpeedPhase; warmup?: boolean; elapsed_ms?: number; duration_ms?: number;
  value?: number; server?: { id: number; name: string }; error?: string;
};
export type SpeedValues = Partial<Record<SpeedPhase, number>>;
export function updateSpeedValues(values: SpeedValues, event: SpeedEvent): SpeedValues {
  if (!event.phase || event.warmup || !["progress", "phase_complete"].includes(event.event)
    || typeof event.value !== "number" || !Number.isFinite(event.value) || event.value < 0) return values;
  return {...values, [event.phase]: event.value};
}
export const speedtestAvailable = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
export async function runSpeedtest(signal: AbortSignal, onEvent: (event: SpeedEvent) => void, serverUrl = ""): Promise<void> {
  signal.throwIfAborted();
  if (!speedtestAvailable()) throw new Error("Open Vapour to run a speedtest");
  const [{invoke}, {listen}] = await Promise.all([import("@tauri-apps/api/core"), import("@tauri-apps/api/event")]);
  signal.throwIfAborted();
  const servers = [];
  if (serverUrl.trim()) {
    const url = new URL(serverUrl.trim());
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("Enter an HTTP or HTTPS server URL");
    url.pathname = `${url.pathname.replace(/\/$/, "")}/`;
    servers.push({id:1,name:url.host,server:url.href,dlURL:"garbage.php",ulURL:"empty.php",pingURL:"empty.php"});
  }
  const runId = crypto.randomUUID();
  let finish!: () => void; let fail!: (reason: unknown) => void;
  const completion = new Promise<void>((resolve,reject)=>{finish=resolve;fail=reject;});
  // Attach rejection handling before starting native work or registering cancellation.
  void completion.catch(()=>{});
  const unlisten = await listen<SpeedEvent>("speedtest-event", ({payload})=>{
    if (payload.run_id !== runId) return;
    if (!signal.aborted) onEvent(payload);
    if (payload.event === "complete" || payload.event === "cancelled") finish();
    if (payload.event === "error") fail(new Error(payload.error || "Speedtest failed"));
  });
  const cancel = () => {
    void invoke("cancel_speedtest", {runId}).catch(fail);
  };
  signal.addEventListener("abort",cancel,{once:true});
  try {
    signal.throwIfAborted();
    await invoke("start_speedtest", {config:{run_id:runId,servers,duration_ms:10000,parallel:4}});
    // Cancellation can arrive while the command is crossing IPC, before the run exists.
    if (signal.aborted) cancel();
    await completion;
  } finally {
    signal.removeEventListener("abort",cancel);
    unlisten();
  }
}
