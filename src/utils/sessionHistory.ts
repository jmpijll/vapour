import type { ProcessTraffic, SocketStream } from "../types";
export function retainSessions(
  previous: ProcessTraffic[],
  incoming: ProcessTraffic[],
  now: number,
): ProcessTraffic[] {
  const key = (p: ProcessTraffic) => `${p.pid}:${p.path.toLowerCase()}`;
  const fresh = new Map(incoming.map((p) => [key(p), p]));
  const result: ProcessTraffic[] = [];
  for (const old of previous) {
    const next = fresh.get(key(old));
    fresh.delete(key(old));
    const sockets = new Map((next?.sockets || []).map((s) => [s.id, s]));
    const merged = old.sockets.flatMap<SocketStream>((s) => {
      const live = sockets.get(s.id);
      sockets.delete(s.id);
      if (live) return [{ ...live, closed_at: undefined }];
      const closed_at = s.closed_at ?? now;
      return now - closed_at < 30000
        ? [
            {
              ...s,
              state: "CLOSED",
              closed_at,
              download_speed_bps: 0,
              upload_speed_bps: 0,
            },
          ]
        : [];
    });
    merged.push(...sockets.values());
    if (next || merged.length)
      result.push({
        ...(next || old),
        sockets: merged,
        download_speed_bps: next?.download_speed_bps ?? 0,
        upload_speed_bps: next?.upload_speed_bps ?? 0,
        active_sockets_count: next?.active_sockets_count ?? 0,
      });
  }
  return [...result, ...fresh.values()];
}
