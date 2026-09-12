import { isAppHidden } from "../utils/visibility";
import { useCallback, useEffect, useState } from "react";
import type { NetworkSnapshot } from "../types";
import { groupProcesses } from "../utils/processNames";
import { retainSessions } from "../utils/sessionHistory";
import type { Sample } from "../components/History";
const native = "__TAURI_INTERNALS__" in window;

async function command<T>(
  name: string,
  args?: Record<string, unknown>,
): Promise<T | null> {
  if (!native) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(name, args);
}

export function useNetworkTelemetry() {
  const [snapshot, setSnapshot] = useState<NetworkSnapshot | null>(null);
  const [history, setHistory] = useState<Sample[]>([]);
  const [histories, setHistories] = useState<Record<string, Sample[]>>({});
  const [isPinned, setIsPinned] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    let timer: ReturnType<typeof setInterval> | undefined;
    let lastTimestamp = 0;
    const accept = (data: NetworkSnapshot | null) => {
      if (disposed || !data || data.timestamp <= lastTimestamp) return;
      lastTimestamp = data.timestamp;
      setSnapshot((old) => ({
        ...data,
        processes: retainSessions(
          old?.processes || [],
          data.processes,
          data.timestamp,
        ),
      }));
      setError(null);
      setHistories((old) => {
        const values: Record<string, { down: number; up: number }> = {};
        for (const app of groupProcesses(data.processes))
          values["app:" + app.groupKey] = {
            down: app.download_speed_bps,
            up: app.upload_speed_bps,
          };
        for (const i of data.interfaces)
          values["interface:" + i.id] = {
            down: i.download_speed_bps,
            up: i.upload_speed_bps,
          };
        const next: Record<string, Sample[]> = {};
        for (const key of new Set([
          ...Object.keys(old),
          ...Object.keys(values),
        ])) {
          const kept = (old[key] || []).filter(
            (p) => p.time > data.timestamp - 65000,
          );
          if (values[key] || kept.some((p) => p.down || p.up))
            next[key] = [
              ...kept,
              { time: data.timestamp, ...(values[key] || { down: 0, up: 0 }) },
            ];
        }
        return next;
      });
      setHistory((old) => [
        ...old.filter((p) => p.time > data.timestamp - 65000),
        {
          time: data.timestamp,
          down: data.total_download_speed_bps,
          up: data.total_upload_speed_bps,
        },
      ]);
    };
    const refresh = () => {
      if (!isAppHidden() && native)
        command<NetworkSnapshot>("get_network_snapshot")
          .then(accept)
          .catch((e) => {
            if (!disposed) setError(String(e));
          });
    };
    const start = async () => {
      if (native) {
        const { listen } = await import("@tauri-apps/api/event");
        if (disposed) return;
        const stop = await listen<NetworkSnapshot>(
          "network-telemetry",
          (event) => accept(event.payload),
        );
        if (disposed) {
          stop();
          return;
        }
        unlisten = stop;
        refresh();
      } else {
        const { generateMockSnapshot } = await import("../demo/telemetry");
        if (disposed) return;
        const tick = () => {
          if (!isAppHidden()) accept(generateMockSnapshot());
        };
        tick();
        timer = setInterval(tick, 1000);
      }
    };
    start().catch((e) => {
      if (!disposed) setError(String(e));
    });
    document.addEventListener("visibilitychange", refresh);
    return () => {
      disposed = true;
      unlisten?.();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  const togglePin = useCallback(async () => {
    const next = !isPinned;
    try {
      await command("toggle_window_pin", { pinned: next });
      setIsPinned(next);
    } catch (e) {
      setError(String(e));
    }
  }, [isPinned]);
  const hideWindow = useCallback(async () => {
    try {
      await command("hide_flyout");
    } catch (e) {
      setError(String(e));
    }
  }, []);
  return {
    snapshot,
    history,
    histories,
    isPinned,
    error,
    togglePin,
    hideWindow,
  };
}
