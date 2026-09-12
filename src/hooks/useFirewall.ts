import { isAppHidden } from "../utils/visibility";
import { useCallback, useEffect, useState } from "react";
export type BlockTarget = {
  path: string;
  remote_ip: string | null;
  remote_port: number | null;
  local_ip: string | null;
  local_port: number | null;
  protocol: string | null;
};
export type BlockRule = { id: string; target: BlockTarget };
export const appTarget = (path: string): BlockTarget => ({
  path,
  remote_ip: null,
  remote_port: null,
  local_ip: null,
  local_port: null,
  protocol: null,
});
const native = "__TAURI_INTERNALS__" in window;
export const sameTarget = (a: BlockTarget, b: BlockTarget) =>
  a.path.toLowerCase() === b.path.toLowerCase() &&
  a.remote_ip === b.remote_ip &&
  a.remote_port === b.remote_port &&
  a.local_ip === b.local_ip &&
  a.local_port === b.local_port &&
  a.protocol === b.protocol;
export function useFirewall() {
  const [rules, setRules] = useState<BlockRule[]>([]),
    [busy, setBusy] = useState(false),
    [elevationChecked, setElevationChecked] = useState(!native),
    [elevating, setElevating] = useState(false),
    [error, setError] = useState<string | null>(null),
    [enforcementReason, setEnforcementReason] = useState<string | null>(null),
    [elevated, setElevated] = useState(!native);
  const refresh = useCallback(async () => {
    if (!native) return;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const [list, admin, environment] = await Promise.all([
        invoke<BlockRule[]>("list_blocks"),
        invoke<boolean>("check_elevation").then(admin => { setElevated(admin); setElevationChecked(true); return admin; }),
        invoke<{ enforcing: boolean; reason: string | null }>("get_firewall_environment"),
      ]);
      setRules(list);
      setElevated(admin);
      setEnforcementReason(environment.reason);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);
  useEffect(() => {
    let disposed = false;
    queueMicrotask(() => {
      if (!disposed) void refresh();
    });
    const onVisible = () => { if (!isAppHidden()) void refresh(); };
    document.addEventListener("visibilitychange", onVisible);
    const timer = window.setInterval(onVisible, 30000);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
      disposed = true;
    };
  }, [refresh]);
  const change = async (target: BlockTarget, block: boolean) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      if (native) {
        const { invoke } = await import("@tauri-apps/api/core");
        setRules(await invoke<BlockRule[]>("set_block", { target, block }));
      } else
        setRules((old) =>
          block
            ? [...old, { id: crypto.randomUUID(), target }]
            : old.filter((r) => !sameTarget(r.target, target)),
        );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  const elevate = async () => {
    if (elevating || !native) return;
    setElevating(true);
    setError(null);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("restart_as_administrator");
    } catch (e) {
      setError(String(e));
    } finally {
      setElevating(false);
    }
  };
  return {
    rules,
    busy,
    error,
    elevated,
    elevationChecked,
    elevating,
    enforcementReason,
    refresh,
    change,
    elevate,
    isBlocked: (target: BlockTarget) =>
      rules.some((r) => sameTarget(r.target, target)),
  };
}
