import { useCallback, useEffect, useState } from "react";

const invoke = async <T,>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> =>
  (await import("@tauri-apps/api/core")).invoke<T>(command, args);

export type CaptureStatus = {
  active: boolean;
  finalizing: boolean;
  partial?: boolean;
  native_loss_available?: boolean;
  loss_details?: Record<string, number>;
  packets: number;
  bytes: number;
  dropped: number;
  duration_ms: number;
  path: string | null;
  scope_label?: string | null;
  error: string | null;
};
export type CaptureInterface = { id: number; name: string };
export type CaptureSession = { socketId: string; label: string; address: string };
export type CaptureAppTarget = { path: string; label: string };

const idle: CaptureStatus = {
  active: false,
  finalizing: false,
  partial: false,
  packets: 0,
  bytes: 0,
  dropped: 0,
  duration_ms: 0,
  path: null,
  scope_label: null,
  error: null,
};
const native = "__TAURI_INTERNALS__" in window;

export const captureInterfaces = () =>
  native
    ? invoke<CaptureInterface[]>("capture_interfaces")
    : Promise.resolve([]);

export function useCapture() {
  const [sessionState, setSessionState] = useState<CaptureSession | null>(null);
  const [appTarget, setAppTargetState] = useState<CaptureAppTarget | null>(null);
  const [interfaceId, setInterfaceId] = useState<number | null>(null);
  const [status, setStatus] = useState(idle);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    if (native) {
      const value = await invoke<CaptureStatus>("capture_status");
      setStatus({ ...idle, ...value, finalizing: value.finalizing === true });
    }
  }, []);

  useEffect(() => {
    if (!native) return;
    let disposed = false;
    const poll = () => {
      void invoke<CaptureStatus>("capture_status")
        .then((value) => {
          if (!disposed)
            setStatus({ ...idle, ...value, finalizing: value.finalizing === true });
        })
        .catch(() => {});
    };
    poll();
    const timer = setInterval(poll, 1000);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, []);

  const action = async (
    command: string,
    args?: Record<string, unknown>,
  ) => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await invoke(command, args);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const setSession = useCallback((value: CaptureSession | null) => {
    setSessionState(value);
    setAppTargetState(null);
  }, []);
  const selectApp = useCallback((value: CaptureAppTarget) => {
    setSessionState(null);
    setAppTargetState(value);
  }, []);
  const clearTarget = useCallback(() => {
    setSessionState(null);
    setAppTargetState(null);
  }, []);
  const startInterface = (selectedInterfaceId: number) =>
    sessionState
      ? action("start_session_capture", {
          interfaceId: selectedInterfaceId,
          socketId: sessionState.socketId,
        })
      : action("start_capture", { interfaceId: selectedInterfaceId });
  const startApp = () =>
    appTarget
      ? action("start_app_capture", { path: appTarget.path })
      : Promise.resolve();

  return {
    status,
    busy,
    error,
    native,
    interfaceId,
    setInterfaceId,
    session: sessionState,
    setSession,
    appTarget,
    selectApp,
    clearTarget,
    start: startInterface,
    startInterface,
    startApp,
    stop: () => action("stop_capture"),
    save: () => action("save_capture"),
    folder: () => action("open_capture_folder"),
  };
}
export type CaptureControl = ReturnType<typeof useCapture>;
