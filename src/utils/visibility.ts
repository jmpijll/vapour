// WebView2 does not reliably set document.hidden when its native tray window hides.
let nativeVisible = true;
export const isAppHidden = () => document.hidden || !nativeVisible;
export async function initializeVisibility() {
  if (!("__TAURI_INTERNALS__" in window)) return;
  const { listen } = await import("@tauri-apps/api/event");
  const { invoke } = await import("@tauri-apps/api/core");
  let revision = 0;
  const update = (visible: boolean) => {
    nativeVisible = visible;
    document.dispatchEvent(new Event("visibilitychange"));
  };
  await listen<boolean>("flyout-visibility", event => { revision++; update(event.payload); });
  const initialRevision = revision;
  const visible = await invoke<boolean>("get_flyout_visible");
  if (revision === initialRevision) update(visible);
}
