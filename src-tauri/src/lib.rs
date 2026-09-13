use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State,
};

pub mod firewall;
pub mod network;
pub mod protection;
pub mod window;

use firewall::FirewallManager;
use network::{NetworkMonitor, NetworkSnapshot};
use window::WindowFlyoutManager;

use parking_lot::Mutex;

pub struct AppState {
    pub monitor: Arc<NetworkMonitor>,
    pub latest: Mutex<Option<NetworkSnapshot>>,
    pub is_pinned: AtomicBool,
    pub tray: Mutex<Option<tauri::tray::TrayIcon>>,
}

#[tauri::command]
async fn get_threat_protection_status(controller: State<'_, protection::controller::ProtectionController>) -> Result<protection::controller::ProtectionStatus, String> {
    let controller=controller.inner().clone();
    tauri::async_runtime::spawn_blocking(move || controller.status()).await.map_err(|e|e.to_string())?
}
#[tauri::command]
async fn set_threat_protection(controller: State<'_, protection::controller::ProtectionController>, enabled: bool) -> Result<protection::controller::ProtectionStatus, String> {
    let controller=controller.inner().clone();
    tauri::async_runtime::spawn_blocking(move || controller.set_enabled(enabled)).await.map_err(|e|e.to_string())?
}

#[tauri::command]
fn get_threat_feed_status(updater: State<'_, protection::updater::FeedUpdater>) -> protection::updater::UpdateStatus {
    updater.status()
}

#[tauri::command]
async fn refresh_threat_feed(controller: State<'_, protection::controller::ProtectionController>) -> Result<protection::controller::ProtectionStatus, String> {
    let controller=controller.inner().clone();
    tauri::async_runtime::spawn_blocking(move || controller.refresh()).await.map_err(|e|e.to_string())?
}

#[tauri::command]
fn get_network_snapshot(state: State<'_, AppState>) -> Option<NetworkSnapshot> {
    state.latest.lock().clone()
}

#[tauri::command]
fn set_stream_muted(state: State<'_, AppState>, stream_id: String, muted: bool) {
    state.monitor.set_stream_muted(stream_id, muted);
}

#[tauri::command]
fn toggle_window_pin(
    state: State<'_, AppState>,
    window: tauri::WebviewWindow,
    pinned: bool,
) -> bool {
    state.is_pinned.store(pinned, Ordering::SeqCst);
    let _ = window.set_always_on_top(pinned);
    pinned
}

#[tauri::command]
fn get_flyout_visible(window: tauri::WebviewWindow) -> bool {
    window.is_visible().unwrap_or(false)
}

#[tauri::command]
fn hide_flyout(window: tauri::WebviewWindow) {
    if window.hide().is_ok() {
        let _ = window.emit("flyout-visibility", false);
    }
}

#[tauri::command]
fn set_appearance(window: tauri::WebviewWindow, dark: bool, transparent: bool) {
    WindowFlyoutManager::set_appearance(&window, dark, transparent);
}

#[tauri::command]
fn check_elevation() -> bool {
    FirewallManager::is_elevated()
}

#[tauri::command]
async fn get_firewall_environment() -> Result<firewall::FirewallEnvironment, String> {
    tauri::async_runtime::spawn_blocking(FirewallManager::environment)
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn list_blocks(app: tauri::AppHandle) -> Result<Vec<firewall::BlockRule>, String> {
    let file = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("blocks-v2.json");
    tauri::async_runtime::spawn_blocking(move || firewall::RuleStore::new(file).list())
        .await
        .map_err(|e| e.to_string())?
}
static FIREWALL_WRITE: Mutex<()> = Mutex::new(());
#[tauri::command]
async fn set_block(
    app: tauri::AppHandle,
    target: firewall::BlockTarget,
    block: bool,
) -> Result<Vec<firewall::BlockRule>, String> {
    let file = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("blocks-v2.json");
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = FIREWALL_WRITE.lock();
        firewall::RuleStore::new(file).change(target, block)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn restart_as_administrator(app: tauri::AppHandle) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    if cfg!(debug_assertions) || !cfg!(feature = "custom-protocol") {
        return Err("Use the standalone release preview to restart as administrator.".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path: Vec<u16> = exe
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize <= 32 {
        return Err("Administrator restart was cancelled or unavailable.".into());
    }
    app.state::<protection::controller::ProtectionController>().stop();
    app.state::<capture::CaptureManager>().stop();
    app.state::<AppState>().monitor.stop();
    app.exit(0);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let monitor = Arc::new(NetworkMonitor::new());
    let state = AppState {
        monitor: Arc::clone(&monitor),
        latest: Mutex::new(None),
        is_pinned: AtomicBool::new(false),
        tray: Mutex::new(None),
    };

    tauri::Builder::default()
        .manage(capture::CaptureManager::default())
        .manage(state)
        .setup(move |app| {
            let feed_updater=protection::updater::FeedUpdater::new(
                app.path().app_data_dir()?.join("protection").join("feodo-v1.json"),
            );
            app.manage(protection::controller::ProtectionController::new(feed_updater.clone(), app.path().app_data_dir()?.join("protection").join("threat-protection-intent.json")));
            app.manage(feed_updater);
            app.state::<protection::controller::ProtectionController>().start_updates()?;
            let handle = app.handle();

            // Load embedded icon
            let icon_bytes = include_bytes!("../icons/32x32.png");
            let decoded = image::load_from_memory(icon_bytes)
                .expect("decode png")
                .to_rgba8();
            let (width, height) = decoded.dimensions();
            let icon = tauri::image::Image::new_owned(decoded.into_raw(), width, height);

            // Setup main window
            if let Some(main_window) = handle.get_webview_window("main") {
                let _ = main_window.set_icon(icon.clone());
                WindowFlyoutManager::setup_glass(&main_window);
                let _ = main_window.center();
                let _ = main_window.show();
                let _ = main_window.set_focus();
            } else {
                println!("WARNING: get_webview_window('main') returned NONE!");
            }

            // Setup Tray Menu
            let toggle_item =
                MenuItem::with_id(handle, "toggle", "Toggle Vapour", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(handle, "quit", "Exit Vapour", true, None::<&str>)?;
            let tray_menu = Menu::with_items(handle, &[&toggle_item, &quit_item])?;

            let tray = TrayIconBuilder::with_id("main-tray")
                .icon(icon)
                .tooltip("Vapour - Live Telemetry")
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    if event.id.as_ref() == "quit" {
                        app.state::<protection::controller::ProtectionController>().stop();
    app.state::<capture::CaptureManager>().stop();
                        app.state::<AppState>().monitor.stop();
                        app.exit(0);
                    } else if event.id.as_ref() == "toggle" {
                        if let Some(window) = app.get_webview_window("main") {
                            if let Ok(is_visible) = window.is_visible() {
                                if is_visible {
                                    if window.hide().is_ok() {
                                        let _ = window.emit("flyout-visibility", false);
                                    }
                                } else {
                                    WindowFlyoutManager::position_near_tray(&window);
                                    if window.show().is_ok() {
                                        let _ = window.emit("flyout-visibility", true);
                                    }
                                    let _ = window.set_focus();
                                }
                            }
                        }
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            if let Ok(is_visible) = window.is_visible() {
                                if is_visible {
                                    let state: State<AppState> = app.state();
                                    if !state.is_pinned.load(Ordering::SeqCst) {
                                        if window.hide().is_ok() {
                                            let _ = window.emit("flyout-visibility", false);
                                        }
                                    }
                                } else {
                                    WindowFlyoutManager::position_near_tray(&window);
                                    if window.show().is_ok() {
                                        let _ = window.emit("flyout-visibility", true);
                                    }
                                    let _ = window.set_focus();
                                }
                            }
                        }
                    }
                })
                .build(handle)?;

            // Store tray in AppState so it is never dropped while process runs
            let state_holder: State<AppState> = handle.state();
            *state_holder.tray.lock() = Some(tray);

            // Background telemetry polling task
            let monitor_clone = Arc::clone(&monitor);
            let handle_clone = handle.clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let worker = Arc::clone(&monitor_clone);
                    let capture_app = handle_clone.clone();
                    if let Ok(snapshot) =
                        tauri::async_runtime::spawn_blocking(move || {let snapshot=worker.capture_snapshot();capture_commands::observe_connections(&capture_app,&snapshot);snapshot})
                            .await
                    {
                        handle_clone
                            .state::<AppState>()
                            .latest
                            .lock()
                            .replace(snapshot.clone());
                        if handle_clone
                            .get_webview_window("main")
                            .is_some_and(|win| win.is_visible().unwrap_or(false))
                        {
                            let _ = handle_clone.emit("network-telemetry", &snapshot);
                        }
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                window.state::<protection::controller::ProtectionController>().stop();
                window.state::<capture::CaptureManager>().stop();
                window.state::<AppState>().monitor.stop();
            }
            if let tauri::WindowEvent::Focused(false) = event {
                if !window.state::<AppState>().is_pinned.load(Ordering::SeqCst) {
                    if window.hide().is_ok() {
                        let _ = window.emit("flyout-visibility", false);
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            capture_commands::capture_interfaces,
            capture_commands::capture_status,
            capture_commands::start_capture,
            capture_commands::start_session_capture,
            capture_commands::start_app_capture,
            capture_commands::stop_capture,
            capture_commands::save_capture,
            capture_commands::open_capture_folder,
            speedtest::start_speedtest,
            speedtest::cancel_speedtest,
            get_network_snapshot,
            set_stream_muted,
            toggle_window_pin,
            hide_flyout,
            get_flyout_visible,
            check_elevation,
            set_appearance,
            list_blocks,
            get_firewall_environment,
            get_threat_protection_status,
            set_threat_protection,
            get_threat_feed_status,
            refresh_threat_feed,
            set_block,
            restart_as_administrator
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
pub mod speedtest_process;
mod speedtest;

pub mod capture;
mod capture_commands;
