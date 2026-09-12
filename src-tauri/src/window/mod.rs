use tauri::WebviewWindow;
use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::UI::Shell::{SHAppBarMessage, ABM_GETTASKBARPOS, APPBARDATA};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

pub struct WindowFlyoutManager;

impl WindowFlyoutManager {
    pub fn setup_glass(window: &WebviewWindow) {
        Self::set_appearance(window, true, true);
    }

    pub fn set_appearance(window: &WebviewWindow, dark: bool, transparent: bool) {
        let _ = window_vibrancy::clear_acrylic(window);
        let _ = window_vibrancy::clear_mica(window);
        if transparent {
            let tint = if dark {
                (28, 30, 32, 80)
            } else {
                (248, 249, 250, 80)
            };
            if window_vibrancy::apply_acrylic(window, Some(tint)).is_err() {
                let _ = window_vibrancy::apply_mica(window, Some(dark));
            }
        }
    }

    pub fn position_near_tray(window: &WebviewWindow) {
        if let Ok(size) = window.outer_size() {
            let win_w = size.width as i32;
            let win_h = size.height as i32;

            let (target_x, target_y) = calculate_flyout_coordinates(win_w, win_h);
            let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition {
                x: target_x,
                y: target_y,
            }));
        }
    }
}

fn calculate_flyout_coordinates(win_w: i32, win_h: i32) -> (i32, i32) {
    unsafe {
        let mut abd = APPBARDATA {
            cbSize: std::mem::size_of::<APPBARDATA>() as u32,
            hWnd: HWND(std::ptr::null_mut()),
            uCallbackMessage: 0,
            uEdge: 0,
            rc: RECT::default(),
            lParam: windows::Win32::Foundation::LPARAM(0),
        };

        let result = SHAppBarMessage(ABM_GETTASKBARPOS, &mut abd);
        if result != 0 {
            let tb_rect = abd.rc;
            let edge = abd.uEdge; // 0 = Left, 1 = Top, 2 = Right, 3 = Bottom

            const MARGIN: i32 = 12;

            return match edge {
                3 => {
                    // Taskbar at Bottom
                    let x = (tb_rect.right - win_w - MARGIN).max(MARGIN);
                    let y = (tb_rect.top - win_h - MARGIN).max(MARGIN);
                    (x, y)
                }
                1 => {
                    // Taskbar at Top
                    let x = (tb_rect.right - win_w - MARGIN).max(MARGIN);
                    let y = tb_rect.bottom + MARGIN;
                    (x, y)
                }
                2 => {
                    // Taskbar at Right
                    let x = (tb_rect.left - win_w - MARGIN).max(MARGIN);
                    let y = (tb_rect.bottom - win_h - MARGIN).max(MARGIN);
                    (x, y)
                }
                0 => {
                    // Taskbar at Left
                    let x = tb_rect.right + MARGIN;
                    let y = (tb_rect.bottom - win_h - MARGIN).max(MARGIN);
                    (x, y)
                }
                _ => {
                    let screen_w = GetSystemMetrics(SM_CXSCREEN);
                    let screen_h = GetSystemMetrics(SM_CYSCREEN);
                    (screen_w - win_w - MARGIN, screen_h - win_h - 60)
                }
            };
        }

        // Fallback
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        (screen_w - win_w - 16, screen_h - win_h - 70)
    }
}
