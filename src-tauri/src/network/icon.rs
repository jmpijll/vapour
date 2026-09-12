use base64::prelude::*;
use image::{ImageEncoder, RgbaImage};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Cursor;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, GetObjectW, BITMAP, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HDC,
};
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

pub struct IconExtractor {
    cache: Arc<Mutex<HashMap<String, String>>>,
}

impl IconExtractor {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_icon_data_url(&self, path: &str) -> Option<String> {
        if path.is_empty() {
            return None;
        }

        // Check cache
        if let Some(cached) = self.cache.lock().get(path) {
            return Some(cached.clone());
        }

        let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();

        unsafe {
            let mut shfi = SHFILEINFOW::default();
            let result = SHGetFileInfoW(
                windows::core::PCWSTR(wide_path.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(0),
                Some(&mut shfi),
                std::mem::size_of::<SHFILEINFOW>() as u32,
                SHGFI_ICON | SHGFI_LARGEICON,
            );

            if result == 0 || shfi.hIcon.is_invalid() {
                return None;
            }

            let data_url = icon_to_png_base64(shfi.hIcon);
            let _ = DestroyIcon(shfi.hIcon);

            if let Some(ref url) = data_url {
                self.cache.lock().insert(path.to_string(), url.clone());
            }

            data_url
        }
    }
}

unsafe fn icon_to_png_base64(hicon: HICON) -> Option<String> {
    let mut icon_info = ICONINFO::default();
    if GetIconInfo(hicon, &mut icon_info).is_err() {
        return None;
    }

    let hbm_color = icon_info.hbmColor;
    let hbm_mask = icon_info.hbmMask;

    let target_bmp = if !hbm_color.is_invalid() {
        hbm_color
    } else {
        hbm_mask
    };

    let mut bmp = BITMAP::default();
    if GetObjectW(
        target_bmp,
        std::mem::size_of::<BITMAP>() as i32,
        Some(&mut bmp as *mut _ as *mut _),
    ) == 0
    {
        if !hbm_color.is_invalid() {
            let _ = DeleteObject(hbm_color);
        }
        if !hbm_mask.is_invalid() {
            let _ = DeleteObject(hbm_mask);
        }
        return None;
    }

    let width = bmp.bmWidth as u32;
    let height = bmp.bmHeight.abs() as u32;

    if width == 0 || height == 0 {
        if !hbm_color.is_invalid() {
            let _ = DeleteObject(hbm_color);
        }
        if !hbm_mask.is_invalid() {
            let _ = DeleteObject(hbm_mask);
        }
        return None;
    }

    let hdc_screen: HDC = HDC(std::ptr::null_mut());
    let hdc_mem = CreateCompatibleDC(hdc_screen);

    let mut bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32), // Top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [windows::Win32::Graphics::Gdi::RGBQUAD::default()],
    };

    let mut pixels: Vec<u8> = vec![0u8; (width * height * 4) as usize];
    let lines_copied = GetDIBits(
        hdc_mem,
        target_bmp,
        0,
        height,
        Some(pixels.as_mut_ptr() as *mut _),
        &mut bmi,
        DIB_RGB_COLORS,
    );

    let _ = DeleteDC(hdc_mem);
    if !hbm_color.is_invalid() {
        let _ = DeleteObject(hbm_color);
    }
    if !hbm_mask.is_invalid() {
        let _ = DeleteObject(hbm_mask);
    }

    if lines_copied == 0 {
        return None;
    }

    // Windows DIB returns BGRA; convert to RGBA
    for chunk in pixels.chunks_exact_mut(4) {
        let b = chunk[0];
        let r = chunk[2];
        chunk[0] = r;
        chunk[2] = b;
    }

    let rgba_img = RgbaImage::from_raw(width, height, pixels)?;
    let mut png_bytes = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(Cursor::new(&mut png_bytes));
    if encoder
        .write_image(&rgba_img, width, height, image::ExtendedColorType::Rgba8)
        .is_err()
    {
        return None;
    }

    let b64 = BASE64_STANDARD.encode(&png_bytes);
    Some(format!("data:image/png;base64,{}", b64))
}
