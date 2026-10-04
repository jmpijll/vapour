#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!("Standalone releases must embed their frontend: run pnpm build:native.");

fn main() {
    if std::env::args_os().skip(1).any(|argument| {
        argument == std::ffi::OsStr::new("--vapour-build-info")
    }) {
        let info = serde_json::json!({
            "product": "Vapour",
            "version": env!("CARGO_PKG_VERSION"),
            "architecture": std::env::consts::ARCH,
            "custom_protocol": cfg!(feature = "custom-protocol"),
            "capture_enabled": cfg!(feature = "experimental-capture"),
        });
        println!("{info}");
        return;
    }
    app_lib::run();
}
