#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!("Standalone releases must embed their frontend: run pnpm build:native.");

fn main() {
    if let Some(code) = app_lib::run_internal_cli() {
        std::process::exit(code);
    }
    app_lib::run();
}
