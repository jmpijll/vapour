#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!("Standalone releases must embed their frontend: run pnpm build:native.");

fn main() {
    app_lib::run();
}
