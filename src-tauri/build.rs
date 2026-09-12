use std::{env, path::PathBuf, process::Command};
fn main() {
    let source = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../sidecar/librespeed");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=GO_BIN");
    let go = env::var_os("GO_BIN").unwrap_or_else(|| "go".into());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("vapour-librespeed.exe");
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {"x86_64"=>"amd64", "aarch64"=>"arm64", _=>panic!("Unsupported speedtest target")};
    let status = Command::new(go).current_dir(source).env("CGO_ENABLED", "0").env("GOOS", "windows").env("GOARCH", arch)
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"]).arg(output).arg(".").status().expect("Install Go or set GO_BIN to the Go executable");
    assert!(status.success(), "LibreSpeed engine build failed");
    tauri_build::build()
}
