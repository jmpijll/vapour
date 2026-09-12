use std::{fs::{self, OpenOptions}, io::{Read, Seek, SeekFrom}, sync::{Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};

static RUN: Mutex<Option<(String, std::sync::Arc<AtomicBool>)>> = Mutex::new(None);
const ENGINE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vapour-librespeed.exe"));

#[tauri::command]
pub fn cancel_speedtest(run_id: String) {
    if let Ok(state) = RUN.lock() {
        if let Some((id, cancel)) = state.as_ref() { if *id == run_id { cancel.store(true, Ordering::SeqCst); } }
    }
}

#[tauri::command]
pub fn start_speedtest(app: tauri::AppHandle, mut config: Value) -> Result<(), String> {
    let id = config.get("run_id").and_then(Value::as_str).ok_or("Missing run ID")?.to_owned();
    if id.len() > 80 || id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') { return Err("Invalid run ID".into()); }
    if serde_json::to_vec(&config).map_err(|e|e.to_string())?.len() > 65536 { return Err("Configuration too large".into()); }
    config["duration_ms"] = json!(10000);
    config["parallel"] = json!(4);
    let mut state = RUN.lock().map_err(|e|e.to_string())?;
    if state.is_some() { return Err("A speedtest is already running".into()); }
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let cache = app.path().app_cache_dir().map_err(|e|e.to_string())?.join("speedtest");
    fs::create_dir_all(&cache).map_err(|e|e.to_string())?;
    let hash = format!("{:x}", Sha256::digest(ENGINE));
    let exe = cache.join(format!("engine-{hash}.exe"));
    if !exe.exists() { fs::write(&exe, ENGINE).map_err(|e|e.to_string())?; }
    if Sha256::digest(fs::read(&exe).map_err(|e|e.to_string())?).as_slice() != Sha256::digest(ENGINE).as_slice() { return Err("Speedtest engine verification failed".into()); }
    let config_path = cache.join(format!("{id}.json"));
    let events = cache.join(format!("{id}.jsonl"));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&config_path).map_err(|e|e.to_string())?;
    serde_json::to_writer(&mut file, &config).map_err(|e|e.to_string())?;
    drop(file);
    let process = match crate::speedtest_process::SpeedProcess::start(&exe, &config_path, &events) {
        Ok(p) => p, Err(e) => { let _=fs::remove_file(&config_path); return Err(e); }
    };
    *state = Some((id.clone(), cancel.clone()));
    std::thread::spawn(move || {
        let start = Instant::now(); let mut offset = 0; let mut pending = Vec::<u8>::new(); let mut terminal: Option<Value> = None;
        let result = (|| -> Result<(), String> {
            loop {
                if cancel.load(Ordering::SeqCst) { process.stop(); terminal=Some(json!({"run_id":id,"event":"cancelled"})); break; }
                if start.elapsed() > Duration::from_secs(125) { return Err("Speedtest timed out".into()); }
                let exited = process.exit_code()?;
                if let Ok(mut f) = fs::File::open(&events) {
                    if f.metadata().map_err(|e|e.to_string())?.len() > 2_000_000 { return Err("Engine output limit exceeded".into()); }
                    f.seek(SeekFrom::Start(offset)).map_err(|e|e.to_string())?;
                    let mut bytes=Vec::new(); f.read_to_end(&mut bytes).map_err(|e|e.to_string())?; offset+=bytes.len() as u64;
                    pending.extend_from_slice(&bytes);
                    while let Some(end)=pending.iter().position(|b| *b==b'\n') {
                        let line:Vec<u8>=pending.drain(..=end).collect();
                        let event:Value=serde_json::from_slice(&line).map_err(|e|e.to_string())?;
                        if event["run_id"].as_str()!=Some(id.as_str()) { return Err("Unexpected engine run ID".into()); }
                        if matches!(event["event"].as_str(),Some("complete"|"cancelled"|"error")) {terminal=Some(event);}
                        else { let _=app.emit("speedtest-event",event); }
                    }
                }
                if let Some(code)=exited { if terminal.is_none() {return Err(format!("Speedtest stopped unexpectedly ({code})"));} break; }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        })();
        drop(process);
        if let Err(error)=result { terminal=Some(json!({"run_id":id,"event":"error","error":error})); }
        let _=fs::remove_file(config_path); let _=fs::remove_file(events);
        if let Ok(mut state)=RUN.lock(){*state=None;}
        if let Some(event)=terminal {let _=app.emit("speedtest-event",event);}
    });
    Ok(())
}
