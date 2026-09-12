use crate::capture::{CaptureManager,CaptureStatus,CaptureInterface};
use tauri::{Manager,State};
use std::path::PathBuf;
#[tauri::command]
pub async fn capture_interfaces()->Result<Vec<CaptureInterface>,String>{tauri::async_runtime::spawn_blocking(crate::capture::list_interfaces).await.map_err(|e|e.to_string())?}
#[tauri::command]
pub fn capture_status(state:State<'_,CaptureManager>)->CaptureStatus{state.status()}
fn capture_path(app:&tauri::AppHandle)->Result<PathBuf,String>{
 let directory=app.path().app_cache_dir().map_err(|e|e.to_string())?.join("captures");
 std::fs::create_dir_all(&directory).map_err(|e|e.to_string())?;
 let retained=std::fs::read_dir(&directory).map_err(|e|e.to_string())?.filter_map(Result::ok).filter(|entry|entry.file_name().to_string_lossy().starts_with("Vapour-")&&entry.path().extension().is_some_and(|ext|ext=="pcapng")).count();
 if retained>=8{return Err("Capture storage full. Open the capture folder to save or remove earlier recordings.".into());}
 let stamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
 Ok(directory.join(format!("Vapour-{stamp}.pcapng")))
}
static SESSION_WATCH:parking_lot::Mutex<Option<(u64,String)>>=parking_lot::Mutex::new(None);
#[tauri::command]
pub async fn start_app_capture(app:tauri::AppHandle,path:String)->Result<CaptureStatus,String>{
 let pids={let state=app.state::<crate::AppState>();let latest=state.latest.lock();
  let snapshot=latest.as_ref().ok_or("Apps unavailable")?;
  snapshot.processes.iter().filter(|p|p.path.eq_ignore_ascii_case(&path)).map(|p|p.pid).collect::<Vec<_>>()};
 if path.is_empty()||pids.is_empty(){return Err("App has closed".into());}
 let output=capture_path(&app)?;
 let runtime=app.path().app_cache_dir().map_err(|e|e.to_string())?.join("runtime");
 tauri::async_runtime::spawn_blocking(move||app.state::<CaptureManager>().start_app(output,runtime,path,pids)).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn start_capture(app:tauri::AppHandle,interface_id:u32)->Result<CaptureStatus,String>{
 let path=capture_path(&app)?;
 tauri::async_runtime::spawn_blocking(move||app.state::<CaptureManager>().start(interface_id,path)).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn start_session_capture(app:tauri::AppHandle,interface_id:u32,socket_id:String)->Result<CaptureStatus,String>{
 let socket={
  let state=app.state::<crate::AppState>();let latest=state.latest.lock();let snapshot=latest.as_ref().ok_or("Connections unavailable")?;
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis() as u64;
  if now.saturating_sub(snapshot.timestamp)>3000 {return Err("Connections are updating; try again".into());}
  snapshot.processes.iter().flat_map(|p|&p.sockets).find(|s|s.id==socket_id&&s.protocol=="TCP"&&s.state=="ESTABLISHED").cloned().ok_or("This connection has closed")?
 };
 let target=crate::capture::SessionTarget{local_ip:socket.local_ip,local_port:socket.local_port,remote_ip:socket.remote_ip,remote_port:socket.remote_port,protocol:socket.protocol};
 target.validate()?;
 let path=capture_path(&app)?;
 tauri::async_runtime::spawn_blocking(move||{
  if !crate::network::monitor::established_socket_exists(&socket_id){return Err("This connection has closed".into());}
  let result=app.state::<CaptureManager>().start_session(interface_id,path,target)?;
  *SESSION_WATCH.lock()=Some((result.run_id,socket_id));
  Ok(result)
 }).await.map_err(|e|e.to_string())?
}
// Called on the background sampler, never the window event loop.
pub fn observe_connections(app:&tauri::AppHandle,snapshot:&crate::network::NetworkSnapshot){
 let watch=SESSION_WATCH.lock().clone();
 if let Some((run_id,socket_id))=watch{
  let manager=app.state::<CaptureManager>();let status=manager.status();
  let present=session_present(snapshot,&socket_id);
  if status.run_id!=run_id||!status.active||!present{
   if !present {manager.stop_run(run_id);}
   let mut current=SESSION_WATCH.lock();if current.as_ref().is_some_and(|(id,_)|*id==run_id){*current=None;}
  }
 }
}
#[tauri::command]
pub async fn stop_capture(app:tauri::AppHandle)->Result<CaptureStatus,String>{tauri::async_runtime::spawn_blocking(move||app.state::<CaptureManager>().stop()).await.map_err(|e|e.to_string())}

fn save_dialog(owner:isize,source:PathBuf)->Result<Option<PathBuf>,String>{
 use windows::{core::w,Win32::{Foundation::{HWND,ERROR_CANCELLED},System::Com::*,UI::Shell::{*,Common::COMDLG_FILTERSPEC}}};
 unsafe {
  CoInitializeEx(None,COINIT_APARTMENTTHREADED).ok().map_err(|e|e.to_string())?;
  struct Apartment;impl Drop for Apartment{fn drop(&mut self){unsafe{CoUninitialize();}}}let _apartment=Apartment;
  let dialog:IFileSaveDialog=CoCreateInstance(&FileSaveDialog,None,CLSCTX_INPROC_SERVER).map_err(|e|e.to_string())?;
  dialog.SetFileTypes(&[COMDLG_FILTERSPEC{pszName:w!("PCAPNG"),pszSpec:w!("*.pcapng")}]).map_err(|e|e.to_string())?;
  dialog.SetDefaultExtension(w!("pcapng")).map_err(|e|e.to_string())?;
  dialog.SetFileName(w!("Vapour.pcapng")).map_err(|e|e.to_string())?;
  dialog.SetOptions(FOS_OVERWRITEPROMPT|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST|FOS_NOCHANGEDIR).map_err(|e|e.to_string())?;
  if let Err(e)=dialog.Show(HWND(owner as *mut _)){if e.code()==ERROR_CANCELLED.to_hresult(){return Ok(None);}return Err(e.to_string());}
  let destination=dialog.GetResult().and_then(|item|item.GetDisplayName(SIGDN_FILESYSPATH)).map_err(|e|e.to_string())?;
  let path=destination.to_string();CoTaskMemFree(Some(destination.0.cast()));
  let path=PathBuf::from(path.map_err(|e|e.to_string())?);
  if path!=source {std::fs::copy(&source,&path).map_err(|e|e.to_string())?;}
  Ok(Some(path))
 }
}
#[tauri::command]
pub async fn save_capture(app:tauri::AppHandle,window:tauri::WebviewWindow)->Result<(),String>{
 let state=app.state::<CaptureManager>().status();
 if state.active{return Err("Stop capture before saving".into());}
 let source=PathBuf::from(state.path.ok_or("No capture to save")?);
 let owner=window.hwnd().map_err(|e|e.to_string())?.0 as isize;
 let was_pinned=app.state::<crate::AppState>().is_pinned.swap(true,std::sync::atomic::Ordering::SeqCst);
 let (send,receive)=tokio::sync::oneshot::channel();
 let source_copy=source.clone();
 let worker=std::thread::spawn(move||{let _=send.send(save_dialog(owner,source_copy));});
 let result=receive.await.map_err(|e|e.to_string());
 app.state::<crate::AppState>().is_pinned.store(was_pinned,std::sync::atomic::Ordering::SeqCst);
 let _=worker.join();
 if let Some(destination)=result?? {
  if destination!=source {std::fs::remove_file(&source).map_err(|e|e.to_string())?;}
  app.state::<CaptureManager>().exported(&source);
 }
 Ok(())
}

#[tauri::command]
pub fn open_capture_folder(app:tauri::AppHandle)->Result<(),String>{
 let directory=app.path().app_cache_dir().map_err(|e|e.to_string())?.join("captures");
 std::fs::create_dir_all(&directory).map_err(|e|e.to_string())?;
 std::process::Command::new("explorer.exe").arg(directory).spawn().map_err(|e|e.to_string())?;Ok(())
}

fn session_present(snapshot:&crate::network::NetworkSnapshot,id:&str)->bool{
 snapshot.processes.iter().flat_map(|p|&p.sockets).any(|s|s.id==id&&s.protocol=="TCP"&&s.state=="ESTABLISHED")
}
#[cfg(test)]
mod session_watch_tests {
 use super::*;
 #[test] fn only_the_same_live_connection_keeps_recording(){
  let mut snapshot:crate::network::NetworkSnapshot=serde_json::from_value(serde_json::json!({"measurement_status":"measured","timestamp":0,"total_download_speed_bps":0,"total_upload_speed_bps":0,"total_active_connections":1,"interfaces":[],"processes":[{"pid":1,"name":"fixture","path":"fixture.exe","icon_data_url":null,"download_speed_bps":0,"upload_speed_bps":0,"total_bytes_received":0,"total_bytes_sent":0,"active_sockets_count":1,"is_blocked":false,"is_system":false,"has_external_traffic":true,"has_unencrypted_traffic":false,"sockets":[{"id":"chosen","protocol":"TCP","state":"ESTABLISHED","local_ip":"192.0.2.1","local_port":1234,"remote_ip":"192.0.2.2","remote_port":443,"is_tls":true,"is_local":false,"is_muted":false,"download_speed_bps":0,"upload_speed_bps":0}]}]})).unwrap();
  assert!(session_present(&snapshot,"chosen"));assert!(!session_present(&snapshot,"other"));
  snapshot.processes[0].sockets[0].state="TIME_WAIT".into();assert!(!session_present(&snapshot,"chosen"));
  snapshot.processes[0].sockets.clear();assert!(!session_present(&snapshot,"chosen"));
 }
}
