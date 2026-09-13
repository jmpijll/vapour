//! Passive WinDivert collection; no send/reinjection symbol is loaded.
use super::attribution::{Event,EventKind,Flow,Identity};
use std::{collections::HashMap,ffi::{c_void,c_char,CString,CStr},net::{IpAddr,SocketAddr},path::Path,sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering},mpsc::{self,SyncSender}},thread::{self,JoinHandle},time::{Duration,Instant}};
type Handle=*mut c_void;
#[repr(C)] #[derive(Clone,Copy)] struct Address {timestamp:i64,bits:u32,reserved:u32,data:[u8;64]}
impl Default for Address {fn default()->Self{Self{timestamp:0,bits:0,reserved:0,data:[0;64]}}}
type Open=unsafe extern "C" fn(*const c_char,i32,i16,u64)->Handle;
type Recv=unsafe extern "C" fn(Handle,*mut c_void,u32,*mut u32,*mut Address)->i32;
type Shutdown=unsafe extern "C" fn(Handle,u32)->i32;
type Close=unsafe extern "C" fn(Handle)->i32;
type Param=unsafe extern "C" fn(Handle,i32,u64)->i32;
type Format=unsafe extern "C" fn(*const u32,*mut c_char,u32)->i32;
#[link(name="kernel32")] extern "system" {
 fn LoadLibraryExW(path:*const u16,file:Handle,flags:u32)->Handle;
 fn GetProcAddress(module:Handle,name:*const u8)->*mut c_void;
 fn FreeLibrary(module:Handle)->i32;
 fn GetLastError()->u32;
 fn QueryPerformanceCounter(value:*mut i64)->i32;
 fn QueryPerformanceFrequency(value:*mut i64)->i32;
 fn GetSystemTimeAsFileTime(value:*mut u64);
}
struct Api {module:usize,open:Open,recv:Recv,shutdown:Shutdown,close:Close,param:Param,format:Format}
impl Drop for Api{fn drop(&mut self){if self.module!=0{unsafe{FreeLibrary(self.module as Handle);}}}}
impl Api {
 fn load(path:&Path)->Result<Arc<Self>,String>{
  if !path.is_absolute(){return Err("Capture library path must be absolute".into());}
  let wide:Vec<_>=path.as_os_str().encode_wide().chain(Some(0)).collect();
  use std::os::windows::ffi::OsStrExt;
  let module=unsafe{LoadLibraryExW(wide.as_ptr(),std::ptr::null_mut(),0x100|0x800)};
  if module.is_null(){return Err(format!("Capture library could not load ({})",unsafe{GetLastError()}));}
  unsafe fn symbol(module:Handle,name:&[u8])->Result<*mut c_void,String>{let p=GetProcAddress(module,name.as_ptr());if p.is_null(){Err("Capture library is missing an entry point".into())}else{Ok(p)}}
  let result=(||unsafe{Ok(Self{module:module as usize,open:std::mem::transmute::<*mut c_void,Open>(symbol(module,b"WinDivertOpen\0")?),recv:std::mem::transmute::<*mut c_void,Recv>(symbol(module,b"WinDivertRecv\0")?),shutdown:std::mem::transmute::<*mut c_void,Shutdown>(symbol(module,b"WinDivertShutdown\0")?),close:std::mem::transmute::<*mut c_void,Close>(symbol(module,b"WinDivertClose\0")?),param:std::mem::transmute::<*mut c_void,Param>(symbol(module,b"WinDivertSetParam\0")?),format:std::mem::transmute::<*mut c_void,Format>(symbol(module,b"WinDivertHelperFormatIPv6Address\0")?)})})();
  if result.is_err(){unsafe{FreeLibrary(module);}}result.map(Arc::new)
 }
}
enum Message {Packet(i64,Vec<u8>),Metadata(Address)}
static BROKEN:AtomicBool=AtomicBool::new(false);
struct NativeHandle {value:std::sync::Mutex<usize>,api:Arc<Api>}
impl NativeHandle {
 fn shutdown(&self){let h=self.value.lock().unwrap_or_else(|e|e.into_inner());if *h!=0{unsafe{(self.api.shutdown)(*h as Handle,1);}}}
 fn close(&self){let mut h=self.value.lock().unwrap_or_else(|e|e.into_inner());if *h!=0{unsafe{(self.api.close)(*h as Handle);}*h=0;}}
}
struct CloseOnExit(Arc<NativeHandle>);
impl Drop for CloseOnExit{fn drop(&mut self){self.0.close();}}
struct Reader {handle:Arc<NativeHandle>,worker:Option<JoinHandle<()>>}
impl Reader {fn shutdown(&self){self.handle.shutdown();}
 fn finish(&mut self)->Result<(),String>{self.finish_with_timeout(Duration::from_secs(2))}
 fn finish_with_timeout(&mut self,timeout:Duration)->Result<(),String>{
  self.shutdown();
  if let Some(worker)=self.worker.take(){
   let deadline=Instant::now()+timeout;
   while !worker.is_finished()&&Instant::now()<deadline{thread::sleep(Duration::from_millis(5));}
   if !worker.is_finished(){BROKEN.store(true,Ordering::Release);return Err("Capture driver did not stop; recording discarded. Restart Vapour before recording again.".into());}
   if worker.join().is_err(){return Err("Capture reader failed".into());}
  }
  Ok(())
 }}
impl Drop for Reader {fn drop(&mut self){if self.worker.is_some(){let _=self.finish();}}}
pub struct Collection {pub packets:Vec<(i64,Vec<u8>)>,pub events:Vec<Event>,pub qpc_frequency:u64,pub qpc_anchor:i64,pub filetime_anchor:i64}
fn bounded_seconds(value:u64)->u64{value.clamp(1,60)}
fn identity(pid:u32)->Option<Identity>{
 use windows::Win32::{Foundation::{CloseHandle,FILETIME},System::Threading::*};
 unsafe{let h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,pid).ok()?;let(mut c,mut e,mut k,mut u)=(FILETIME::default(),FILETIME::default(),FILETIME::default(),FILETIME::default());let ok=GetProcessTimes(h,&mut c,&mut e,&mut k,&mut u).is_ok();let _=CloseHandle(h);ok.then_some(Identity{pid,creation_time_100ns:((c.dwHighDateTime as u64)<<32)|c.dwLowDateTime as u64})}
}
fn qpc_to_filetime(qpc:i64,anchor:i64,filetime:i64,frequency:u64)->Option<u64>{
 if frequency==0{return None;}
 let value=filetime as i128+(qpc as i128-anchor as i128)*10_000_000/frequency as i128;
 u64::try_from(value).ok()
}
fn identity_is_valid_at(owner:Identity,event_qpc:i64,anchor:i64,filetime:i64,frequency:u64)->bool{
 owner.creation_time_100ns!=0&&event_qpc>=0&&qpc_to_filetime(event_qpc,anchor,filetime,frequency).is_some_and(|event_time|owner.creation_time_100ns<=event_time)
}
fn ip(api:&Api,data:&[u8])->Option<IpAddr>{
 let mut words=[0u32;4];for(i,w)in words.iter_mut().enumerate(){*w=u32::from_ne_bytes(data.get(i*4..i*4+4)?.try_into().ok()?);}
 let mut out=[0i8;128];if unsafe{(api.format)(words.as_ptr(),out.as_mut_ptr(),128)}==0{return None;}
 let value:IpAddr=unsafe{CStr::from_ptr(out.as_ptr())}.to_str().ok()?.parse().ok()?;
 Some(match value {IpAddr::V6(v)=>v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),other=>other})
}
fn event(api:&Api,address:Address,cache:&mut HashMap<(u64,u32),Identity>,anchor:i64,filetime:i64,frequency:u64)->Option<Event>{
 let layer=address.bits&255;let kind=match(layer,(address.bits>>8)&255){(2,1)=>EventKind::Established,(2,2)=>EventKind::Deleted,(3,4)=>EventKind::Connect,(3,6)=>EventKind::Accept,(3,7)=>EventKind::Close,_=>return None};
 let d=address.data;let endpoint=u64::from_ne_bytes(d[0..8].try_into().ok()?);let pid=u32::from_ne_bytes(d[16..20].try_into().ok()?);
 let local=SocketAddr::new(ip(api,&d[20..36])?,u16::from_ne_bytes(d[52..54].try_into().ok()?));
 let remote=SocketAddr::new(ip(api,&d[36..52])?,u16::from_ne_bytes(d[54..56].try_into().ok()?));
 if !matches!(d[56],6|17)||local.port()==0||remote.port()==0||local.ip().is_unspecified()||remote.ip().is_unspecified(){return None;}
 let current=identity(pid).filter(|owner|identity_is_valid_at(*owner,address.timestamp,anchor,filetime,frequency));
 // Only endpoint-bound closure evidence may use an identity recorded while alive.
 let owner=current.or_else(||matches!(kind,EventKind::Close|EventKind::Deleted).then(||cache.get(&(endpoint,pid)).copied()).flatten().filter(|owner|identity_is_valid_at(*owner,address.timestamp,anchor,filetime,frequency))).unwrap_or(Identity{pid,creation_time_100ns:0});
 if owner.creation_time_100ns!=0{cache.insert((endpoint,pid),owner);}
 Some(Event{timestamp_qpc:address.timestamp,endpoint_id:endpoint,owner,flow:Flow{protocol:d[56],local,remote},kind})
}
pub fn collect(dll:&Path,cancel:&AtomicBool,max_seconds:u64,ready:SyncSender<Result<(),String>>,diagnostics:&mut super::CaptureLossDetails)->Result<Collection,String>{
 if BROKEN.load(Ordering::Acquire){return Err("Restart Vapour after the previous capture shutdown failure".into());}
 let api=Api::load(dll)?;let mut frequency=0;let mut anchor=0;let mut filetime=0u64;
 unsafe{if QueryPerformanceFrequency(&mut frequency)==0||frequency<=0||QueryPerformanceCounter(&mut anchor)==0{return Err("Capture clock unavailable".into());}GetSystemTimeAsFileTime(&mut filetime);}
 let(tx,rx)=mpsc::sync_channel(4096);let failed=Arc::new(AtomicBool::new(false));let budget=Arc::new(AtomicUsize::new(0));let packet_count=Arc::new(AtomicUsize::new(0));
 let queue_full=Arc::new(AtomicUsize::new(0));let size_limit=Arc::new(AtomicUsize::new(0));
 let mut readers=Vec::new();
 for layer in [2,3,0] {
  let filter=CString::new(if layer==0{"tcp or udp"}else{"true"}).unwrap();let handle=unsafe{(api.open)(filter.as_ptr(),layer,0,5)};
  if handle.is_null()||handle as usize==usize::MAX{return Err(format!("App capture requires administrator access and a working WinDivert driver ({})",unsafe{GetLastError()}));}
  let mut configured=true;for(param,value)in [(0,4096),(1,2000),(2,8*1024*1024)]{if unsafe{(api.param)(handle,param,value)}==0{configured=false;}}
  if !configured{unsafe{(api.close)(handle);}return Err("Capture queue configuration failed".into());}
  let full=queue_full.clone();let limit=size_limit.clone();
  let h=handle as usize;let module=api.clone();let send=tx.clone();let failure=failed.clone();let memory=budget.clone();let count=packet_count.clone();
  let native_handle=Arc::new(NativeHandle{value:std::sync::Mutex::new(h),api:api.clone()});
  let worker_handle=native_handle.clone();
  let worker=thread::Builder::new().name(format!("vapour-divert-{layer}")).spawn(move||{
   let _close=CloseOnExit(worker_handle);
   let mut bytes=vec![0u8;65575];
   loop{let mut address=Address::default();let mut length=0u32;
    let ok=unsafe{(module.recv)(h as Handle,if layer==0{bytes.as_mut_ptr().cast()}else{std::ptr::null_mut()},if layer==0{bytes.len() as u32}else{0},&mut length,&mut address)};
    if ok==0 {if unsafe{GetLastError()}!=232{failure.store(true,Ordering::Release);}break;}
    let message=if layer==0{
     let len=length as usize;
     if len>bytes.len()||len==0||memory.fetch_add(len,Ordering::AcqRel).saturating_add(len)>32*1024*1024||count.fetch_add(1,Ordering::AcqRel)>=20_000{limit.fetch_add(1,Ordering::Relaxed);failure.store(true,Ordering::Release);continue;}
     Message::Packet(address.timestamp,bytes[..len].to_vec())
    }else{Message::Metadata(address)};
    if send.try_send(message).is_err(){full.fetch_add(1,Ordering::Relaxed);failure.store(true,Ordering::Release);}
   }
  }).map_err(|e|{unsafe{(api.close)(handle);}e.to_string()})?;
  readers.push(Reader{handle:native_handle,worker:Some(worker)});
 }
 drop(tx);let _=ready.send(Ok(()));
 let mut result=Collection{packets:Vec::new(),events:Vec::new(),qpc_frequency:frequency as u64,qpc_anchor:anchor,filetime_anchor:filetime as i64};let mut cache=HashMap::new();let started=Instant::now();
 let mut receive=|message|->Result<(),String>{match message{Message::Packet(at,bytes)=>result.packets.push((at,bytes)),Message::Metadata(address)=>{
  if result.events.len()>=20_000{return Err("Capture metadata limit reached".into());}
  if let Some(e)=event(&api,address,&mut cache,anchor,filetime as i64,frequency as u64){result.events.push(e);}
 }}Ok(())};
 let mut processing_error=None;
 while !cancel.load(Ordering::Acquire)&&started.elapsed()<Duration::from_secs(bounded_seconds(max_seconds))&&!failed.load(Ordering::Acquire){
  match rx.recv_timeout(Duration::from_millis(20)){Ok(message)=>if let Err(e)=receive(message){processing_error=Some(e);break;},Err(mpsc::RecvTimeoutError::Timeout)=>{},Err(_)=>break}
 }
 // Stop every producer before waiting, then consume the final queued messages.
 for reader in &readers{reader.shutdown();}
 for reader in &mut readers{reader.finish()?;}
 for message in rx.try_iter(){if let Err(e)=receive(message){processing_error=Some(e);break;}}
 diagnostics.queue_full=queue_full.load(Ordering::Acquire) as u64;
 diagnostics.size_limit=size_limit.load(Ordering::Acquire) as u64 + u64::from(processing_error.is_some());
 if let Some(error)=processing_error{return Err(error);}
 if failed.load(Ordering::Acquire){return Err("Capture lost data or reached its memory limit; recording discarded".into());}
 Ok(result)
}
#[cfg(test)]mod tests{use super::super::attribution::Identity;#[test]fn max_seconds_is_bounded(){assert_eq!(super::bounded_seconds(90),60);assert_eq!(super::bounded_seconds(0),1);}#[test]fn address_abi_matches_native(){assert_eq!(std::mem::size_of::<super::Address>(),80);}#[test]fn qpc_identity_check_rejects_a_pid_created_after_the_event(){let owner=Identity{pid:7,creation_time_100ns:999};assert!(super::identity_is_valid_at(owner,100,100,1_000,10_000_000));assert!(!super::identity_is_valid_at(owner,98,100,1_000,10_000_000));assert!(!super::identity_is_valid_at(Identity{creation_time_100ns:1_001,..owner},100,100,1_000,10_000_000));}}

#[cfg(test)] mod lifecycle_tests {
 use super::*;
 static CLOSES:AtomicUsize=AtomicUsize::new(0);
 unsafe extern "C" fn open(_: *const c_char,_:i32,_:i16,_:u64)->Handle{1usize as Handle}
 unsafe extern "C" fn recv(_:Handle,_:*mut c_void,_:u32,_:*mut u32,_:*mut Address)->i32{0}
 unsafe extern "C" fn shutdown(_:Handle,_:u32)->i32{1}
 unsafe extern "C" fn close(_:Handle)->i32{CLOSES.fetch_add(1,Ordering::SeqCst);1}
 unsafe extern "C" fn param(_:Handle,_:i32,_:u64)->i32{1}
 unsafe extern "C" fn format(_:*const u32,_:*mut c_char,_:u32)->i32{0}
 #[test] fn stalled_worker_keeps_handle_alive_until_receive_exits(){
  CLOSES.store(0,Ordering::SeqCst);
  let api=Arc::new(Api{module:0,open,recv,shutdown,close,param,format});
  let handle=Arc::new(NativeHandle{value:std::sync::Mutex::new(123),api});
  let child=handle.clone();let(tx,rx)=mpsc::channel();
  let worker=thread::spawn(move||{let _close=CloseOnExit(child);let _=rx.recv();});
  let mut reader=Reader{handle,worker:Some(worker)};
  let started=Instant::now();assert!(reader.finish_with_timeout(Duration::from_millis(10)).is_err());
  assert!(started.elapsed()<Duration::from_secs(1));assert_eq!(CLOSES.load(Ordering::SeqCst),0);
  tx.send(()).unwrap();let deadline=Instant::now()+Duration::from_secs(1);
  while CLOSES.load(Ordering::SeqCst)==0&&Instant::now()<deadline{thread::sleep(Duration::from_millis(1));}
  assert_eq!(CLOSES.load(Ordering::SeqCst),1);BROKEN.store(false,Ordering::Release);
 }
}
