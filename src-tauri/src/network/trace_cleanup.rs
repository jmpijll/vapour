use ferrisetw::trace::stop_trace_by_name;
use windows::Win32::{Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, ERROR_SUCCESS}, System::{Diagnostics::Etw::{QueryAllTracesW, EVENT_TRACE_PROPERTIES}, Threading::{OpenProcess, GetExitCodeProcess, PROCESS_QUERY_LIMITED_INFORMATION}}};

fn owner(name: &str) -> Option<u32> {
    let suffix = name.strip_prefix("Vapour-Network-")?;
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) { return None; }
    suffix.parse().ok().filter(|pid| *pid > 0)
}

// A killed process cannot run Drop. Reclaim only Vapour sessions whose PID no longer exists.
// Access denied or a reused PID is deliberately treated as a live owner.
pub fn cleanup_orphans() {
    #[repr(C)]
    struct Buffer { properties: EVENT_TRACE_PROPERTIES, names: [u16; 2048] }
    let mut buffers: Vec<Box<Buffer>> = (0..128).map(|_| {
        let mut b: Box<Buffer> = Box::new(unsafe { std::mem::zeroed() });
        b.properties.Wnode.BufferSize = std::mem::size_of::<Buffer>() as u32;
        b.properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        b.properties.LogFileNameOffset = b.properties.LoggerNameOffset + 2048;
        b
    }).collect();
    let mut pointers: Vec<_> = buffers.iter_mut().map(|b| &mut b.properties as *mut _).collect();
    let mut count = 0;
    if unsafe { QueryAllTracesW(&mut pointers, &mut count) } != ERROR_SUCCESS { return; }
    for buffer in buffers.iter().take(count as usize) {
        let offset=buffer.properties.LoggerNameOffset as usize;
        if offset < std::mem::size_of::<EVENT_TRACE_PROPERTIES>() || offset % 2 != 0 || offset >= std::mem::size_of::<Buffer>() {continue;}
        let words=unsafe {std::slice::from_raw_parts((buffer.as_ref() as *const Buffer as *const u8).add(offset).cast::<u16>(),(std::mem::size_of::<Buffer>()-offset)/2)};
        let Some(end)=words.iter().position(|v|*v==0) else {continue};
        let Ok(name)=String::from_utf16(&words[..end]) else {continue};
        let Some(pid)=owner(&name) else {continue};
        let dead=match unsafe {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,pid)} {
            Ok(handle)=>{unsafe {let mut code=259;let exited=GetExitCodeProcess(handle,&mut code).is_ok()&&code!=259;let _=CloseHandle(handle);exited}},
            Err(error)=>error.code()==ERROR_INVALID_PARAMETER.to_hresult(),
        };
        if dead { if let Err(error)=stop_trace_by_name(&name) {log::warn!("Cannot reclaim abandoned network trace: {error:?}");} }
    }
}
#[cfg(test)]
mod tests {
 use super::owner;
 #[test] fn only_exact_owned_session_names() {
  assert_eq!(owner("Vapour-Network-123"),Some(123));
  for name in ["NT Kernel Logger","Vapour-Network-0","Vapour-Network--1","Vapour-Network-123 extra","Vapour-Network-","Other-123"] {assert_eq!(owner(name),None);}
 }
}
