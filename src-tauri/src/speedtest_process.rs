use std::{os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle}, path::Path};
use windows::{core::{PCWSTR,PWSTR}, Win32::{Foundation::HANDLE, Security::*, System::{Threading::*, JobObjects::*}, UI::WindowsAndMessaging::{GetShellWindow,GetWindowThreadProcessId}}};

pub struct SpeedProcess { handle: OwnedHandle, _job: OwnedHandle }
fn managed(handle: OwnedHandle) -> Result<SpeedProcess, String> {
    let result = unsafe {
        (|| -> windows::core::Result<OwnedHandle> {
            let job = OwnedHandle::from_raw_handle(CreateJobObjectW(None, PCWSTR::null())?.0);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(HANDLE(job.as_raw_handle()), JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of_val(&limits) as u32)?;
            AssignProcessToJobObject(HANDLE(job.as_raw_handle()), HANDLE(handle.as_raw_handle()))?;
            Ok(job)
        })()
    };
    match result {
        Ok(job) => Ok(SpeedProcess {handle, _job:job}),
        Err(error) => { unsafe { let _=TerminateProcess(HANDLE(handle.as_raw_handle()),1); WaitForSingleObject(HANDLE(handle.as_raw_handle()),5000); } Err(format!("Cannot contain speedtest process: {error}")) }
    }
}
impl SpeedProcess {
    pub fn start(exe:&Path, config:&Path, events:&Path)->Result<Self,String> {
        let wide=|s:&str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let application=wide(&exe.to_string_lossy());
        let mut command=wide(&format!("\"{}\" --config \"{}\" --events \"{}\"",exe.display(),config.display(),events.display()));
        let directory=wide(&exe.parent().ok_or("Missing engine directory")?.to_string_lossy());
        let startup=STARTUPINFOW { cb:std::mem::size_of::<STARTUPINFOW>() as u32,..Default::default() };
        if !crate::firewall::FirewallManager::is_elevated() {
            unsafe {
                let mut process=PROCESS_INFORMATION::default();
                CreateProcessW(PCWSTR(application.as_ptr()),PWSTR(command.as_mut_ptr()),None,None,false,
                    CREATE_NO_WINDOW|CREATE_SUSPENDED,None,PCWSTR(directory.as_ptr()),&startup,&mut process).map_err(|e|e.to_string())?;
                return resume_managed(process);
            }
        }
        unsafe {
            let mut pid=0;GetWindowThreadProcessId(GetShellWindow(),Some(&mut pid));
            if pid==0 {return Err("Cannot find the desktop user's normal security token.".into());}
            let shell=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,pid).map_err(|e|e.to_string())?;
            let shell=OwnedHandle::from_raw_handle(shell.0);
            let mut token=HANDLE::default();
            OpenProcessToken(HANDLE(shell.as_raw_handle()),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY,&mut token).map_err(|e|e.to_string())?;
            let token=OwnedHandle::from_raw_handle(token.0);
            let mut elevation=TOKEN_ELEVATION::default();let mut length=0;
            GetTokenInformation(HANDLE(token.as_raw_handle()),TokenElevation,Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),std::mem::size_of::<TOKEN_ELEVATION>() as u32,&mut length).map_err(|e|e.to_string())?;
            if elevation.TokenIsElevated!=0 {return Err("The desktop token is elevated; refusing an elevated speedtest.".into());}
            let mut primary=HANDLE::default();
            DuplicateTokenEx(HANDLE(token.as_raw_handle()),TOKEN_ALL_ACCESS,None,SecurityImpersonation,TokenPrimary,&mut primary).map_err(|e|e.to_string())?;
            let primary=OwnedHandle::from_raw_handle(primary.0);
            let mut process=PROCESS_INFORMATION::default();
            CreateProcessWithTokenW(HANDLE(primary.as_raw_handle()),CREATE_PROCESS_LOGON_FLAGS(0),PCWSTR(application.as_ptr()),PWSTR(command.as_mut_ptr()),CREATE_NO_WINDOW|CREATE_SUSPENDED,None,PCWSTR(directory.as_ptr()),&startup,&mut process).map_err(|e|format!("Cannot launch the unprivileged speedtest: {e}"))?;
            resume_managed(process)
        }
    }
    pub fn exit_code(&self)->Result<Option<u32>,String> {
        let mut code=0;unsafe {GetExitCodeProcess(HANDLE(self.handle.as_raw_handle()),&mut code).map_err(|e|e.to_string())?;}
        Ok(if code==259 {None}else{Some(code)})
    }
    pub fn stop(&self) {unsafe {let _=TerminateProcess(HANDLE(self.handle.as_raw_handle()),1); WaitForSingleObject(HANDLE(self.handle.as_raw_handle()),5000);}}
}
impl Drop for SpeedProcess {fn drop(&mut self){if self.exit_code().ok().flatten().is_none(){self.stop();}}}

unsafe fn resume_managed(process: PROCESS_INFORMATION) -> Result<SpeedProcess,String> {
    let thread = OwnedHandle::from_raw_handle(process.hThread.0);
    let process = managed(OwnedHandle::from_raw_handle(process.hProcess.0))?;
    if ResumeThread(HANDLE(thread.as_raw_handle())) == u32::MAX {
        return Err("Cannot resume the speedtest process".into());
    }
    Ok(process)
}
