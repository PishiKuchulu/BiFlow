use std::ffi::c_void;
use std::ptr::null_mut;
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

#[cfg(windows)]
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) != 0;
        CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(windows)]
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let wide_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        if LookupPrivilegeValueW(std::ptr::null(), wide_name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let ok = AdjustTokenPrivileges(
            token,
            0,
            &mut tp as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        );

        CloseHandle(token);
        ok != 0
    }
}

#[cfg(not(windows))]
pub fn enable_debug_privilege() -> bool {
    false
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(windows)]
pub fn restart_as_administrator() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let wide_exe: Vec<u16> = current_exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let wide_verb: Vec<u16> = std::ffi::OsStr::new("runas").encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        let res = windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            wide_verb.as_ptr(),
            wide_exe.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
        if res as usize > 32 {
            std::process::exit(0);
        } else {
            Err(format!("Elevation request failed (error code {})", res as usize))
        }
    }
}

#[cfg(not(windows))]
pub fn restart_as_administrator() -> Result<(), String> {
    Err("Not supported on non-Windows platforms".into())
}

#[allow(dead_code)]
pub fn require_windows() -> Result<(), String> {
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("BiFlow is Windows-only.".into())
    }
}
