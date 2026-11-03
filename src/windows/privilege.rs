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
    // Elevation is a property of the process token and cannot change
    // during the process lifetime, so it is computed once: this runs on
    // hot paths (a watchdog cycle and every spawned system tool used to
    // re-open the token each time).
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(query_elevated)
}

#[cfg(windows)]
fn query_elevated() -> bool {
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

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

// NOTE: BiFlow deliberately does NOT enable SeDebugPrivilege anymore. Every
// process query it performs works with PROCESS_QUERY_LIMITED_INFORMATION on
// the user's own processes, and holding SeDebugPrivilege widens the attack
// surface (any process compromise inherits the ability to open SYSTEM
// processes) and is a strong malware heuristic for antivirus engines.

/// Quotes one command-line argument for ShellExecuteW's parameter
/// string: arguments containing spaces or quotes are wrapped in double
/// quotes with embedded quotes/backslashes escaped (the standard
/// CommandLineToArgvW convention).
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

#[cfg(windows)]
pub fn restart_as_administrator() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let wide_exe: Vec<u16> = current_exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let wide_verb: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Forward the current arguments: dropping them used to silently lose
    // state the caller relies on — most visibly --minimized, so an
    // autostarted instance that re-elevated popped up a full window
    // instead of returning to the tray.
    let params: String = std::env::args()
        .skip(1)
        .map(|a| quote_arg(&a))
        .collect::<Vec<String>>()
        .join(" ");
    let wide_params: Vec<u16> = if params.is_empty() {
        Vec::new()
    } else {
        std::ffi::OsStr::new(&params)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let params_ptr = if wide_params.is_empty() {
        std::ptr::null()
    } else {
        wide_params.as_ptr()
    };

    unsafe {
        let res = windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            wide_verb.as_ptr(),
            wide_exe.as_ptr(),
            params_ptr,
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
        if res as usize > 32 {
            std::process::exit(0);
        } else {
            Err(format!(
                "Elevation request failed (error code {})",
                res as usize
            ))
        }
    }
}

#[cfg(not(windows))]
pub fn restart_as_administrator() -> Result<(), String> {
    Err("Not supported on non-Windows platforms".into())
}
