pub mod autostart;
pub mod firewall;
pub mod injector;
pub mod privilege;
pub mod tray;

/// Absolute path of a Windows system tool (`netsh.exe`, `schtasks.exe`, ...)
/// inside the System32 directory, resolved via GetSystemDirectoryW.
///
/// An elevated process must never launch system tools by bare name:
/// CreateProcessW searches the directory of the current executable BEFORE
/// System32, so a same-named file planted next to a portable BiFlow.exe
/// would be executed with BiFlow's administrator token.
pub fn system_tool(file_name: &str) -> std::path::PathBuf {
    system32_dir().join(file_name)
}

/// Absolute path of Windows PowerShell 5.1
/// (System32\WindowsPowerShell\v1.0\powershell.exe).
pub fn system_powershell() -> std::path::PathBuf {
    system32_dir()
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

fn system32_dir() -> std::path::PathBuf {
    unsafe {
        // The System32 path is short; a stack buffer is plenty (this used
        // to allocate a 64 KiB heap vector on every spawned tool call).
        let mut buf = [0u16; 1024];
        let n = windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if n > 0 && (n as usize) < buf.len() {
            return std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n as usize]));
        }
    }
    // Fallback: %SystemRoot%\System32 (SystemRoot is set by Windows itself).
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    std::path::PathBuf::from(root).join("System32")
}

#[cfg(windows)]
pub(crate) fn get_main_window_hwnd() -> windows_sys::Win32::Foundation::HWND {
    struct SearchData {
        pid: u32,
        hwnd: windows_sys::Win32::Foundation::HWND,
    }

    unsafe {
        let current_pid = windows_sys::Win32::System::Threading::GetCurrentProcessId();

        extern "system" fn enum_proc(
            hwnd: windows_sys::Win32::Foundation::HWND,
            lparam: windows_sys::Win32::Foundation::LPARAM,
        ) -> i32 {
            unsafe {
                let data = &mut *(lparam as *mut SearchData);
                let mut pid = 0u32;
                windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(
                    hwnd, &mut pid,
                );
                if pid == data.pid {
                    let mut title_buf = [0u16; 256];
                    let len = windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextW(
                        hwnd,
                        title_buf.as_mut_ptr(),
                        title_buf.len() as i32,
                    );
                    if len > 0 {
                        let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                        if title.contains("BiFlow") {
                            data.hwnd = hwnd;
                            return 0; // stop enumeration, exact match found
                        } else if data.hwnd.is_null() {
                            data.hwnd = hwnd; // fallback to window with valid title
                        }
                    }
                }
                1
            }
        }

        let mut data = SearchData {
            pid: current_pid,
            hwnd: std::ptr::null_mut(),
        };

        windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows(
            Some(enum_proc),
            &mut data as *mut _ as isize,
        );

        data.hwnd
    }
}

#[cfg(windows)]
pub fn bring_window_to_front() {
    let hwnd = get_main_window_hwnd();
    if !hwnd.is_null() {
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW,
            );
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_RESTORE,
            );
            windows_sys::Win32::UI::WindowsAndMessaging::BringWindowToTop(hwnd);
            windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(windows)]
pub fn hide_main_window() {
    let hwnd = get_main_window_hwnd();
    if !hwnd.is_null() {
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                hwnd,
                windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
            );
        }
    }
}
