pub mod autostart;
pub mod firewall;
pub mod injector;
pub mod privilege;
pub mod tray;

#[cfg(windows)]
pub fn get_main_window_hwnd() -> windows_sys::Win32::Foundation::HWND {
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
                windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(hwnd, &mut pid);
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
