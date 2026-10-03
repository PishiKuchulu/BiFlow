use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

const EMBEDDED_HOOK_DLL: &[u8] = include_bytes!("../../cpp/biflow_hook64.dll");

pub fn ensure_dll_extracted() -> Result<PathBuf, String> {
    let temp = std::env::temp_dir().join("BiFlow");
    fs::create_dir_all(&temp).map_err(|e| e.to_string())?;
    let dll_path = temp.join("biflow_hook64.dll");

    // Write if not exists or if size differs
    let needs_write = match fs::metadata(&dll_path) {
        Ok(m) => m.len() != EMBEDDED_HOOK_DLL.len() as u64,
        Err(_) => true,
    };

    if needs_write {
        fs::write(&dll_path, EMBEDDED_HOOK_DLL).map_err(|e| e.to_string())?;
    }

    Ok(dll_path)
}

pub fn update_target_ip(ip: &str, _if_index: u32) -> Result<(), String> {
    let clean = ip.trim();
    let temp_file = std::env::temp_dir().join("biflow_target_ip.txt");
    let _ = fs::write(temp_file, clean);

    // Also write to global ProgramData so all processes and sandboxes can read it
    if let Ok(prog_data) = std::env::var("ProgramData") {
        let dir = PathBuf::from(prog_data).join("BiFlow");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::write(dir.join("target_ip.txt"), clean);
    }

    Ok(())
}

pub fn clear_target_ip() {
    let temp_file = std::env::temp_dir().join("biflow_target_ip.txt");
    let _ = fs::remove_file(temp_file);

    if let Ok(prog_data) = std::env::var("ProgramData") {
        let p = PathBuf::from(prog_data).join("BiFlow").join("target_ip.txt");
        let _ = fs::remove_file(p);
    }
}

pub fn inject_dll_into_pid(pid: u32, dll_path: &Path) -> Result<(), String> {
    let wide_path: Vec<u16> = dll_path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let bytes_len = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        let process: HANDLE = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            0,
            pid,
        );

        if process.is_null() {
            return Err(format!("Could not open process {} (error {})", pid, GetLastError()));
        }

        // Architecture check: 64-bit DLL cannot be injected into 32-bit (WOW64) process
        let mut is_wow64: i32 = 0;
        if IsWow64Process(process, &mut is_wow64) != 0 && is_wow64 != 0 {
            CloseHandle(process);
            return Err(format!("Skipping 32-bit (WOW64) process (PID {}) - incompatible with 64-bit DLL", pid));
        }

        let remote_mem = VirtualAllocEx(
            process,
            null_mut(),
            bytes_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            CloseHandle(process);
            return Err(format!("VirtualAllocEx failed in target process (error {})", GetLastError()));
        }

        let mut written: usize = 0;
        let ok_write = WriteProcessMemory(
            process,
            remote_mem,
            wide_path.as_ptr() as *const _,
            bytes_len,
            &mut written,
        );

        if ok_write == 0 {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!("WriteProcessMemory failed (error {})", GetLastError()));
        }

        let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll").encode_wide().chain(std::iter::once(0)).collect();
        let kernel32 = GetModuleHandleW(kernel32_name.as_ptr());
        let load_library_w = GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr());

        if load_library_w.is_none() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err("LoadLibraryW address not found in kernel32.dll".into());
        }

        let thread: HANDLE = CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute(load_library_w)),
            remote_mem,
            0,
            null_mut(),
        );

        if thread.is_null() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!("CreateRemoteThread failed (error {})", GetLastError()));
        }

        let wait_res = WaitForSingleObject(thread, 3000);
        let mut exit_code: u32 = 0;
        GetExitCodeThread(thread, &mut exit_code);
        CloseHandle(thread);

        if wait_res == WAIT_TIMEOUT {
            // Do not free remote_mem if thread is still executing to prevent target crash
            CloseHandle(process);
            return Err(format!("Injection thread timed out for PID {}", pid));
        }

        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);

        if exit_code == 0 {
            return Err(format!("LoadLibraryW returned NULL in PID {} (injection failed)", pid));
        }
    }

    Ok(())
}

pub fn launch_with_bypass(exe: &Path, target_ip: &str, if_index: u32) -> Result<u32, String> {
    let dll_path = ensure_dll_extracted()?;
    update_target_ip(target_ip, if_index)?;

    let exe_name = exe.file_name().map(|f| f.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let wide_exe: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let parent_dir = exe.parent().unwrap_or(Path::new("."));
    let wide_dir: Vec<u16> = parent_dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // For Chromium browsers (Chrome, Edge, Brave), add flags to allow DLL injection and bypass system proxy directly
    let cmd_str = if exe_name.contains("chrome") || exe_name.contains("msedge") || exe_name.contains("brave") {
        format!("\"{}\" --disable-features=RendererCodeIntegrity --no-proxy-server", exe.display())
    } else {
        format!("\"{}\"", exe.display())
    };

    let mut cmd_line: Vec<u16> = cmd_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Set BIFLOW_TARGET_IP in our current environment so child inherits it
    let env_val = target_ip.trim();
    std::env::set_var("BIFLOW_TARGET_IP", env_val);

    let success = unsafe {
        CreateProcessW(
            wide_exe.as_ptr(),
            cmd_line.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            wide_dir.as_ptr(),
            &mut si,
            &mut pi,
        )
    };

    if success == 0 {
        return Err(format!("Failed to start application (Win32 error {})", unsafe { GetLastError() }));
    }

    let pid = pi.dwProcessId;

    // Inject our hook DLL into suspended process
    let inject_res = inject_dll_into_pid(pid, &dll_path);

    // Resume the process thread
    unsafe {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    inject_res.map(|_| pid)
}

pub fn find_pids_by_exe_name(exe_name: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let lower_target = exe_name.to_ascii_lowercase();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return pids;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())],
                );
                if name.to_ascii_lowercase() == lower_target {
                    pids.push(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    pids
}

pub fn resolve_executable_path(name: &str) -> Option<String> {
    if Path::new(name).is_absolute() && Path::new(name).exists() {
        return Some(name.to_string());
    }

    // 1. Check Windows App Paths in HKLM and HKCU
    for hive in [winreg::enums::HKEY_LOCAL_MACHINE, winreg::enums::HKEY_CURRENT_USER] {
        let key_path = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{}", name);
        if let Ok(key) = winreg::RegKey::predef(hive).open_subkey(&key_path) {
            if let Ok(val) = key.get_value::<String, _>("") {
                let clean = val.trim().trim_matches('"');
                if Path::new(clean).exists() {
                    return Some(clean.to_string());
                }
            }
        }
    }

    // 2. Check System directories
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let p32 = Path::new(&sys_root).join("System32").join(name);
        if p32.exists() {
            return Some(p32.to_string_lossy().to_string());
        }
        let p_root = Path::new(&sys_root).join(name);
        if p_root.exists() {
            return Some(p_root.to_string_lossy().to_string());
        }
    }

    // 3. In-memory check against PATH environment variable (zero subprocesses, zero console windows)
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    None
}

pub fn get_process_full_path(pid: u32) -> Option<String> {
    unsafe {
        // Try PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
        let process = OpenProcess(0x1000, 0, pid);
        if !process.is_null() {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let success = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(process);

            if success != 0 && len > 0 {
                return Some(String::from_utf16_lossy(&buf[..len as usize]));
            }
        }

        // Secondary fallback with PROCESS_QUERY_INFORMATION (0x0400)
        let process2 = OpenProcess(0x0400, 0, pid);
        if !process2.is_null() {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let success = QueryFullProcessImageNameW(process2, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(process2);

            if success != 0 && len > 0 {
                return Some(String::from_utf16_lossy(&buf[..len as usize]));
            }
        }

        None
    }
}

pub fn get_process_maps() -> (
    std::collections::HashMap<String, Vec<u32>>,
    std::collections::HashMap<u32, u32>,
    std::collections::HashMap<u32, String>,
) {
    let mut name_map: std::collections::HashMap<String, Vec<u32>> = std::collections::HashMap::new();
    let mut parents: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut paths: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return (name_map, parents, paths);
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())],
                );
                let pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;

                if pid > 4 {
                    name_map.entry(name.to_ascii_lowercase())
                        .or_default()
                        .push(pid);

                    parents.insert(pid, parent_pid);

                    if let Some(path) = get_process_full_path(pid) {
                        paths.insert(pid, path);
                    } else if let Some(path) = resolve_executable_path(&name) {
                        paths.insert(pid, path);
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    (name_map, parents, paths)
}

#[allow(dead_code)]
pub fn get_all_running_processes_map() -> std::collections::HashMap<String, Vec<u32>> {
    let (name_map, _, _) = get_process_maps();
    name_map
}

pub fn get_running_gui_processes() -> Vec<(u32, String, String)> {
    let mut procs = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return procs;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())],
                );
                let pid = entry.th32ProcessID;

                // Filter out system internal OS processes
                let lower = name.to_ascii_lowercase();
                let skip = [
                    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                    "lsass.exe", "fontdrvhost.exe", "winlogon.exe",
                    "dwm.exe", "sihost.exe", "taskhostw.exe", "biflow.exe"
                ];

                if !skip.contains(&lower.as_str()) && lower.ends_with(".exe") && pid > 4 {
                    let full_path = get_process_full_path(pid)
                        .or_else(|| resolve_executable_path(&name));

                    if let Some(path) = full_path {
                        if Path::new(&path).is_absolute() {
                            procs.push((pid, name.clone(), path));
                        }
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    procs.sort_by(|a, b| a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()));
    procs.dedup_by(|a, b| a.1.eq_ignore_ascii_case(&b.1));
    procs
}

