use std::env;
use std::os::windows::process::CommandExt;
use std::process::Command;
use winreg::{enums::*, RegKey};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APP_NAME: &str = "BiFlow";
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Tri-state task query: Ok(true/false) is a real answer from schtasks;
/// Err means the query itself failed, which callers must not flatten
/// into "task absent" (an unverifiable removal is a failed removal).
fn task_query() -> Result<bool, String> {
    // Absolute System32 path: an elevated process must never resolve
    // system tools by bare name (the executable's own folder is searched
    // before System32).
    let task_check = Command::new(crate::windows::system_tool("schtasks.exe"))
        .args(["/Query", "/TN", APP_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to run schtasks: {}", e))?;
    Ok(task_check.status.success())
}

fn task_exists() -> bool {
    matches!(task_query(), Ok(true))
}

/// The current user's SID string, read from the process token. The
/// autostart XML and the protected-location check both need the user's
/// real identity; environment variables (USERDOMAIN/USERNAME) are
/// inherited, spoofable text and are not an identity source.
fn current_user_sid_string() -> Option<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut len: u32 = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            len,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str: windows_sys::core::PWSTR = null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str) == 0 || sid_str.is_null() {
            return None;
        }
        let mut n = 0usize;
        while *sid_str.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, n));
        LocalFree(sid_str as HLOCAL);
        Some(s)
    }
}

/// True when the executable lives somewhere a standard user cannot
/// replace it: under a Program Files / ProgramData root (checked on the
/// canonicalized path, so junction tricks do not slip past) AND with a
/// directory DACL that grants no write-like rights to untrusted
/// principals. The prefix test alone is NOT sufficient — the default
/// %ProgramData% ACL lets any user create a subfolder there, and that
/// subfolder is fully writable by its creator while passing a prefix
/// test. The logon task runs the executable with HighestAvailable, so
/// registering it from a user-writable folder would let any same-user
/// process replace the binary and have its code run at the next logon
/// with the full administrator token.
fn exe_dir_is_protected(exe: &std::path::Path) -> bool {
    let Some(user_sid) = current_user_sid_string() else {
        return false;
    };
    let Ok(canonical) = std::fs::canonicalize(exe) else {
        return false;
    };
    let exe_str = canonical.to_string_lossy().to_ascii_lowercase();
    let exe_str = exe_str.strip_prefix(r"\\?\").unwrap_or(&exe_str);
    let mut under_root = false;
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
        if let Ok(root) = env::var(var) {
            let root = root.trim_end_matches('\\').to_ascii_lowercase();
            if !root.is_empty() && exe_str.starts_with(&format!("{}\\", root)) {
                under_root = true;
                break;
            }
        }
    }
    if !under_root {
        return false;
    }
    let Some(dir) = canonical.parent() else {
        return false;
    };
    // Fail closed on an unreadable DACL.
    matches!(
        crate::windows::injector::path_grants_untrusted_write(dir, &user_sid),
        Some(false)
    )
}

fn run_key_present() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey(RUN_KEY) {
        if let Ok(val) = key.get_value::<String, _>(APP_NAME) {
            return !val.trim().is_empty();
        }
    }
    false
}

pub fn is_autostart_enabled() -> bool {
    task_exists() || run_key_present()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Builds the Task Scheduler XML for the logon task. Compared to a bare
/// `schtasks /Create /SC ONLOGON`, the XML form:
/// - triggers only for the current user (not every account on the machine),
/// - is not stopped on battery and has no 72-hour execution time limit, so
///   Windows never kills BiFlow (and its policy files) mid-session,
/// - starts BiFlow minimized to the tray via the --minimized argument,
/// - registers ONLY the task: keeping the legacy HKCU Run entry as a second
///   mechanism could start two instances racing over the policy files.
fn task_xml(exe: &std::path::Path) -> Result<String, String> {
    // The principal is the current user's SID from the process token,
    // never environment text. If the SID cannot be determined the task
    // must not be registered at all: omitting <UserId> would silently
    // widen the logon trigger to EVERY user of the machine.
    let sid = current_user_sid_string()
        .ok_or_else(|| "Could not determine the current user's SID".to_string())?;
    let user_id = format!("<UserId>{}</UserId>", xml_escape(&sid));
    let workdir = exe
        .parent()
        .map(|p| xml_escape(&p.to_string_lossy()))
        .unwrap_or_default();
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>BiFlow - start with Windows (minimized to tray)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      {user_id}
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      {user_id}
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--minimized</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#,
        user_id = user_id,
        exe = xml_escape(&exe.to_string_lossy()),
        workdir = workdir,
    ))
}

fn remove_run_key() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_WRITE) {
        let _ = key.delete_value(APP_NAME);
    }
}

fn delete_task() -> bool {
    let out = Command::new(crate::windows::system_tool("schtasks.exe"))
        .args(["/Delete", "/TN", APP_NAME, "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    matches!(out, Ok(o) if o.status.success())
}

pub fn set_autostart(enable: bool) -> Result<(), String> {
    if enable {
        let exe = env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;

        // The logon task runs this executable with HighestAvailable. From a
        // user-writable location the binary could be replaced by any
        // same-user process and the replacement would run elevated at the
        // next logon, so registration is refused there (see
        // exe_dir_is_protected).
        if !exe_dir_is_protected(&exe) {
            return Err(
                "Autostart requires BiFlow to run from a protected location (for example C:\\Program Files\\BiFlow). A copy in a user-writable folder cannot register an elevated logon task."
                    .into(),
            );
        }

        // The XML file is written into the ACL-protected ProgramData folder,
        // not %TEMP%: it is handed to an elevated scheduler, so its location
        // must not be writable by non-elevated processes. There is no TEMP
        // fallback: if the protected folder is unavailable, fail honestly.
        let xml_dir = crate::windows::injector::biflow_programdata_dir()
            .ok_or_else(|| "ProgramData environment variable is unavailable".to_string())?;
        let xml_path = xml_dir.join("biflow_autostart_task.xml");
        // Prove the containing folder's protection BEFORE publishing
        // into it (policy publishing re-proves it on every write): if
        // the root ACL application had failed, the XML would otherwise
        // sit in a possibly user-writable folder between the rename
        // below and its own per-file ACL.
        crate::windows::injector::apply_protected_acl(&xml_dir)?;
        // schtasks /XML expects a UTF-16LE file. It is published via a
        // temp file + rename so a crash mid-write cannot leave a torn
        // XML (containing the exe path and the user's SID) behind.
        let xml = task_xml(&exe)?;
        let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
        for unit in xml.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let xml_tmp = xml_dir.join("biflow_autostart_task.xml.tmp");
        std::fs::write(&xml_tmp, &bytes)
            .map_err(|e| format!("Failed to write autostart task XML: {}", e))?;
        if let Err(e) = std::fs::rename(&xml_tmp, &xml_path) {
            let _ = std::fs::remove_file(&xml_tmp);
            return Err(format!("Failed to publish autostart task XML: {}", e));
        }
        // The XML defines an elevated task; prove its protection instead of
        // relying on whatever the folder happened to inherit.
        if let Err(e) = crate::windows::injector::apply_protected_acl(&xml_path) {
            let _ = std::fs::remove_file(&xml_path);
            return Err(format!("Failed to protect autostart task XML: {}", e));
        }

        let out = Command::new(crate::windows::system_tool("schtasks.exe"))
            .args([
                "/Create",
                "/TN",
                APP_NAME,
                "/XML",
                &xml_path.to_string_lossy(),
                "/F",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to run schtasks: {}", e))?;

        let _ = std::fs::remove_file(&xml_path);

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            // Honest failure: previously a failed task creation still showed
            // "enabled successfully" whenever the registry write succeeded.
            return Err(format!(
                "Failed to create the BiFlow logon task{}.",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {}", detail)
                }
            ));
        }

        // Single mechanism only: drop any legacy Run entry so the app can
        // never be started twice at logon.
        remove_run_key();
        Ok(())
    } else {
        delete_task();
        remove_run_key();
        // Verify BOTH mechanisms are really gone, with a strict query:
        // previously the delete result was ignored and the UI reported
        // "disabled" while the task (and its elevated logon run) stayed
        // registered, and a surviving Run-key entry would have been
        // missed entirely because only the task side was checked.
        match task_query() {
            Ok(true) => {
                return Err(
                    "The BiFlow logon task could not be removed (it is still registered).".into(),
                );
            }
            Ok(false) => {}
            Err(e) => {
                return Err(format!(
                    "Could not verify that the BiFlow logon task was removed: {}",
                    e
                ));
            }
        }
        if run_key_present() {
            return Err(
                "The BiFlow Run-key entry could not be removed (it is still present).".into(),
            );
        }
        Ok(())
    }
}
