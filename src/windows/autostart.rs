use std::env;
use std::os::windows::process::CommandExt;
use std::process::Command;
use winreg::{enums::*, RegKey};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APP_NAME: &str = "BiFlow";
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn task_exists() -> bool {
    // Absolute System32 path: an elevated process must never resolve
    // system tools by bare name (the executable's own folder is searched
    // before System32).
    let task_check = Command::new(crate::windows::system_tool("schtasks.exe"))
        .args(["/Query", "/TN", APP_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    matches!(task_check, Ok(out) if out.status.success())
}

/// True when the executable lives under a location that standard users
/// cannot write to (Program Files / ProgramData roots). The logon task
/// runs the executable with HighestAvailable, so registering it from a
/// user-writable folder (a portable copy in Downloads, say) would let any
/// same-user process replace the binary and have its code run at the next
/// logon with the full administrator token.
fn exe_dir_is_protected(exe: &std::path::Path) -> bool {
    let exe_str = exe.to_string_lossy().to_ascii_lowercase();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
        if let Ok(root) = env::var(var) {
            let root = root.trim_end_matches('\\').to_ascii_lowercase();
            if !root.is_empty() && exe_str.starts_with(&format!("{}\\", root)) {
                return true;
            }
        }
    }
    false
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
fn task_xml(exe: &std::path::Path) -> String {
    let user = match (env::var("USERDOMAIN"), env::var("USERNAME")) {
        (Ok(domain), Ok(name)) if !name.is_empty() => format!("{}\\{}", domain, name),
        (_, Ok(name)) if !name.is_empty() => name,
        _ => String::new(),
    };
    let user_id = if user.is_empty() {
        String::new()
    } else {
        format!("<UserId>{}</UserId>", xml_escape(&user))
    };
    let workdir = exe
        .parent()
        .map(|p| xml_escape(&p.to_string_lossy()))
        .unwrap_or_default();
    format!(
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
    )
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
        // schtasks /XML expects a UTF-16LE file.
        let xml = task_xml(&exe);
        let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
        for unit in xml.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&xml_path, &bytes)
            .map_err(|e| format!("Failed to write autostart task XML: {}", e))?;
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
        // Verify the task is really gone: previously the delete result was
        // ignored and the UI reported "disabled" while the task (and its
        // elevated logon run) stayed registered.
        if task_exists() {
            return Err(
                "The BiFlow logon task could not be removed (it is still registered).".into(),
            );
        }
        Ok(())
    }
}
