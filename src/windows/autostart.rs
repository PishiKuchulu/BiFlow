use std::env;
use std::os::windows::process::CommandExt;
use std::process::Command;
use winreg::{enums::*, RegKey};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APP_NAME: &str = "BiFlow";
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn is_autostart_enabled() -> bool {
    // 1. Check if scheduled task exists
    let task_check = Command::new("schtasks")
        .args(["/Query", "/TN", APP_NAME])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(out) = task_check {
        if out.status.success() {
            return true;
        }
    }

    // 2. Check HKCU Run registry key as fallback
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey(RUN_KEY) {
        if let Ok(val) = key.get_value::<String, _>(APP_NAME) {
            return !val.trim().is_empty();
        }
    }

    false
}

pub fn set_autostart(enable: bool) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    if enable {
        let exe = env::current_exe().map_err(|e| format!("Failed to get current executable path: {}", e))?;
        let cmd = format!("\"{}\"", exe.display());

        // 1. If elevated, create Scheduled Task with HIGHEST privileges
        // This is required on Windows because UAC silences elevated HKCU Run entries at logon!
        let task_res = Command::new("schtasks")
            .args([
                "/Create",
                "/TN",
                APP_NAME,
                "/TR",
                &cmd,
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/F",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        let task_ok = task_res.map(|o| o.status.success()).unwrap_or(false);

        // 2. Also register in HKCU Run as secondary fallback
        let reg_res = hkcu
            .create_subkey(RUN_KEY)
            .and_then(|(key, _)| key.set_value(APP_NAME, &cmd));

        if !task_ok && reg_res.is_err() {
            return Err("Failed to configure autostart via both Task Scheduler and Registry".into());
        }
    } else {
        // Delete Scheduled Task
        let _ = Command::new("schtasks")
            .args(["/Delete", "/TN", APP_NAME, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        // Delete Registry Value
        if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_WRITE) {
            let _ = key.delete_value(APP_NAME);
        }
    }

    Ok(())
}
