use std::os::windows::process::CommandExt;
use std::process::Command;
use uuid::Uuid;

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn rule_name(app_id: &Uuid) -> String {
    format!("BiFlow_Block_{}", app_id.simple())
}

pub fn block_app(app_id: &Uuid, app_name: &str, exe_path: &str) -> Result<(), String> {
    let name = rule_name(app_id);

    // Resolve to verified absolute path if needed
    let resolved_exe = if std::path::Path::new(exe_path).is_absolute() {
        exe_path.to_string()
    } else {
        crate::windows::injector::resolve_executable_path(exe_path)
            .unwrap_or_else(|| exe_path.to_string())
    };

    let clean_path = resolved_exe.trim().trim_matches('"');
    if !std::path::Path::new(clean_path).is_absolute() {
        return Err(format!(
            "Cannot block {}: executable path must be an absolute path (found: {})",
            app_name, clean_path
        ));
    }

    // 1. Delete any existing rule with this name to avoid duplicates
    let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", name)]);

    // 2. Add outbound block rule (blocks sending traffic to internet/network)
    let out_res = run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={}", name),
        "dir=out",
        "action=block",
        &format!("program={}", clean_path),
        "enable=yes",
        &format!("description=Blocked by BiFlow for {}", app_name),
    ]);

    // 3. Add inbound block rule (blocks receiving any network connections)
    let _ = run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={}", name),
        "dir=in",
        "action=block",
        &format!("program={}", clean_path),
        "enable=yes",
        &format!("description=Blocked by BiFlow for {}", app_name),
    ]);

    // 4. Verify rule presence. If netsh failed, use PowerShell New-NetFirewallRule as fallback
    if !is_rule_present(app_id) {
        let ps_add = format!(
            "New-NetFirewallRule -DisplayName '{}' -Direction Outbound -Action Block -Program '{}' -Enabled True -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Action Block -Program '{}' -Enabled True -ErrorAction SilentlyContinue",
            name, clean_path, name, clean_path
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_add])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    // 5. Terminate active TCP connections for this application so that internet is CUT IMMEDIATELY!
    let file_name = std::path::Path::new(clean_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| app_name.to_string());

    let pids = crate::windows::injector::find_pids_by_exe_name(&file_name);
    if !pids.is_empty() {
        let pid_set: std::collections::HashSet<u32> = pids.into_iter().collect();
        crate::network::terminate_tcp_connections_for_pids(&pid_set);
    }

    crate::config::append_log(&format!(
        "BLOCK_INTERNET app={} exe={} name={}",
        app_id, clean_path, app_name
    ));

    out_res.map(|_| ())
}

pub fn unblock_app(app_id: &Uuid) -> Result<(), String> {
    let name = rule_name(app_id);
    let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", name)]);

    // Also remove via PowerShell to guarantee zero leftovers
    let ps_del = format!("Remove-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue", name);
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_del])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    crate::config::append_log(&format!("UNBLOCK_INTERNET app={}", app_id));
    Ok(())
}

#[allow(dead_code)]
pub fn is_rule_present(app_id: &Uuid) -> bool {
    let name = rule_name(app_id);
    if let Ok(output) = run_netsh(&["advfirewall", "firewall", "show", "rule", &format!("name={}", name)]) {
        output.contains(&name)
    } else {
        false
    }
}

pub fn clear_all_blocked_rules(app_ids: &[Uuid]) {
    for id in app_ids {
        let _ = unblock_app(id);
    }

    // Comprehensive purge: remove any orphaned BiFlow rules in one operation
    let purge_script = "Remove-NetFirewallRule -DisplayName 'BiFlow_Block*' -ErrorAction SilentlyContinue";
    if crate::windows::privilege::is_elevated() {
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", purge_script])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    } else {
        let ps_cmd = format!(
            "Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -Command \"{}\"' -Verb RunAs -Wait -WindowStyle Hidden",
            purge_script
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

fn run_netsh(args: &[&str]) -> Result<String, String> {
    if crate::windows::privilege::is_elevated() {
        let output = Command::new("netsh")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to execute netsh: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            let msg = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else if !stdout.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                format!("netsh failed with exit code {:?}", output.status.code())
            };
            return Err(msg);
        }

        Ok(stdout)
    } else {
        // Fallback for non-elevated: launch elevated netsh via PowerShell
        let args_formatted = args
            .iter()
            .map(|a| {
                if a.contains(' ') || a.contains('"') {
                    format!("`\"{}\"`", a.replace('"', "`\""))
                } else {
                    a.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        let ps_cmd = format!(
            "Start-Process netsh -ArgumentList '{}' -Verb RunAs -Wait -WindowStyle Hidden",
            args_formatted
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to request administrator elevation: {}", e))?;

        if !output.status.success() {
            return Err("Administrator elevation was rejected or failed.".into());
        }

        Ok("Success (elevated)".into())
    }
}
