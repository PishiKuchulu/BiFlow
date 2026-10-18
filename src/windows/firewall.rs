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

    // NOTE: program/description values are quoted because netsh rejects
    // unquoted values containing spaces (e.g. "C:\Program Files\...").
    let script_lines = vec![
        format!("netsh advfirewall firewall delete rule name=\"{}\"", name),
        format!(
            "netsh advfirewall firewall add rule name=\"{}\" dir=out action=block program=\"{}\" enable=yes description=\"Blocked by BiFlow\"",
            name, clean_path
        ),
        format!(
            "netsh advfirewall firewall add rule name=\"{}\" dir=in action=block program=\"{}\" enable=yes description=\"Blocked by BiFlow\"",
            name, clean_path
        ),
    ];

    if crate::windows::privilege::is_elevated() {
        let mut out_err: Option<String> = None;
        for line in &script_lines {
            if let Err(e) = run_netsh_line(line) {
                // The outbound rule is the critical one; remember its failure.
                if line.contains("dir=out") {
                    out_err = Some(e);
                }
            }
        }

        // Verify rule presence. If netsh failed, use PowerShell as fallback.
        if !is_rule_present(app_id) {
            run_powershell_block(&name, clean_path);
        }

        if let Some(e) = out_err {
            if !is_rule_present(app_id) {
                return Err(e);
            }
        }
    } else {
        // Single UAC prompt for the whole sequence instead of one per command.
        run_elevated_batch(&script_lines)?;

        if !is_rule_present(app_id) {
            let ps_add = format!(
                "Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -Command \"New-NetFirewallRule -DisplayName ''{0}'' -Direction Outbound -Action Block -Program ''{1}'' -Enabled True; New-NetFirewallRule -DisplayName ''{0}'' -Direction Inbound -Action Block -Program ''{1}'' -Enabled True\"' -Verb RunAs -Wait -WindowStyle Hidden",
                name,
                clean_path.replace('\'', "''")
            );
            let _ = Command::new("powershell")
                .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_add])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }

        if !is_rule_present(app_id) {
            return Err("Administrator elevation was rejected or failed.".into());
        }
    }

    // Terminate active TCP connections (IPv4 + IPv6) for this exact executable
    // so that internet is CUT IMMEDIATELY, not just for new connections.
    let pids = crate::windows::injector::find_pids_by_exe_path(std::path::Path::new(clean_path));
    if !pids.is_empty() {
        let pid_set: std::collections::HashSet<u32> = pids.into_iter().collect();
        crate::network::terminate_tcp_connections_for_pids(&pid_set);
    }

    crate::config::append_log(&format!(
        "BLOCK_INTERNET app={} exe={} name={}",
        app_id, clean_path, app_name
    ));

    Ok(())
}

fn run_powershell_block(name: &str, clean_path: &str) {
    let ps_add = format!(
        "New-NetFirewallRule -DisplayName '{}' -Direction Outbound -Action Block -Program '{}' -Enabled True -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Action Block -Program '{}' -Enabled True -ErrorAction SilentlyContinue",
        name,
        clean_path.replace('\'', "''"),
        name,
        clean_path.replace('\'', "''"),
    );
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_add])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

pub fn unblock_app(app_id: &Uuid) -> Result<(), String> {
    let name = rule_name(app_id);

    let script_lines = vec![
        format!("netsh advfirewall firewall delete rule name=\"{}\"", name),
        format!(
            "powershell -NoProfile -WindowStyle Hidden -Command \"Remove-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue\"",
            name
        ),
    ];

    if crate::windows::privilege::is_elevated() {
        for line in &script_lines {
            let _ = run_netsh_line(line);
        }
    } else {
        // One UAC prompt for the whole unblock sequence.
        let _ = run_elevated_batch(&script_lines);
    }

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
    let mut script_lines: Vec<String> = Vec::new();
    for id in app_ids {
        let name = rule_name(id);
        script_lines.push(format!("netsh advfirewall firewall delete rule name=\"{}\"", name));
        let _ = unblock_app_quiet(id);
    }

    // Comprehensive purge: remove any orphaned BiFlow rules in one operation.
    script_lines.push(
        "powershell -NoProfile -WindowStyle Hidden -Command \"Remove-NetFirewallRule -DisplayName 'BiFlow_Block*' -ErrorAction SilentlyContinue\"".to_string(),
    );

    if crate::windows::privilege::is_elevated() {
        for line in &script_lines {
            let _ = run_netsh_line(line);
        }
    } else {
        let _ = run_elevated_batch(&script_lines);
    }
}

/// Quiet per-rule removal used by clear_all_blocked_rules (the batch above
/// does the real work); only logs.
fn unblock_app_quiet(app_id: &Uuid) -> Result<(), String> {
    crate::config::append_log(&format!("UNBLOCK_INTERNET app={}", app_id));
    Ok(())
}

/// Run one `netsh ...` command line (already tokenized by spaces the way
/// cmd.exe would; quoted values are preserved).
fn run_netsh_line(line: &str) -> Result<String, String> {
    // Re-tokenize respecting double quotes.
    let args = split_cmd_line(line);
    if args.is_empty() || args[0] != "netsh" {
        // Allow embedded powershell lines to pass through to cmd-less execution.
        return run_powershell_line(line);
    }
    let arg_refs: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
    run_netsh(&arg_refs)
}

fn run_powershell_line(line: &str) -> Result<String, String> {
    // line shape: powershell -NoProfile -WindowStyle Hidden -Command "<script>"
    let script = extract_ps_command(line).unwrap_or(line);
    let output = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute powershell: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "powershell failed with exit code {:?}",
            output.status.code()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Extract the script from `... -Command "<script>"` (outermost quotes).
fn extract_ps_command(line: &str) -> Option<&str> {
    let marker = "-Command \"";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.rfind('"')?;
    Some(&rest[..end])
}

/// Minimal command-line splitter that respects double quotes.
fn split_cmd_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Run several command lines with a SINGLE UAC elevation prompt by writing
/// them to a temp .cmd file and executing it elevated.
fn run_elevated_batch(lines: &[String]) -> Result<(), String> {
    use std::io::Write;

    let path = std::env::temp_dir().join("biflow_fw_batch.cmd");
    {
        let mut f = std::fs::File::create(&path)
            .map_err(|e| format!("Failed to write batch file: {}", e))?;
        f.write_all(b"@echo off\r\n")
            .map_err(|e| e.to_string())?;
        for line in lines {
            f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
            f.write_all(b"\r\n").map_err(|e| e.to_string())?;
        }
    }

    let ps_cmd = format!(
        "Start-Process -FilePath '{}' -Verb RunAs -Wait -WindowStyle Hidden",
        path.display()
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to request administrator elevation: {}", e))?;

    let _ = std::fs::remove_file(&path);

    if !output.status.success() {
        return Err("Administrator elevation was rejected or failed.".into());
    }
    Ok(())
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
        // Fallback for non-elevated single commands: launch elevated netsh via PowerShell
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_line_splitter_respects_quotes() {
        let parts = split_cmd_line(
            "netsh advfirewall firewall add rule name=\"My Rule\" program=\"C:\\Program Files\\a.exe\"",
        );
        let expected: Vec<String> = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=My Rule",
            "program=C:\\Program Files\\a.exe",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(parts, expected);
    }

    #[test]
    fn rule_names_are_stable() {
        let id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        assert_eq!(rule_name(&id), "BiFlow_Block_12345678123412341234123456789abc");
    }
}
