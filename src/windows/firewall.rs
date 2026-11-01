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

        // Verify BOTH directions separately, and verify the rules really
        // block THIS executable: a rule with this name in one direction
        // must never mask a missing rule in the other, name-only presence
        // must never mask a disabled or foreign rule, and a failed query
        // is "unknown", never "absent".
        let mut dirs = query_verified_block(app_id, clean_path);
        if !matches!(dirs, Ok((true, true))) {
            // Fall back to PowerShell (with the same rule -Name, so the
            // readback below can see what it created), then retry.
            run_powershell_block(&name, clean_path);
            dirs = query_verified_block(app_id, clean_path);
        }
        match dirs {
            Ok((true, true)) => {}
            Ok((false, false)) => {
                return Err(out_err.unwrap_or_else(|| {
                    "Firewall block rules could not be created or verified".into()
                }));
            }
            Ok((out, inn)) => {
                // Partial success is not success: remove the surviving
                // half-rule so the app is not left half-blocked, and say so.
                let _ = run_netsh_line(&format!(
                    "netsh advfirewall firewall delete rule name=\"{}\"",
                    name
                ));
                return Err(format!(
                    "Only one firewall direction was created for {} (out={}, in={}); the partial rule was removed",
                    app_name, out, inn
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Firewall block for {} could not be verified: {}",
                    app_name, e
                ));
            }
        }
    } else {
        // BiFlow's manifest already requires Administrator, so this branch is
        // unreachable in practice. It used to write a fixed-name .cmd file
        // into %TEMP% and run it elevated — a classic TOCTOU privilege
        // escalation (any same-user process could rewrite the file while the
        // UAC prompt was up). It now fails honestly instead.
        return Err("Blocking requires BiFlow to run as Administrator.".into());
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
    // -Name is set to the same value netsh uses, so the netsh readback in
    // query_rule_directions can see rules this fallback created.
    let ps_add = format!(
        "New-NetFirewallRule -Name '{}' -DisplayName '{}' -Direction Outbound -Action Block -Program '{}' -Enabled True -ErrorAction SilentlyContinue; New-NetFirewallRule -Name '{}' -DisplayName '{}' -Direction Inbound -Action Block -Program '{}' -Enabled True -ErrorAction SilentlyContinue",
        name,
        name,
        clean_path.replace('\'', "''"),
        name,
        name,
        clean_path.replace('\'', "''"),
    );
    let _ = Command::new(crate::windows::system_powershell())
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_add])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

pub fn unblock_app(app_id: &Uuid) -> Result<(), String> {
    let name = rule_name(app_id);

    if !crate::windows::privilege::is_elevated() {
        return Err("Unblocking requires BiFlow to run as Administrator.".into());
    }

    let script_lines = vec![
        format!("netsh advfirewall firewall delete rule name=\"{}\"", name),
        format!(
            "powershell -NoProfile -WindowStyle Hidden -Command \"Remove-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue\"",
            name
        ),
    ];

    for line in &script_lines {
        let _ = run_netsh_line(line);
    }

    // Verify the rule is really gone in BOTH directions before reporting
    // success. A failed query is "unknown", never "absent": reporting Ok
    // on a query failure used to make the UI drop the app from the blocked
    // list while the firewall rule could still be silently in force.
    match query_rule_directions(app_id) {
        Ok((false, false)) => {}
        Ok((out, inn)) => {
            return Err(format!(
                "Firewall rule {} is still present after the delete attempt (out={}, in={})",
                name, out, inn
            ));
        }
        Err(e) => {
            return Err(format!(
                "Firewall rule removal for {} could not be verified: {}",
                name, e
            ));
        }
    }

    crate::config::append_log(&format!("UNBLOCK_INTERNET app={}", app_id));
    Ok(())
}

/// One firewall rule as reported by the structured PowerShell query.
/// Property names and enum values come from the API objects, so they are
/// identical on every Windows display language — unlike netsh text output,
/// whose "No rules match" sentence (the old absence test) is localized.
struct FwRule {
    direction_out: bool,
    enabled: bool,
    block: bool,
    program: String,
}

/// Structured readback of every rule with the given -Name (empty when none
/// exist). Returns Err when the query itself fails: "unknown" must never
/// be read as "absent".
fn query_rules_ps(name: &str) -> Result<Vec<FwRule>, String> {
    if !crate::windows::privilege::is_elevated() {
        return Err("Firewall queries require BiFlow to run as Administrator.".into());
    }
    let script = "$rs = Get-NetFirewallRule -Name '__NAME__' -ErrorAction SilentlyContinue; foreach ($r in $rs) { $a = $r | Get-NetFirewallApplicationFilter; Write-Output (\"{0}|{1}|{2}|{3}\" -f $r.Direction, $r.Enabled, $r.Action, $a.Program) }"
        .replace("__NAME__", name);
    let output = Command::new(crate::windows::system_powershell())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell firewall query failed with exit code {:?}",
            output.status.code()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() == 4 {
            rules.push(FwRule {
                direction_out: parts[0].trim().eq_ignore_ascii_case("Outbound"),
                enabled: parts[1].trim().eq_ignore_ascii_case("True"),
                block: parts[2].trim().eq_ignore_ascii_case("Block"),
                program: parts[3].trim().trim_matches('"').to_string(),
            });
        }
    }
    Ok(rules)
}

/// Names of every rule matching a -Name pattern (used to enumerate orphan
/// BiFlow rules after a purge, not just the IDs the caller remembered).
fn query_rule_names_ps(pattern: &str) -> Result<Vec<String>, String> {
    if !crate::windows::privilege::is_elevated() {
        return Err("Firewall queries require BiFlow to run as Administrator.".into());
    }
    let script = "Get-NetFirewallRule -Name '__PATTERN__' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }"
        .replace("__PATTERN__", pattern);
    let output = Command::new(crate::windows::system_powershell())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "PowerShell firewall query failed with exit code {:?}",
            output.status.code()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Query whether a rule with this app's name exists, separately per
/// direction (any state: this is the presence test used to verify
/// removals). Returns Err when the query itself fails.
pub fn query_rule_directions(app_id: &Uuid) -> Result<(bool, bool), String> {
    let rules = query_rules_ps(&rule_name(app_id))?;
    Ok((
        rules.iter().any(|r| r.direction_out),
        rules.iter().any(|r| !r.direction_out),
    ))
}

/// Verified block state, separately per direction: a rule counts only
/// when it is enabled, blocks, and targets exactly this executable. Mere
/// name presence is not proof of blocking — a disabled rule, a rule for a
/// different program, or a leftover from another tool can share the name
/// while the app's traffic flows freely.
pub fn query_verified_block(app_id: &Uuid, exe_path: &str) -> Result<(bool, bool), String> {
    let rules = query_rules_ps(&rule_name(app_id))?;
    let want = exe_path.trim().trim_matches('"');
    let is_block = |r: &FwRule| r.enabled && r.block && r.program.eq_ignore_ascii_case(want);
    Ok((
        rules.iter().any(|r| r.direction_out && is_block(r)),
        rules.iter().any(|r| !r.direction_out && is_block(r)),
    ))
}

pub fn clear_all_blocked_rules(app_ids: &[Uuid]) -> Result<(), String> {
    if !crate::windows::privilege::is_elevated() {
        return Err("Clearing firewall rules requires BiFlow to run as Administrator.".into());
    }

    let mut script_lines: Vec<String> = Vec::new();
    for id in app_ids {
        let name = rule_name(id);
        script_lines.push(format!(
            "netsh advfirewall firewall delete rule name=\"{}\"",
            name
        ));
    }

    for line in &script_lines {
        let _ = run_netsh_line(line);
    }

    // Comprehensive purge: remove any orphaned BiFlow rules (left behind
    // by removed apps or older versions) in one operation. This runs as a
    // CHECKED operation: previously it was a fire-and-forget line whose
    // failure was invisible, so orphans could survive a "successful" clear.
    let purge = Command::new(crate::windows::system_powershell())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Remove-NetFirewallRule -Name 'BiFlow_Block*' -ErrorAction SilentlyContinue",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match purge {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return Err(format!(
                "The orphan firewall-rule purge failed with exit code {:?}",
                out.status.code()
            ));
        }
        Err(e) => {
            return Err(format!(
                "Failed to run the orphan firewall-rule purge: {}",
                e
            ));
        }
    }

    // Verify per ID with a real readback, and report every ID that failed:
    // a failed query is "unknown", never "absent", and only verified
    // removals are logged, so the caller never clears its blocked list
    // while Windows still blocks.
    let mut failures: Vec<String> = Vec::new();
    for id in app_ids {
        match query_rule_directions(id) {
            Ok((false, false)) => {
                crate::config::append_log(&format!("UNBLOCK_INTERNET app={}", id));
            }
            Ok((out, inn)) => {
                failures.push(format!("{} (out={}, in={})", id, out, inn));
            }
            Err(e) => {
                failures.push(format!("{} (verification failed: {})", id, e));
            }
        }
    }
    // Enumerate ALL remaining BiFlow rules, not just the caller's IDs:
    // an orphan the caller forgot must not survive a reported success.
    match query_rule_names_ps("BiFlow_Block*") {
        Ok(names) if names.is_empty() => {}
        Ok(names) => {
            failures.push(format!(
                "orphan rule(s) still present: {}",
                names.join(", ")
            ));
        }
        Err(e) => {
            failures.push(format!("orphan check failed: {}", e));
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "{} firewall rule(s) could not be removed or verified: {}",
            failures.len(),
            failures.join(", ")
        ));
    }
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
    let output = Command::new(crate::windows::system_powershell())
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

fn run_netsh(args: &[&str]) -> Result<String, String> {
    if crate::windows::privilege::is_elevated() {
        let output = Command::new(crate::windows::system_tool("netsh.exe"))
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
        Err("netsh requires BiFlow to run as Administrator.".into())
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
        assert_eq!(
            rule_name(&id),
            "BiFlow_Block_12345678123412341234123456789abc"
        );
    }
}
