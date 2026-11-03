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

    // netsh is invoked with an argv array, never a formatted command
    // line: the old build-a-string-then-re-tokenize approach made correct
    // quoting depend on a hand-written splitter. With argv, values with
    // spaces (e.g. "C:\Program Files\...") need no quoting at all.
    let name_arg = format!("name={}", name);
    let program_arg = format!("program={}", clean_path);
    let delete_args: Vec<&str> = vec![
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        name_arg.as_str(),
    ];
    let add_out_args: Vec<&str> = vec![
        "advfirewall",
        "firewall",
        "add",
        "rule",
        name_arg.as_str(),
        "dir=out",
        "action=block",
        program_arg.as_str(),
        "enable=yes",
        "description=Blocked by BiFlow",
    ];
    let add_in_args: Vec<&str> = vec![
        "advfirewall",
        "firewall",
        "add",
        "rule",
        name_arg.as_str(),
        "dir=in",
        "action=block",
        program_arg.as_str(),
        "enable=yes",
        "description=Blocked by BiFlow",
    ];

    if crate::windows::privilege::is_elevated() {
        let _ = run_netsh(&delete_args);
        let mut out_err: Option<String> = None;
        let mut in_err: Option<String> = None;
        if let Err(e) = run_netsh(&add_out_args) {
            out_err = Some(e);
        }
        if let Err(e) = run_netsh(&add_in_args) {
            in_err = Some(e);
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
                return Err(out_err.or(in_err).unwrap_or_else(|| {
                    "Firewall block rules could not be created or verified".into()
                }));
            }
            Ok((out, inn)) => {
                // Partial success is not success: remove the surviving
                // half-rule so the app is not left half-blocked. The
                // removal itself is verified before the error message is
                // allowed to claim it happened.
                let _ = run_netsh(&delete_args);
                let removed = matches!(query_rule_directions(app_id), Ok((false, false)));
                return Err(format!(
                    "Only one firewall direction was created for {} (out={}, in={}); {}",
                    app_name,
                    out,
                    inn,
                    if removed {
                        "the partial rule was removed"
                    } else {
                        "removal of the partial rule could not be confirmed — check Windows Firewall for a leftover rule"
                    }
                ));
            }
            Err(e) => {
                // The rules may exist even though verification failed:
                // leaving them while the caller reports failure would
                // diverge firewall state from the UI. Attempt the same
                // verified cleanup as the partial-success branch and
                // say what actually happened (round-2 audit).
                let _ = run_netsh(&delete_args);
                let removed = matches!(query_rule_directions(app_id), Ok((false, false)));
                return Err(format!(
                    "Firewall block for {} could not be verified: {}; {}",
                    app_name,
                    e,
                    if removed {
                        "any partially created rules were removed"
                    } else {
                        "cleanup of possibly-created rules could not be confirmed — check Windows Firewall for leftover rules"
                    }
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
        let (cut, failed) = crate::network::terminate_tcp_connections_for_pids(&pid_set);
        crate::config::append_log(&format!(
            "BLOCK_CONN_CUT app={} terminated={} failed={}",
            app_id, cut, failed
        ));
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

    let name_arg = format!("name={}", name);
    let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", &name_arg]);
    // Also remove via PowerShell: it deletes rules netsh sometimes leaves
    // (e.g. rules the PS fallback in block_app created under the same
    // -Name). The verification below is what decides success.
    let ps_remove = format!(
        "Remove-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue",
        name.replace('\'', "''")
    );
    let _ = Command::new(crate::windows::system_powershell())
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &ps_remove,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

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
    name: String,
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
    // The substituted value is escaped here, inside the helper, so its
    // safety never depends on every future caller remembering to escape
    // before interpolating into a single-quoted PowerShell literal.
    let script = "$rs = Get-NetFirewallRule -Name '__NAME__' -ErrorAction SilentlyContinue; foreach ($r in $rs) { $a = $r | Get-NetFirewallApplicationFilter; Write-Output (\"{0}|{1}|{2}|{3}|{4}\" -f $r.Name, $r.Direction, $r.Enabled, $r.Action, $a.Program) }"
        .replace("__NAME__", &name.replace('\'', "''"));
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
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() == 5 {
            rules.push(FwRule {
                name: parts[0].trim().to_string(),
                direction_out: parts[1].trim().eq_ignore_ascii_case("Outbound"),
                enabled: parts[2].trim().eq_ignore_ascii_case("True"),
                block: parts[3].trim().eq_ignore_ascii_case("Block"),
                program: parts[4].trim().trim_matches('"').to_string(),
            });
        }
    }
    Ok(rules)
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

/// Startup reconciliation for all blocked apps with ONE batch query.
/// Firewall rules are persistent, so only apps whose rule is actually
/// missing or unverified are re-created. This used to run one or two
/// PowerShell spawns PER blocked app on the startup path; the batch
/// reads every BiFlow rule once and decides locally. When an app (and
/// therefore its executable) is known, reconciliation checks the
/// VERIFIED state (enabled + Block + exact program, both directions);
/// without a known executable only presence can be checked. A failed
/// query leaves every rule untouched: unknown is not absent.
pub fn reconcile_blocked_apps(blocked: &[(Uuid, Option<(String, String)>)]) {
    if !crate::windows::privilege::is_elevated() {
        return;
    }
    let all = match query_rules_ps("BiFlow_Block*") {
        Ok(r) => r,
        Err(e) => {
            crate::config::append_log(&format!("FIREWALL_VERIFY_FAILED batch {}", e));
            return;
        }
    };
    for (id, app) in blocked {
        let name = rule_name(id);
        let mine: Vec<&FwRule> = all.iter().filter(|r| r.name == name).collect();
        let satisfied = match app {
            Some((_, exe)) => {
                let want = exe.trim().trim_matches('"');
                let is_block =
                    |r: &FwRule| r.enabled && r.block && r.program.eq_ignore_ascii_case(want);
                mine.iter().any(|r| r.direction_out && is_block(r))
                    && mine.iter().any(|r| !r.direction_out && is_block(r))
            }
            None => mine.iter().any(|r| r.direction_out) && mine.iter().any(|r| !r.direction_out),
        };
        if !satisfied {
            if let Some((app_name, exe)) = app {
                let _ = block_app(id, app_name, exe);
            }
        }
    }
}

pub fn clear_all_blocked_rules(app_ids: &[Uuid]) -> Result<(), String> {
    if !crate::windows::privilege::is_elevated() {
        return Err("Clearing firewall rules requires BiFlow to run as Administrator.".into());
    }

    for id in app_ids {
        let name_arg = format!("name={}", rule_name(id));
        let _ = run_netsh(&["advfirewall", "firewall", "delete", "rule", &name_arg]);
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

    // Verify with ONE batch readback of every remaining BiFlow rule
    // (this used to spawn one PowerShell per ID plus a separate orphan
    // enumeration: 2N+2 cold starts for N blocked apps). Per-ID presence
    // and the orphan check are both computed from the single result. A
    // failed query is "unknown", never "absent", and only verified
    // removals are logged, so the caller never clears its blocked list
    // while Windows still blocks.
    let mut failures: Vec<String> = Vec::new();
    match query_rules_ps("BiFlow_Block*") {
        Ok(remaining) => {
            for id in app_ids {
                let name = rule_name(id);
                let out = remaining.iter().any(|r| r.name == name && r.direction_out);
                let inn = remaining.iter().any(|r| r.name == name && !r.direction_out);
                if !out && !inn {
                    crate::config::append_log(&format!("UNBLOCK_INTERNET app={}", id));
                } else {
                    failures.push(format!("{} (out={}, in={})", id, out, inn));
                }
            }
            // Any rule the caller did not list is an orphan, and an
            // orphan must not survive a reported success either.
            let mut orphans: Vec<String> = remaining
                .iter()
                .map(|r| r.name.clone())
                .filter(|n| !app_ids.iter().any(|id| rule_name(id) == *n))
                .collect();
            orphans.sort();
            orphans.dedup();
            if !orphans.is_empty() {
                failures.push(format!(
                    "orphan rule(s) still present: {}",
                    orphans.join(", ")
                ));
            }
        }
        Err(e) => {
            failures.push(format!("verification failed: {}", e));
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
    fn rule_names_are_stable() {
        let id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        assert_eq!(
            rule_name(&id),
            "BiFlow_Block_12345678123412341234123456789abc"
        );
    }
}
