use crate::{config, models::InterfaceInfo, windows::injector};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use uuid::Uuid;

pub type ProcessMaps = (
    HashMap<String, Vec<u32>>,
    HashMap<u32, u32>,
    HashMap<u32, String>,
);

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ActiveBypass {
    pub app_id: Uuid,
    pub exe_path: PathBuf,
    pub exe_name: String,
    /// PIDs the hook DLL is verified live in, mapped to the process creation
    /// time (FILETIME ticks, 0 when unknown). Keying by creation time as
    /// well as PID means a recycled PID is never mistaken for the process
    /// that was originally injected.
    pub injected_pids: HashMap<u32, u64>,
    /// True when the app was not running at apply time; the watchdog injects on launch.
    pub awaiting_process: bool,
    /// Set when the app was running but every injection attempt failed.
    pub inject_error: Option<String>,
}

/// Honest live status of a bypass, so the UI never claims an active bypass
/// when the hook DLL is not actually inside the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassLiveStatus {
    /// Hook DLL is injected into at least one live process AND the DLL
    /// itself reported all of its Winsock hooks installed.
    Live,
    /// App is not running; the watchdog will inject when it starts.
    Pending,
    /// App is running but injection failed for every process.
    Failed,
}

#[derive(Debug, Default)]
pub struct EnforcementManager {
    pub active: HashMap<Uuid, ActiveBypass>,
    target_ip: Option<String>,
}

impl EnforcementManager {
    /// Writes the target-IP file and the bypassed-apps allow-list so the
    /// injected hook DLLs pick up the current policy (or its removal).
    /// When nothing is active, all policy files are deleted, which the hook
    /// interprets as "bypass disabled".
    fn sync_policy_files(&self) {
        match &self.target_ip {
            Some(ip) if !self.active.is_empty() => {
                let _ = injector::update_target_ip(ip);
                let paths: Vec<String> = self
                    .active
                    .values()
                    .map(|b| b.exe_path.to_string_lossy().to_string())
                    .collect();
                injector::update_bypass_app_list(&paths);
            }
            _ => injector::clear_target_ip(),
        }
    }

    pub fn apply(
        &mut self,
        app_id: Uuid,
        exe: PathBuf,
        direct: &InterfaceInfo,
    ) -> Result<(), String> {
        let source_ip = direct
            .ipv4
            .clone()
            .ok_or("Direct interface has no valid IPv4 address")?;

        let dll_path = injector::ensure_dll_extracted()?;
        self.target_ip = Some(source_ip);

        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut injected_pids: HashMap<u32, u64> = HashMap::new();
        let mut awaiting_process = false;
        let mut inject_error: Option<String> = None;

        if exe_name.is_empty() {
            inject_error = Some("Empty executable name".into());
        } else {
            // Match by full executable path so same-name binaries in other
            // folders are never injected by accident.
            let pids = injector::find_pids_by_exe_path(&exe);
            if pids.is_empty() {
                awaiting_process = true;
            } else {
                let mut last_err: Option<String> = None;
                for pid in pids {
                    match injector::inject_dll_into_pid(pid, &dll_path) {
                        Ok(_) => {
                            injected_pids
                                .insert(pid, injector::process_creation_time(pid).unwrap_or(0));
                        }
                        Err(e) => {
                            last_err = Some(e);
                        }
                    }
                }
                if injected_pids.is_empty() {
                    inject_error =
                        last_err.or_else(|| Some("DLL injection failed".into()));
                }
            }
        }

        self.active.insert(
            app_id,
            ActiveBypass {
                app_id,
                exe_path: exe.clone(),
                exe_name: exe_name.clone(),
                injected_pids,
                awaiting_process,
                inject_error: inject_error.clone(),
            },
        );
        self.sync_policy_files();

        config::append_log(&format!(
            "ENABLE_BYPASS app={} exe={} iface={} ip={} status={:?}",
            app_id,
            exe.display(),
            direct.name,
            self.target_ip.as_deref().unwrap_or("?"),
            self.live_status(app_id),
        ));

        if let Some(err) = inject_error {
            if !awaiting_process {
                return Err(format!("Bypass configured, but live injection failed: {}", err));
            }
        }

        Ok(())
    }

    pub fn launch(
        &mut self,
        app_id: Uuid,
        exe: &PathBuf,
        direct: &InterfaceInfo,
    ) -> Result<(u32, bool), String> {
        let source_ip = direct
            .ipv4
            .clone()
            .ok_or("Direct interface has no valid IPv4 address")?;

        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        // Register the bypass and publish the policy files BEFORE the
        // process starts, so the hook DLL finds the allow-list (including
        // this exe) the moment it initializes.
        self.target_ip = Some(source_ip.clone());
        self.active.insert(
            app_id,
            ActiveBypass {
                app_id,
                exe_path: exe.clone(),
                exe_name: exe_name.clone(),
                injected_pids: HashMap::new(),
                awaiting_process: false,
                inject_error: None,
            },
        );
        self.sync_policy_files();

        let outcome = match injector::launch_with_bypass(exe, &source_ip) {
            Ok(o) => o,
            Err(e) => {
                self.active.remove(&app_id);
                if self.active.is_empty() {
                    self.target_ip = None;
                }
                self.sync_policy_files();
                return Err(e);
            }
        };

        if let Some(entry) = self.active.get_mut(&app_id) {
            entry
                .injected_pids
                .insert(outcome.pid, injector::process_creation_time(outcome.pid).unwrap_or(0));
            entry.awaiting_process = false;
            entry.inject_error = None;
        }
        self.sync_policy_files();

        config::append_log(&format!(
            "LAUNCH_BYPASS app={} exe={} pid={} ip={} unelevated={}",
            app_id,
            exe.display(),
            outcome.pid,
            source_ip,
            outcome.unelevated
        ));

        Ok((outcome.pid, outcome.unelevated))
    }

    pub fn remove(&mut self, app_id: Uuid) -> Result<(), String> {
        if let Some(entry) = self.active.remove(&app_id) {
            config::append_log(&format!("DISABLE_BYPASS app={} exe={}", app_id, entry.exe_name));
        }
        if self.active.is_empty() {
            self.target_ip = None;
        }
        // Rewrites the allow-list without the removed app so its injected
        // processes stop bypassing on new sockets; deletes everything when
        // no bypass remains.
        self.sync_policy_files();
        Ok(())
    }

    pub fn clear_all(&mut self) -> Result<(), String> {
        self.active.clear();
        self.target_ip = None;
        self.sync_policy_files();
        config::append_log("CLEAR_ALL_BYPASSES");
        Ok(())
    }

    pub fn is_active(&self, app: Uuid) -> bool {
        self.active.contains_key(&app)
    }

    /// Honest status used by the UI pill: never reports "bypassing" unless
    /// the hook DLL is actually injected into a live process and the DLL
    /// confirmed its hooks are installed.
    pub fn live_status(&self, app_id: Uuid) -> Option<BypassLiveStatus> {
        self.active.get(&app_id).map(|b| {
            if !b.injected_pids.is_empty() {
                BypassLiveStatus::Live
            } else if b.awaiting_process {
                BypassLiveStatus::Pending
            } else {
                BypassLiveStatus::Failed
            }
        })
    }

    pub fn inject_error(&self, app_id: Uuid) -> Option<String> {
        self.active
            .get(&app_id)
            .and_then(|b| b.inject_error.clone())
    }

    pub fn count(&self) -> usize {
        self.active.len()
    }

    /// One watchdog cycle. Runs on a dedicated background thread (see
    /// AppState), never on the UI thread, and keeps working while the
    /// window is hidden in the tray.
    ///
    /// - Re-reads the selected adapter's current IPv4 and republishes the
    ///   policy when it changed (DHCP renewal, Wi-Fi roaming), so injected
    ///   hooks stop binding to a dead address.
    /// - Injects processes whose exe path matches a bypassed app, plus
    ///   their descendants that live in the same install directory tree
    ///   (launcher helpers such as steamwebhelper.exe).
    pub fn check_watchdog(&mut self, maps: &ProcessMaps, direct_ip: Option<&str>) {
        if self.active.is_empty() {
            return;
        }

        // Adapter IP drift: republish policy with the fresh address.
        if let Some(ip) = direct_ip {
            if self.target_ip.as_deref() != Some(ip) {
                config::append_log(&format!(
                    "ADAPTER_IP_CHANGED old={} new={}",
                    self.target_ip.as_deref().unwrap_or("?"),
                    ip
                ));
                self.target_ip = Some(ip.to_string());
                self.sync_policy_files();
            }
        }

        let dll_path = match injector::ensure_dll_extracted() {
            Ok(p) => p,
            Err(e) => {
                config::append_log(&format!("WATCHDOG_DLL_ERROR {}", e));
                return;
            }
        };

        let (_names, parents, paths) = maps;

        for bypass in self.active.values_mut() {
            if bypass.exe_name.is_empty() {
                continue;
            }
            let target = bypass.exe_path.to_string_lossy().to_ascii_lowercase();
            let app_dir = bypass
                .exe_path
                .parent()
                .map(|p| p.to_string_lossy().to_ascii_lowercase());

            // Primary processes: exact exe path match.
            let mut current: HashSet<u32> = paths
                .iter()
                .filter(|(_, p)| p.to_ascii_lowercase() == target)
                .map(|(pid, _)| *pid)
                .collect();

            // Descendants running from the same install tree (helper
            // processes of launchers/multi-process apps).
            if let Some(dir) = &app_dir {
                let prefix = format!("{}\\", dir.trim_end_matches('\\'));
                let descendants: Vec<u32> = paths
                    .iter()
                    .filter(|(pid, p)| {
                        !current.contains(pid)
                            && p.to_ascii_lowercase().starts_with(&prefix)
                    })
                    .map(|(pid, _)| *pid)
                    .filter(|pid| {
                        // Walk up the parent chain; covered when an ancestor
                        // is one of the app's own processes.
                        let mut cur = *pid;
                        for _ in 0..8 {
                            match parents.get(&cur) {
                                Some(parent) if *parent != cur && *parent > 4 => {
                                    if current.contains(parent) {
                                        return true;
                                    }
                                    cur = *parent;
                                }
                                _ => break,
                            }
                        }
                        false
                    })
                    .collect();
                current.extend(descendants);
            }

            // Purge dead PIDs and entries whose creation time no longer
            // matches (the PID was recycled by a different process).
            bypass.injected_pids.retain(|pid, created| {
                if !current.contains(pid) {
                    return false;
                }
                if *created == 0 {
                    return true;
                }
                injector::process_creation_time(*pid)
                    .map(|now| now == *created)
                    .unwrap_or(false)
            });

            let had_pids = !current.is_empty();
            let mut last_err: Option<String> = None;
            for &pid in &current {
                if !bypass.injected_pids.contains_key(&pid) {
                    match injector::inject_dll_into_pid(pid, &dll_path) {
                        Ok(_) => {
                            bypass.injected_pids.insert(
                                pid,
                                injector::process_creation_time(pid).unwrap_or(0),
                            );
                        }
                        Err(e) => {
                            last_err = Some(e);
                        }
                    }
                }
            }

            if bypass.injected_pids.is_empty() {
                if had_pids {
                    bypass.awaiting_process = false;
                    bypass.inject_error =
                        last_err.or_else(|| Some("DLL injection failed".into()));
                } else {
                    bypass.awaiting_process = true;
                    bypass.inject_error = None;
                }
            } else {
                bypass.awaiting_process = false;
                bypass.inject_error = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_status_transitions() {
        let mut m = EnforcementManager::default();
        let id = Uuid::new_v4();
        m.active.insert(
            id,
            ActiveBypass {
                app_id: id,
                exe_path: PathBuf::from("C:\\a.exe"),
                exe_name: "a.exe".into(),
                injected_pids: HashMap::new(),
                awaiting_process: true,
                inject_error: None,
            },
        );
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Pending));
        assert_eq!(m.live_status(Uuid::new_v4()), None);

        let b = m.active.get_mut(&id).unwrap();
        b.awaiting_process = false;
        b.inject_error = Some("denied".into());
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Failed));

        let b = m.active.get_mut(&id).unwrap();
        b.injected_pids.insert(1234, 42);
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Live));
    }
}
