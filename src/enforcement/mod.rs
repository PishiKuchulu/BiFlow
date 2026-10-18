use crate::{config, models::InterfaceInfo, windows::injector};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use uuid::Uuid;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ActiveBypass {
    pub app_id: Uuid,
    pub exe_path: PathBuf,
    pub exe_name: String,
    pub injected_pids: HashSet<u32>,
    /// True when the app was not running at apply time; the watchdog injects on launch.
    pub awaiting_process: bool,
    /// Set when the app was running but every injection attempt failed.
    pub inject_error: Option<String>,
}

/// Honest live status of a bypass, so the UI never claims an active bypass
/// when the hook DLL is not actually inside the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassLiveStatus {
    /// Hook DLL is injected into at least one live process.
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

        let mut injected_pids = HashSet::new();
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
                            injected_pids.insert(pid);
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
    ) -> Result<u32, String> {
        let source_ip = direct
            .ipv4
            .clone()
            .ok_or("Direct interface has no valid IPv4 address")?;

        let pid = injector::launch_with_bypass(exe, &source_ip)?;

        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        self.target_ip = Some(source_ip.clone());
        let entry = self.active.entry(app_id).or_insert_with(|| ActiveBypass {
            app_id,
            exe_path: exe.clone(),
            exe_name,
            injected_pids: HashSet::new(),
            awaiting_process: false,
            inject_error: None,
        });
        entry.injected_pids.insert(pid);
        entry.awaiting_process = false;
        entry.inject_error = None;
        self.sync_policy_files();

        config::append_log(&format!(
            "LAUNCH_BYPASS app={} exe={} pid={} ip={}",
            app_id,
            exe.display(),
            pid,
            source_ip
        ));

        Ok(pid)
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

    /// Honest status used by the UI pill: never reports "bypassing" unless the
    /// hook DLL is actually injected into a live process.
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

    pub fn check_watchdog(&mut self) {
        if self.active.is_empty() {
            return;
        }

        let dll_path = match injector::ensure_dll_extracted() {
            Ok(p) => p,
            Err(_) => return,
        };

        for bypass in self.active.values_mut() {
            if bypass.exe_name.is_empty() {
                continue;
            }
            let current_pids = injector::find_pids_by_exe_path(&bypass.exe_path);
            // Purge dead PIDs from cache
            bypass.injected_pids.retain(|pid| current_pids.contains(pid));

            let had_pids = !current_pids.is_empty();
            let mut last_err: Option<String> = None;
            for &pid in &current_pids {
                if !bypass.injected_pids.contains(&pid) {
                    match injector::inject_dll_into_pid(pid, &dll_path) {
                        Ok(_) => {
                            bypass.injected_pids.insert(pid);
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
                injected_pids: HashSet::new(),
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
        b.injected_pids.insert(1234);
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Live));
    }
}
