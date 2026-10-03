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
}

#[derive(Debug, Default)]
pub struct EnforcementManager {
    pub active: HashMap<Uuid, ActiveBypass>,
}

impl EnforcementManager {
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
        injector::update_target_ip(&source_ip, direct.index)?;

        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut injected_pids = HashSet::new();

        // Inject into any currently running instances
        if !exe_name.is_empty() {
            let pids = injector::find_pids_by_exe_name(&exe_name);
            for pid in pids {
                if injector::inject_dll_into_pid(pid, &dll_path).is_ok() {
                    injected_pids.insert(pid);
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
            },
        );

        config::append_log(&format!(
            "ENABLE_BYPASS app={} exe={} iface={} ip={}",
            app_id,
            exe.display(),
            direct.name,
            source_ip
        ));

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

        let pid = injector::launch_with_bypass(exe, &source_ip, direct.index)?;

        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let entry = self.active.entry(app_id).or_insert_with(|| ActiveBypass {
            app_id,
            exe_path: exe.clone(),
            exe_name,
            injected_pids: HashSet::new(),
        });
        entry.injected_pids.insert(pid);

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
            injector::clear_target_ip();
        }
        Ok(())
    }

    pub fn clear_all(&mut self) -> Result<(), String> {
        self.active.clear();
        injector::clear_target_ip();
        config::append_log("CLEAR_ALL_BYPASSES");
        Ok(())
    }

    pub fn is_active(&self, app: Uuid) -> bool {
        self.active.contains_key(&app)
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
            let current_pids = injector::find_pids_by_exe_name(&bypass.exe_name);
            // Purge dead PIDs from cache
            bypass.injected_pids.retain(|pid| current_pids.contains(pid));

            for pid in current_pids {
                if !bypass.injected_pids.contains(&pid) {
                    if injector::inject_dll_into_pid(pid, &dll_path).is_ok() {
                        bypass.injected_pids.insert(pid);
                    }
                }
            }
        }
    }
}
