use crate::{
    config, discovery,
    enforcement::EnforcementManager,
    models::*,
    network,
    windows::{autostart, injector},
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;
use uuid::Uuid;

pub struct AppState {
    pub store: Store,
    pub apps: Vec<AppEntry>,
    pub interfaces: Vec<InterfaceInfo>,
    pub selected_app: Option<Uuid>,
    pub selected_direct_if: Option<u32>,
    pub search: String,
    pub status: String,
    pub manager: EnforcementManager,
    pub last_watchdog: Instant,
    pub filter_running_only: bool,
    pub filter_net_only: bool,
    pub filter_bypassed_only: bool,
    pub filter_blocked_only: bool,
    pub running_processes: HashMap<String, Vec<u32>>,
    pub process_parents: HashMap<u32, u32>,
    pub pid_to_path: HashMap<u32, String>,
    pub active_network_pids: HashSet<u32>,
    pub active_profile_baseline: Vec<BypassRule>,
}

impl AppState {
    pub fn new() -> Self {
        let mut store = config::load().unwrap_or_default();

        // Sync autostart status with actual Windows registry
        let reg_autostart = autostart::is_autostart_enabled();
        if store.autostart != reg_autostart {
            store.autostart = reg_autostart;
        }

        let mut apps = discovery::discover();

        // Merge currently running processes immediately on launch
        let running = discovery::discover_running_processes();
        for r in running {
            if !apps.iter().any(|a| {
                a.name.eq_ignore_ascii_case(&r.name)
                    || a.executable.eq_ignore_ascii_case(&r.executable)
            }) {
                apps.push(r);
            }
        }

        // Merge custom apps from store
        for custom in &store.custom_apps {
            if !apps.iter().any(|a| a.executable.eq_ignore_ascii_case(&custom.executable)) {
                apps.push(custom.clone());
            }
        }

        let interfaces = network::interfaces().unwrap_or_default();

        // Choose preferred or best physical direct interface
        let selected_direct_if = if let Some(idx) = store.selected_adapter_index {
            if interfaces.iter().any(|i| i.index == idx) {
                Some(idx)
            } else {
                Self::find_best_direct_interface(&interfaces)
            }
        } else {
            Self::find_best_direct_interface(&interfaces)
        };

        let (running_processes, process_parents, pid_to_path) = injector::get_process_maps();
        let active_network_pids = network::get_active_network_pids();

        let mut state = Self {
            store,
            apps,
            interfaces,
            selected_app: None,
            selected_direct_if,
            search: String::new(),
            status: "Ready. Select an application to bypass VPN or block from internet.".into(),
            manager: EnforcementManager::default(),
            last_watchdog: Instant::now(),
            filter_running_only: false,
            filter_net_only: false,
            filter_bypassed_only: false,
            filter_blocked_only: false,
            running_processes,
            process_parents,
            pid_to_path,
            active_network_pids,
            active_profile_baseline: Vec::new(),
        };

        state.auto_discover_network_apps();

        // Reconcile and synchronize blocked_apps and blocked_executables
        for exe in &state.store.blocked_executables {
            let det_id = discovery::generate_app_id(exe);
            if !state.store.blocked_apps.contains(&det_id) {
                state.store.blocked_apps.push(det_id);
            }
        }
        for blocked_id in &state.store.blocked_apps {
            if let Some(app) = state.apps.iter().find(|a| a.id == *blocked_id) {
                if !state
                    .store
                    .blocked_executables
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(&app.executable))
                {
                    state.store.blocked_executables.push(app.executable.clone());
                }
            }
        }

        // Ensure active profile is always initialized and valid
        if state.store.profiles.is_empty() {
            let default_id = Uuid::new_v4();
            state.store.profiles.push(Profile {
                id: default_id,
                name: "Default".into(),
                enabled: true,
                priority: 100,
                rules: vec![],
                adapter_index: None,
            });
            state.store.active_profile = Some(default_id);
        } else if state.store.active_profile.is_none()
            || !state.store.profiles.iter().any(|p| Some(p.id) == state.store.active_profile)
        {
            state.store.active_profile = Some(state.store.profiles[0].id);
        }

        // Apply adapter preference from active profile if set and valid
        if let Some(active_pid) = state.store.active_profile {
            if let Some(p) = state.store.profiles.iter().find(|p| p.id == active_pid) {
                if let Some(saved_idx) = p.adapter_index {
                    if state.interfaces.iter().any(|i| i.index == saved_idx) {
                        state.selected_direct_if = Some(saved_idx);
                    }
                }
            }
        }

        // Apply rules from active profile if any
        state.apply_active_profile_rules();

        // Record baseline rules snapshot for active profile
        if let Some(active_pid) = state.store.active_profile {
            if let Some(p) = state.store.profiles.iter().find(|p| p.id == active_pid) {
                state.active_profile_baseline = p.rules.clone();
            }
        }

        // Sync firewall rules for blocked applications on startup if running as administrator
        if crate::windows::privilege::is_elevated() {
            for blocked_id in &state.store.blocked_apps {
                if let Some(app) = state.apps.iter().find(|a| a.id == *blocked_id) {
                    let _ = crate::windows::firewall::block_app(blocked_id, &app.name, &app.executable);
                }
            }
        }

        state
    }

    fn find_best_direct_interface(interfaces: &[InterfaceInfo]) -> Option<u32> {
        interfaces
            .iter()
            .find(|x| x.status.eq_ignore_ascii_case("Up") && x.ipv4.is_some() && !network::is_likely_vpn(x))
            .map(|x| x.index)
    }

    pub fn save(&mut self) {
        if let Err(e) = config::save(&self.store) {
            self.status = format!("Save error: {}", e);
        }
    }

    pub fn auto_discover_network_apps(&mut self) {
        let mut new_entries = Vec::new();

        for &pid in &self.active_network_pids {
            if pid <= 4 {
                continue;
            }

            let exe_path = if let Some(p) = self.pid_to_path.get(&pid) {
                p.clone()
            } else {
                continue;
            };

            let path_lower = exe_path.to_ascii_lowercase();
            if path_lower.ends_with("biflow.exe") {
                continue;
            }

            let file_stem = Path::new(&exe_path)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "App".into());

            // Check if already in self.apps
            let already_exists = self.apps.iter().any(|a| {
                a.executable.eq_ignore_ascii_case(&exe_path)
                    || a.name.eq_ignore_ascii_case(&file_stem)
            });

            if !already_exists && !new_entries.iter().any(|a: &AppEntry| a.executable.eq_ignore_ascii_case(&exe_path)) {
                let id = discovery::generate_app_id(&exe_path);
                new_entries.push(AppEntry {
                    id,
                    name: file_stem,
                    publisher: Some("Active Internet Process".into()),
                    executable: exe_path,
                    version: None,
                    source: "Active Network".into(),
                    valid: true,
                });
            }
        }

        if !new_entries.is_empty() {
            self.apps.extend(new_entries);
        }
    }

    pub fn update_running_cache(&mut self) {
        let (running_map, parents, paths) = injector::get_process_maps();
        self.running_processes = running_map;
        self.process_parents = parents;
        self.pid_to_path = paths;
        self.active_network_pids = network::get_active_network_pids();
        self.auto_discover_network_apps();
    }

    pub fn is_app_running(&self, app: &AppEntry) -> bool {
        let exe_file = Path::new(&app.executable)
            .file_name()
            .map(|f| f.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();

        if !exe_file.is_empty() && self.running_processes.contains_key(&exe_file) {
            return true;
        }

        let name_lower = app.name.to_ascii_lowercase();
        if self.running_processes.contains_key(&name_lower) {
            return true;
        }

        let with_exe = format!("{}.exe", name_lower);
        if self.running_processes.contains_key(&with_exe) {
            return true;
        }

        // Direct path match in active processes
        self.pid_to_path.values().any(|p| p.eq_ignore_ascii_case(&app.executable))
    }

    pub fn has_active_network(&self, app: &AppEntry) -> bool {
        let exe_file = Path::new(&app.executable)
            .file_name()
            .map(|f| f.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();

        // 1. Direct PID match by exe file name
        if let Some(pids) = self.running_processes.get(&exe_file) {
            if pids.iter().any(|p| self.active_network_pids.contains(p)) {
                return true;
            }
        }

        // 2. Direct PID match by app name
        let name_lower = app.name.to_ascii_lowercase();
        if let Some(pids) = self.running_processes.get(&name_lower) {
            if pids.iter().any(|p| self.active_network_pids.contains(p)) {
                return true;
            }
        }

        // 3. Child process match (e.g. Steam -> steamwebhelper, Discord -> DiscordHelper, Electron apps)
        if let Some(pids) = self.running_processes.get(&exe_file) {
            for net_pid in &self.active_network_pids {
                if let Some(parent) = self.process_parents.get(net_pid) {
                    if pids.contains(parent) {
                        return true;
                    }
                }
            }
        }

        // 4. Same directory / Sub-directory binary match
        if let Some(app_dir) = Path::new(&app.executable).parent() {
            let app_dir_str = app_dir.to_string_lossy().to_ascii_lowercase();
            if app_dir_str.len() > 3 {
                for net_pid in &self.active_network_pids {
                    if let Some(p) = self.pid_to_path.get(net_pid) {
                        if p.to_ascii_lowercase().starts_with(&app_dir_str) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    pub fn toggle_autostart(&mut self, enable: bool) {
        if let Err(e) = autostart::set_autostart(enable) {
            self.status = format!("Autostart setting error: {}", e);
        } else {
            self.store.autostart = enable;
            self.save();
            self.status = if enable {
                "BiFlow configured to start automatically with Windows.".into()
            } else {
                "BiFlow removed from Windows startup.".into()
            };
        }
    }

    pub fn refresh(&mut self) {
        let mut discovered = discovery::discover();
        let running = discovery::discover_running_processes();
        for r in running {
            if !discovered.iter().any(|a| {
                a.name.eq_ignore_ascii_case(&r.name)
                    || a.executable.eq_ignore_ascii_case(&r.executable)
            }) {
                discovered.push(r);
            }
        }
        for custom in &self.store.custom_apps {
            if !discovered.iter().any(|a| a.executable.eq_ignore_ascii_case(&custom.executable)) {
                discovered.push(custom.clone());
            }
        }
        self.apps = discovered;
        self.interfaces = network::interfaces().unwrap_or_default();
        self.update_running_cache();

        // Preserve selected direct interface if still valid
        let target_idx = self.store.selected_adapter_index.or(self.selected_direct_if);
        if let Some(idx) = target_idx {
            if self.interfaces.iter().any(|i| i.index == idx) {
                self.selected_direct_if = Some(idx);
            } else {
                self.selected_direct_if = Self::find_best_direct_interface(&self.interfaces);
            }
        } else {
            self.selected_direct_if = Self::find_best_direct_interface(&self.interfaces);
        }

        // Preserve selected app if still present
        if let Some(sel) = self.selected_app {
            if !self.apps.iter().any(|a| a.id == sel) {
                self.selected_app = None;
            }
        }

        self.status = format!(
            "Refreshed: {} applications ({} with active network), {} network adapters.",
            self.apps.len(),
            self.active_network_pids.len(),
            self.interfaces.len()
        );
    }

    #[allow(dead_code)]
    pub fn selected_app_entry(&self) -> Option<&AppEntry> {
        self.selected_app.and_then(|id| self.apps.iter().find(|a| a.id == id))
    }

    pub fn direct_interface(&self) -> Option<&InterfaceInfo> {
        self.selected_direct_if.and_then(|i| self.interfaces.iter().find(|x| x.index == i))
    }

    pub fn add_custom_file(&mut self) {
        if let Some(app) = discovery::pick_executable_file() {
            let id = app.id;
            if !self.apps.iter().any(|a| a.executable.eq_ignore_ascii_case(&app.executable)) {
                self.apps.push(app.clone());
                self.store.custom_apps.push(app);
                self.save();
            }
            self.selected_app = Some(id);
            self.status = "Application added successfully.".into();
        }
    }

    pub fn is_app_blocked(&self, app_id: Uuid) -> bool {
        if self.store.blocked_apps.contains(&app_id) {
            return true;
        }
        if let Some(app) = self.apps.iter().find(|a| a.id == app_id) {
            let clean = app.executable.to_ascii_lowercase();
            return self
                .store
                .blocked_executables
                .iter()
                .any(|e| e.to_ascii_lowercase() == clean);
        }
        false
    }

    pub fn toggle_block_internet(&mut self, app_id: Uuid) {
        let Some(app) = self.apps.iter().find(|a| a.id == app_id).cloned() else {
            return;
        };

        if self.is_app_blocked(app_id) {
            match crate::windows::firewall::unblock_app(&app_id) {
                Ok(_) => {
                    self.store.blocked_apps.retain(|id| *id != app_id);
                    self.store
                        .blocked_executables
                        .retain(|e| !e.eq_ignore_ascii_case(&app.executable));
                    self.save();
                    self.status = format!("✅ Internet access unblocked for {}.", app.name);
                }
                Err(e) => {
                    self.status = format!("Failed to unblock {}: {}", app.name, e);
                }
            }
        } else {
            // If the app is currently bypassed, disable the bypass first
            if self.manager.is_active(app_id) {
                let _ = self.manager.remove(app_id);
                self.update_active_profile_rule(app_id, false);
            }

            match crate::windows::firewall::block_app(&app_id, &app.name, &app.executable) {
                Ok(_) => {
                    if !self.store.blocked_apps.contains(&app_id) {
                        self.store.blocked_apps.push(app_id);
                    }
                    if !self
                        .store
                        .blocked_executables
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(&app.executable))
                    {
                        self.store.blocked_executables.push(app.executable.clone());
                    }
                    self.save();
                    self.status = format!(
                        "🚫 Internet access completely blocked for {}! Windows Firewall is now blocking all connections.",
                        app.name
                    );
                }
                Err(e) => {
                    self.status = format!("Failed to block {}: {}", app.name, e);
                }
            }
        }
    }

    pub fn unblock_all_apps(&mut self) {
        crate::windows::firewall::clear_all_blocked_rules(&self.store.blocked_apps);
        let count = self.store.blocked_apps.len().max(self.store.blocked_executables.len());
        self.store.blocked_apps.clear();
        self.store.blocked_executables.clear();
        self.save();
        self.status = format!(
            "✅ All {} blocked applications have been unblocked from Windows Firewall.",
            count
        );
    }

    pub fn is_app_bypassed(&self, app_id: Uuid) -> bool {
        if self.manager.is_active(app_id) {
            return true;
        }
        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter().find(|p| p.id == pid) {
                return p.rules.iter().any(|r| r.app_id == app_id && r.enabled);
            }
        }
        false
    }

    pub fn set_selected_adapter(&mut self, idx: u32) {
        self.selected_direct_if = Some(idx);
        self.store.selected_adapter_index = Some(idx);
        if let Some(active_pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == active_pid) {
                p.adapter_index = Some(idx);
            }
        }
        self.save();
        let _ = self.manager.clear_all();
        self.apply_active_profile_rules();
        if let Some(iface) = self.interfaces.iter().find(|i| i.index == idx) {
            self.status = format!("Direct network adapter set to '{}' for active profile.", iface.name);
        }
    }

    pub fn has_unsaved_changes(&self) -> bool {
        let Some(pid) = self.store.active_profile else { return false; };
        if let Some(p) = self.store.profiles.iter().find(|p| p.id == pid) {
            return p.rules != self.active_profile_baseline;
        }
        false
    }

    pub fn revert_active_profile(&mut self) {
        let Some(pid) = self.store.active_profile else { return; };
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == pid) {
            p.rules = self.active_profile_baseline.clone();
        }
        self.save();
        let _ = self.manager.clear_all();
        self.apply_active_profile_rules();
        self.status = "Reverted profile changes to last saved state.".into();
    }

    pub fn toggle_bypass(&mut self) {
        let Some(app_id) = self.selected_app else {
            self.status = "Select an application first.".into();
            return;
        };

        let Some(app) = self.apps.iter().find(|a| a.id == app_id).cloned() else {
            return;
        };

        if self.is_app_blocked(app_id) {
            self.status = format!("Cannot enable bypass: {} is currently blocked from internet.", app.name);
            return;
        }

        let currently_bypassed = self.is_app_bypassed(app_id);

        if currently_bypassed {
            let _ = self.manager.remove(app_id);
            self.update_active_profile_rule(app_id, false);
            self.status = format!("Bypass disabled for {}", app.name);
            return;
        }

        self.update_active_profile_rule(app_id, true);

        if let Some(direct) = self.direct_interface().cloned() {
            let exe_path = PathBuf::from(&app.executable);
            match self.manager.apply(app_id, exe_path, &direct) {
                Ok(_) => {
                    self.status = format!(
                        "Direct bypass activated for {}! New connections will route via {}.",
                        app.name, direct.name
                    );
                }
                Err(e) => {
                    self.status = format!("Saved in profile (live route warning: {})", e);
                }
            }
        } else {
            self.status = format!(
                "Added '{}' to profile bypasses. (Select an adapter in Network tab to start routing).",
                app.name
            );
        }
    }

    pub fn launch_selected(&mut self) {
        let Some(app_id) = self.selected_app else {
            self.status = "Select an application first.".into();
            return;
        };

        let Some(app) = self.apps.iter().find(|a| a.id == app_id).cloned() else {
            return;
        };

        if self.is_app_blocked(app_id) {
            self.status = format!("Cannot launch bypass: {} is currently blocked from internet.", app.name);
            return;
        }

        let Some(direct) = self.direct_interface().cloned() else {
            self.status = "Please select a direct physical network adapter first.".into();
            return;
        };

        let exe_path = PathBuf::from(&app.executable);
        match self.manager.launch(app_id, &exe_path, &direct) {
            Ok(pid) => {
                self.update_active_profile_rule(app_id, true);
                self.status = format!(
                    "Launched {} (PID: {}) directly bypassing VPN via {}!",
                    app.name, pid, direct.name
                );
            }
            Err(e) => {
                self.status = format!("Failed to launch app: {}", e);
            }
        }
    }

    pub fn disable_all(&mut self) {
        let _ = self.manager.clear_all();
        injector::clear_target_ip();
        self.status = "All active bypasses paused in memory. Profile rules preserved.".into();
    }

    pub fn switch_profile(&mut self, profile_id: Uuid) {
        // 1. Clear active live bypass enforcement in memory without altering stored profile rules
        let _ = self.manager.clear_all();

        // 2. Set active profile
        self.store.active_profile = Some(profile_id);

        // 3. Apply adapter preference from this profile if saved and valid
        if let Some(p) = self.store.profiles.iter().find(|p| p.id == profile_id) {
            if let Some(saved_idx) = p.adapter_index {
                if self.interfaces.iter().any(|i| i.index == saved_idx) {
                    self.selected_direct_if = Some(saved_idx);
                    self.store.selected_adapter_index = Some(saved_idx);
                }
            }
            self.active_profile_baseline = p.rules.clone();
        }

        self.save();

        // 4. Apply all enabled rules from the new active profile
        self.apply_active_profile_rules();

        if let Some(p) = self.store.profiles.iter().find(|x| x.id == profile_id) {
            let active_count = p.rules.iter().filter(|r| r.enabled).count();
            self.status = format!("Activated profile '{}' ({} rules active).", p.name, active_count);
        }
    }

    pub fn create_profile(&mut self, name: String, copy_current: bool) -> Uuid {
        let new_id = Uuid::new_v4();
        let rules = if copy_current {
            let mut current_rules = Vec::new();
            if let Some(active_pid) = self.store.active_profile {
                if let Some(active_p) = self.store.profiles.iter().find(|p| p.id == active_pid) {
                    current_rules = active_p.rules.clone();
                }
            }
            for (app_id, bypass) in &self.manager.active {
                if !current_rules.iter().any(|r| r.app_id == *app_id) {
                    current_rules.push(BypassRule {
                        app_id: *app_id,
                        enabled: true,
                        exe_path: Some(bypass.exe_path.to_string_lossy().to_string()),
                    });
                }
            }

            // Restore previously active profile to its baseline so previous profile is not mutated by the new profile's changes!
            if let Some(prev_pid) = self.store.active_profile {
                if let Some(prev_p) = self.store.profiles.iter_mut().find(|p| p.id == prev_pid) {
                    prev_p.rules = self.active_profile_baseline.clone();
                }
            }

            current_rules
        } else {
            vec![]
        };

        let new_profile = Profile {
            id: new_id,
            name: name.clone(),
            enabled: true,
            priority: 100,
            rules: rules.clone(),
            adapter_index: self.selected_direct_if,
        };

        self.store.profiles.push(new_profile);
        self.store.active_profile = Some(new_id);
        self.active_profile_baseline = rules;
        self.save();

        let _ = self.manager.clear_all();
        self.apply_active_profile_rules();

        self.status = format!("Created and activated profile '{}'.", name);
        new_id
    }

    pub fn delete_profile(&mut self, profile_id: Uuid) -> Result<(), String> {
        if self.store.profiles.len() <= 1 {
            return Err("Cannot delete the only remaining profile.".into());
        }

        let is_active = self.store.active_profile == Some(profile_id);

        let removed_name = if let Some(pos) = self.store.profiles.iter().position(|p| p.id == profile_id) {
            let p = self.store.profiles.remove(pos);
            p.name
        } else {
            return Err("Profile not found.".into());
        };

        if is_active {
            let next_id = self.store.profiles[0].id;
            self.switch_profile(next_id);
        } else {
            self.save();
        }

        self.status = format!("Deleted profile '{}'.", removed_name);
        Ok(())
    }

    pub fn duplicate_profile(&mut self, profile_id: Uuid) -> Option<Uuid> {
        let profile = self.store.profiles.iter().find(|p| p.id == profile_id)?.clone();
        let new_id = Uuid::new_v4();
        let new_name = format!("{} (Copy)", profile.name);
        let new_profile = Profile {
            id: new_id,
            name: new_name.clone(),
            enabled: true,
            priority: profile.priority,
            rules: profile.rules.clone(),
            adapter_index: profile.adapter_index,
        };
        self.store.profiles.push(new_profile);
        self.save();
        self.status = format!("Duplicated profile to '{}'.", new_name);
        Some(new_id)
    }

    pub fn rename_profile(&mut self, profile_id: Uuid, new_name: String) {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == profile_id) {
            p.name = trimmed.to_string();
            self.save();
            self.status = format!("Renamed profile to '{}'.", trimmed);
        }
    }

    pub fn save_current_bypasses_to_active_profile(&mut self) {
        let Some(active_pid) = self.store.active_profile else { return; };

        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == active_pid) {
            p.adapter_index = self.selected_direct_if;
            self.active_profile_baseline = p.rules.clone();
            let count = p.rules.iter().filter(|r| r.enabled).count();
            let name = p.name.clone();
            self.save();
            self.status = format!("Saved {} bypass rules into active profile '{}'.", count, name);
        }
    }

    pub fn remove_rule_from_profile(&mut self, profile_id: Uuid, app_id: Uuid) {
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == profile_id) {
            p.rules.retain(|r| r.app_id != app_id);
            self.save();
        }
        if self.store.active_profile == Some(profile_id) {
            let _ = self.manager.remove(app_id);
        }
    }

    fn update_active_profile_rule(&mut self, app_id: Uuid, enabled: bool) {
        let exe_path = self
            .apps
            .iter()
            .find(|a| a.id == app_id)
            .map(|a| a.executable.clone());

        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter_mut().find(|x| x.id == pid) {
                if enabled {
                    if let Some(r) = p.rules.iter_mut().find(|r| {
                        r.app_id == app_id
                            || (r.exe_path.is_some() && r.exe_path == exe_path)
                    }) {
                        r.app_id = app_id;
                        r.enabled = true;
                        if r.exe_path.is_none() {
                            r.exe_path = exe_path;
                        }
                    } else {
                        p.rules.push(BypassRule {
                            app_id,
                            enabled: true,
                            exe_path,
                        });
                    }
                } else {
                    p.rules.retain(|r| {
                        !(r.app_id == app_id
                            || (r.exe_path.is_some() && exe_path.is_some() && r.exe_path == exe_path))
                    });
                }
            }
            self.save();
        }
    }

    pub fn apply_active_profile_rules(&mut self) {
        let Some(pid) = self.store.active_profile else { return; };
        let rules = match self.store.profiles.iter().find(|p| p.id == pid) {
            Some(p) => p.rules.clone(),
            None => return,
        };

        let Some(direct) = self.direct_interface().cloned() else { return; };

        for rule in rules {
            if rule.enabled {
                let app = self
                    .apps
                    .iter()
                    .find(|a| a.id == rule.app_id)
                    .or_else(|| {
                        if let Some(exe) = &rule.exe_path {
                            self.apps.iter().find(|a| a.executable.eq_ignore_ascii_case(exe))
                        } else {
                            None
                        }
                    });

                if let Some(app) = app {
                    let exe = PathBuf::from(&app.executable);
                    let _ = self.manager.apply(app.id, exe, &direct);
                }
            }
        }
    }

    pub fn tick_watchdog(&mut self) {
        if self.last_watchdog.elapsed().as_millis() > 1500 {
            self.last_watchdog = Instant::now();
            self.update_running_cache();
            self.manager.check_watchdog();
        }
    }
}
