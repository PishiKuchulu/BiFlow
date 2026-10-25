use crate::{
    config, discovery,
    enforcement::EnforcementManager,
    models::*,
    network,
    windows::{autostart, injector},
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
    /// Shared with the background watchdog thread: enforcement (process
    /// scanning + injection + adapter-IP tracking) runs there, not on the
    /// UI thread, and keeps working while the window is hidden in the tray.
    pub manager: Arc<Mutex<EnforcementManager>>,
    /// Selected adapter index mirrored for the watchdog thread.
    pub watchdog_adapter: Arc<Mutex<Option<u32>>>,
    /// True when the config file existed but could not be read at startup;
    /// saving is then disabled so defaults never overwrite the real config.
    pub config_load_failed: bool,
    /// Set by Disable All while profile rules remain: the UI offers Resume.
    pub bypass_paused: bool,
    /// Per-app (running, has-active-network) snapshot refreshed with the
    /// process cache, so per-frame UI rendering does no repeated scans.
    pub app_status: HashMap<Uuid, (bool, bool)>,
    pub last_watchdog: Instant,
    pub filter_running_only: bool,
    pub filter_net_only: bool,
    pub filter_bypassed_only: bool,
    pub filter_blocked_only: bool,
    pub process_parents: HashMap<u32, u32>,
    pub pid_to_path: HashMap<u32, String>,
    pub active_network_pids: HashSet<u32>,
    pub active_profile_baseline: Vec<BypassRule>,
}

impl AppState {
    /// Locks the shared enforcement manager, recovering from poisoning so a
    /// panicked watchdog cycle can never wedge the UI.
    pub fn manager(&self) -> std::sync::MutexGuard<'_, EnforcementManager> {
        self.manager.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One-shot status map for a whole UI frame (one lock instead of two
    /// locks per rendered row).
    pub fn live_status_map(
        &self,
    ) -> HashMap<Uuid, (crate::enforcement::BypassLiveStatus, Option<String>)> {
        self.manager().live_status_map()
    }

    pub fn active_bypass_ids(&self) -> HashSet<Uuid> {
        self.manager().active_ids()
    }

    pub fn active_bypass_count(&self) -> usize {
        self.manager().count()
    }

    /// Paused means "the active profile has enabled rules that are not
    /// currently enforced". Recomputed after every change instead of being
    /// cleared by a single toggle, so enabling one app while paused can
    /// never hide the Resume action for the others.
    pub fn recompute_paused(&mut self) {
        let active = self.active_bypass_ids();
        self.bypass_paused = match self.store.active_profile {
            Some(pid) => self
                .store
                .profiles
                .iter()
                .find(|p| p.id == pid)
                .map(|p| {
                    p.enabled
                        && p.rules
                            .iter()
                            .any(|r| r.enabled && !active.contains(&r.app_id))
                })
                .unwrap_or(false),
            None => false,
        };
    }

    pub fn new() -> Self {
        let (mut store, config_load_failed) = match config::load() {
            Ok(s) => (s, false),
            Err(e) => {
                config::append_log(&format!("CONFIG_LOAD_FAILED {}", e));
                (Store::default(), true)
            }
        };

        // Sync autostart status with actual Windows registry
        let reg_autostart = autostart::is_autostart_enabled();
        if store.autostart != reg_autostart {
            store.autostart = reg_autostart;
        }

        let mut apps = discovery::discover();

        // Merge currently running processes immediately on launch. Matching
        // is by executable path ONLY: merging by display name used to fuse
        // two different apps that happen to share a name.
        let running = discovery::discover_running_processes();
        for r in running {
            if !apps
                .iter()
                .any(|a| a.executable.eq_ignore_ascii_case(&r.executable))
            {
                apps.push(r);
            }
        }

        // Merge custom apps from store
        for custom in &store.custom_apps {
            if !apps
                .iter()
                .any(|a| a.executable.eq_ignore_ascii_case(&custom.executable))
            {
                apps.push(custom.clone());
            }
        }

        let interfaces = network::interfaces().unwrap_or_default();

        // Choose the saved adapter (by stable GUID first, IfIndex second)
        // or the best physical direct interface.
        let selected_direct_if = Self::resolve_adapter(
            &interfaces,
            store.selected_adapter_id.as_deref(),
            store.selected_adapter_index,
        );
        // Persist the GUID of the resolved interface so profiles created
        // later (and the next startup) resolve by GUID, not by IfIndex:
        // an auto-detected selection must not leave a profile with only an
        // unstable index behind.
        if let Some(idx) = selected_direct_if {
            if let Some(iface) = interfaces.iter().find(|i| i.index == idx) {
                store.selected_adapter_id = Some(iface.adapter_id.clone());
                store.selected_adapter_index = Some(idx);
            }
        }

        // The basename-keyed process map is intentionally discarded: all
        // status decisions use full executable paths (see is_app_running).
        let (_running_processes, process_parents, pid_to_path) = injector::get_process_maps();
        let active_network_pids = network::get_active_network_pids();

        let mut state = Self {
            store,
            apps,
            interfaces,
            selected_app: None,
            selected_direct_if,
            search: String::new(),
            status: "Ready. Select an application to bypass VPN or block from internet.".into(),
            manager: Arc::new(Mutex::new(EnforcementManager::default())),
            watchdog_adapter: Arc::new(Mutex::new(selected_direct_if)),
            config_load_failed,
            bypass_paused: false,
            app_status: HashMap::new(),
            last_watchdog: Instant::now(),
            filter_running_only: false,
            filter_net_only: false,
            filter_bypassed_only: false,
            filter_blocked_only: false,
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
                adapter_id: None,
            });
            state.store.active_profile = Some(default_id);
        } else if state.store.active_profile.is_none()
            || !state
                .store
                .profiles
                .iter()
                .any(|p| Some(p.id) == state.store.active_profile)
        {
            state.store.active_profile = Some(state.store.profiles[0].id);
        }

        // Apply adapter preference from active profile if set and valid
        if let Some(active_pid) = state.store.active_profile {
            if let Some(p) = state.store.profiles.iter().find(|p| p.id == active_pid) {
                if p.adapter_id.is_some() || p.adapter_index.is_some() {
                    if let Some(idx) = Self::resolve_adapter(
                        &state.interfaces,
                        p.adapter_id.as_deref(),
                        p.adapter_index,
                    ) {
                        state.selected_direct_if = Some(idx);
                        if let Ok(mut wa) = state.watchdog_adapter.lock() {
                            *wa = Some(idx);
                        }
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

        // Reconcile firewall rules for blocked applications on startup:
        // firewall rules are persistent, so only apps whose rule is
        // actually MISSING get re-created. (Previously every blocked app
        // was deleted + re-added with several netsh/PowerShell spawns on
        // the startup path, with a brief unblocked window in between.)
        if crate::windows::privilege::is_elevated() {
            for blocked_id in &state.store.blocked_apps {
                match crate::windows::firewall::query_rule_directions(blocked_id) {
                    Ok((true, true)) => continue,
                    Ok(_) => {
                        if let Some(app) = state.apps.iter().find(|a| a.id == *blocked_id) {
                            let _ = crate::windows::firewall::block_app(
                                blocked_id,
                                &app.name,
                                &app.executable,
                            );
                        }
                    }
                    Err(e) => {
                        // Unknown is not absent: leave the existing rules
                        // alone instead of recreating (or assuming) them.
                        config::append_log(&format!("FIREWALL_VERIFY_FAILED {} {}", blocked_id, e));
                    }
                }
            }
        }

        state.refresh_app_status_cache();
        state.spawn_watchdog_thread();

        state
    }

    /// Background enforcement loop: process discovery, injection of newly
    /// started bypassed apps, and adapter-IP tracking — independent of the
    /// UI repaint cycle, so it keeps running while the window is in the tray.
    ///
    /// The cycle is split in three phases so the manager mutex is only held
    /// for short snapshot/commit steps.
    ///
    /// Snapshot (lock), plan + DLL resolve + injections (no lock), commit
    /// (lock). UI status reads therefore never queue behind a remote-thread
    /// or hook-status wait.
    fn spawn_watchdog_thread(&self) {
        let manager = self.manager.clone();
        let adapter = self.watchdog_adapter.clone();
        let _ = std::thread::Builder::new()
            .name("biflow-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                let maps = injector::get_process_maps();
                let ifaces = network::interfaces().unwrap_or_default();
                let idx = *adapter.lock().unwrap_or_else(|e| e.into_inner());
                let ip = idx
                    .and_then(|i| ifaces.iter().find(|x| x.index == i))
                    .and_then(|i| i.ipv4.clone());
                let snapshot = {
                    let mgr = manager.lock().unwrap_or_else(|e| e.into_inner());
                    mgr.watchdog_snapshot()
                };
                if snapshot.entries.is_empty() {
                    continue;
                }
                let dll_path = match injector::ensure_dll_extracted() {
                    Ok(p) => p,
                    Err(e) => {
                        config::append_log(&format!("WATCHDOG_DLL_ERROR {}", e));
                        continue;
                    }
                };
                let plan = EnforcementManager::watchdog_plan(&snapshot, &maps);
                let mut injected: HashMap<Uuid, Vec<(u32, u64)>> = HashMap::new();
                let mut errors: HashMap<Uuid, String> = HashMap::new();
                for entry in &plan {
                    for &pid in &entry.to_inject {
                        match injector::inject_dll_into_pid(pid, &dll_path) {
                            Ok(()) => {
                                injected
                                    .entry(entry.app_id)
                                    .or_default()
                                    .push((pid, injector::process_creation_time(pid).unwrap_or(0)));
                            }
                            Err(e) => {
                                errors.insert(entry.app_id, e);
                            }
                        }
                    }
                }
                let mut mgr = manager.lock().unwrap_or_else(|e| e.into_inner());
                mgr.watchdog_commit(plan, &injected, &errors, ip.as_deref());
            });
    }

    /// Resolves a saved adapter selection: stable GUID first, then IfIndex,
    /// then the best autodetected direct interface.
    fn resolve_adapter(
        interfaces: &[InterfaceInfo],
        adapter_id: Option<&str>,
        adapter_index: Option<u32>,
    ) -> Option<u32> {
        if let Some(guid) = adapter_id {
            if !guid.is_empty() {
                if let Some(i) = interfaces
                    .iter()
                    .find(|i| i.adapter_id.eq_ignore_ascii_case(guid))
                {
                    return Some(i.index);
                }
            }
        }
        if let Some(idx) = adapter_index {
            if interfaces.iter().any(|i| i.index == idx) {
                return Some(idx);
            }
        }
        Self::find_best_direct_interface(interfaces)
    }

    fn find_best_direct_interface(interfaces: &[InterfaceInfo]) -> Option<u32> {
        // A usable direct uplink must be Up, have a default gateway and a
        // real (non-APIPA) IPv4 address, and not be a VPN/virtual adapter.
        interfaces
            .iter()
            .find(|x| {
                x.status.eq_ignore_ascii_case("Up")
                    && x.gateway.is_some()
                    && x.ipv4
                        .as_deref()
                        .map(|ip| !network::is_apipa_ipv4(ip))
                        .unwrap_or(false)
                    && !network::is_likely_vpn(x)
            })
            .map(|x| x.index)
    }

    /// Persists the store. Returns Err (and leaves the error in
    /// `self.status`) when saving is disabled or fails, so callers can
    /// never report an operation as successful when it was not persisted.
    pub fn save(&mut self) -> Result<(), String> {
        if self.config_load_failed {
            self.status =
                "Config file could not be loaded at startup; saving is disabled to protect it."
                    .into();
            return Err("config load failed at startup".into());
        }
        if let Err(e) = config::save(&self.store) {
            self.status = format!("Save error: {}", e);
            return Err(e.to_string());
        }
        Ok(())
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

            // Check if already in self.apps, by executable path ONLY: a
            // same-name binary in another folder is a different app and
            // must not be swallowed by a display-name match.
            let already_exists = self
                .apps
                .iter()
                .any(|a| a.executable.eq_ignore_ascii_case(&exe_path));

            if !already_exists
                && !new_entries
                    .iter()
                    .any(|a: &AppEntry| a.executable.eq_ignore_ascii_case(&exe_path))
            {
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
        let (_running_map, parents, paths) = injector::get_process_maps();
        self.process_parents = parents;
        self.pid_to_path = paths;
        self.active_network_pids = network::get_active_network_pids();
        if let Ok(ifaces) = network::interfaces() {
            self.interfaces = ifaces;
        }
        self.auto_discover_network_apps();
        self.refresh_app_status_cache();
    }

    /// Recomputes the per-app (running, active-network) snapshot once per
    /// cache refresh. The UI reads this cache every frame instead of
    /// re-running the O(apps × processes) scans per frame.
    pub fn refresh_app_status_cache(&mut self) {
        let mut cache = HashMap::with_capacity(self.apps.len());
        for app in &self.apps {
            let running = self.is_app_running(app);
            let net = running && self.has_active_network(app);
            cache.insert(app.id, (running, net));
        }
        self.app_status = cache;
    }

    pub fn app_running_cached(&self, app: &AppEntry) -> bool {
        self.app_status.get(&app.id).map(|s| s.0).unwrap_or(false)
    }

    pub fn app_network_cached(&self, app: &AppEntry) -> bool {
        self.app_status.get(&app.id).map(|s| s.1).unwrap_or(false)
    }

    pub fn is_app_running(&self, app: &AppEntry) -> bool {
        // Full executable path ONLY: a same-name binary in another folder
        // must never make this app look running. (The basename-keyed
        // process map is deliberately not consulted here.)
        self.pid_to_path
            .values()
            .any(|p| p.eq_ignore_ascii_case(&app.executable))
    }

    pub fn has_active_network(&self, app: &AppEntry) -> bool {
        // Exact-path PIDs of this app (no basename fallback: a same-name
        // binary elsewhere must never make this app look online).
        let own_pids: Vec<u32> = self
            .pid_to_path
            .iter()
            .filter(|(_, p)| p.eq_ignore_ascii_case(&app.executable))
            .map(|(pid, _)| *pid)
            .collect();
        if own_pids
            .iter()
            .any(|p| self.active_network_pids.contains(p))
        {
            return true;
        }

        // Child process match (e.g. Steam -> steamwebhelper, Discord -> DiscordHelper, Electron apps)
        for net_pid in &self.active_network_pids {
            if let Some(parent) = self.process_parents.get(net_pid) {
                if own_pids.contains(parent) {
                    return true;
                }
            }
        }

        // Same directory / Sub-directory binary match. The prefix must
        // end at a path separator boundary: "C:\Program Files\Foo" must
        // not match processes in "C:\Program Files\FooBar".
        if let Some(app_dir) = Path::new(&app.executable).parent() {
            let app_dir_str = app_dir.to_string_lossy().to_ascii_lowercase();
            if app_dir_str.len() > 3 {
                let dir_prefix = format!("{}\\", app_dir_str.trim_end_matches('\\'));
                for net_pid in &self.active_network_pids {
                    if let Some(p) = self.pid_to_path.get(net_pid) {
                        if p.to_ascii_lowercase().starts_with(&dir_prefix) {
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
            // The registry/task is the source of truth and is re-synced at
            // startup, so a failed config save does not change the outcome.
            let _ = self.save();
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
            if !discovered
                .iter()
                .any(|a| a.executable.eq_ignore_ascii_case(&r.executable))
            {
                discovered.push(r);
            }
        }
        for custom in &self.store.custom_apps {
            if !discovered
                .iter()
                .any(|a| a.executable.eq_ignore_ascii_case(&custom.executable))
            {
                discovered.push(custom.clone());
            }
        }
        self.apps = discovered;
        self.interfaces = network::interfaces().unwrap_or_default();
        self.update_running_cache();

        // Preserve selected direct interface if still valid (GUID first)
        self.selected_direct_if = Self::resolve_adapter(
            &self.interfaces,
            self.store.selected_adapter_id.as_deref(),
            self.store
                .selected_adapter_index
                .or(self.selected_direct_if),
        );
        if let Ok(mut wa) = self.watchdog_adapter.lock() {
            *wa = self.selected_direct_if;
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
        self.selected_app
            .and_then(|id| self.apps.iter().find(|a| a.id == id))
    }

    pub fn direct_interface(&self) -> Option<&InterfaceInfo> {
        self.selected_direct_if
            .and_then(|i| self.interfaces.iter().find(|x| x.index == i))
    }

    pub fn add_custom_file(&mut self) {
        if let Some(app) = discovery::pick_executable_file() {
            let id = app.id;
            if !self
                .apps
                .iter()
                .any(|a| a.executable.eq_ignore_ascii_case(&app.executable))
            {
                self.apps.push(app.clone());
                self.store.custom_apps.push(app);
                if self.save().is_err() {
                    // save() already left the error in self.status.
                    self.selected_app = Some(id);
                    return;
                }
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
                    if self.save().is_err() {
                        // save() left the error in self.status; the block
                        // list change is live but will not survive restart.
                        return;
                    }
                    self.status = format!("✅ Internet access unblocked for {}.", app.name);
                }
                Err(e) => {
                    self.status = format!("Failed to unblock {}: {}", app.name, e);
                }
            }
        } else {
            // If the app is currently bypassed, disable the bypass first
            if self.manager().is_active(app_id) {
                let _ = self.manager().remove(app_id);
                let _ = self.update_active_profile_rule(app_id, false);
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
                    if self.save().is_err() {
                        return;
                    }
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
        match crate::windows::firewall::clear_all_blocked_rules(&self.store.blocked_apps) {
            Ok(()) => {
                let count = self
                    .store
                    .blocked_apps
                    .len()
                    .max(self.store.blocked_executables.len());
                self.store.blocked_apps.clear();
                self.store.blocked_executables.clear();
                if self.save().is_err() {
                    return;
                }
                self.status = format!(
                    "✅ All {} blocked applications have been unblocked from Windows Firewall.",
                    count
                );
            }
            Err(e) => {
                // Keep the blocked list: the rules are still in the firewall.
                self.status = format!("Failed to unblock all applications: {}", e);
            }
        }
    }

    pub fn is_app_bypassed(&self, app_id: Uuid) -> bool {
        if self.manager().is_active(app_id) {
            return true;
        }
        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter().find(|p| p.id == pid) {
                // A disabled profile's rules are dormant, not bypasses.
                return p.enabled && p.rules.iter().any(|r| r.app_id == app_id && r.enabled);
            }
        }
        false
    }

    /// Same as is_app_bypassed, but against a pre-fetched manager snapshot
    /// (one lock per frame instead of one per row).
    pub fn is_app_bypassed_cached(&self, app_id: Uuid, active: &HashSet<Uuid>) -> bool {
        if active.contains(&app_id) {
            return true;
        }
        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter().find(|p| p.id == pid) {
                return p.enabled && p.rules.iter().any(|r| r.app_id == app_id && r.enabled);
            }
        }
        false
    }

    pub fn set_selected_adapter(&mut self, idx: u32) {
        self.selected_direct_if = Some(idx);
        self.store.selected_adapter_index = Some(idx);
        let adapter_id = self
            .interfaces
            .iter()
            .find(|i| i.index == idx)
            .map(|i| i.adapter_id.clone());
        self.store.selected_adapter_id = adapter_id.clone();
        if let Ok(mut wa) = self.watchdog_adapter.lock() {
            *wa = Some(idx);
        }
        if let Some(active_pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == active_pid) {
                p.adapter_index = Some(idx);
                p.adapter_id = adapter_id;
            }
        }
        // Adapter choice is explicit, but it does not activate a dormant
        // profile: apply_active_profile_rules still skips disabled profiles.
        // A failed save does not block the live switch; it is reported in
        // the status instead of being masked by a success message.
        let saved = self.save();
        let _ = self.manager().clear_all();
        let _ = self.apply_active_profile_rules();
        self.recompute_paused();
        if let Some(iface) = self.interfaces.iter().find(|i| i.index == idx) {
            self.status = match saved {
                Ok(()) => format!(
                    "Direct network adapter set to '{}' for active profile.",
                    iface.name
                ),
                Err(e) => format!(
                    "Direct network adapter set to '{}', but the choice could not be saved: {}",
                    iface.name, e
                ),
            };
        }
    }

    pub fn has_unsaved_changes(&self) -> bool {
        let Some(pid) = self.store.active_profile else {
            return false;
        };
        if let Some(p) = self.store.profiles.iter().find(|p| p.id == pid) {
            return p.rules != self.active_profile_baseline;
        }
        false
    }

    pub fn revert_active_profile(&mut self) {
        let Some(pid) = self.store.active_profile else {
            return;
        };
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == pid) {
            p.rules = self.active_profile_baseline.clone();
        }
        let saved = self.save();
        let _ = self.manager().clear_all();
        let _ = self.apply_active_profile_rules();
        self.recompute_paused();
        self.status = match saved {
            Ok(()) => "Reverted profile changes to last saved state.".into(),
            Err(e) => format!(
                "Profile changes reverted in memory, but the revert could not be saved: {}",
                e
            ),
        };
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
            self.status = format!(
                "Cannot enable bypass: {} is currently blocked from internet.",
                app.name
            );
            return;
        }

        let currently_bypassed = self.is_app_bypassed(app_id);

        if currently_bypassed {
            let remove_result = self.manager().remove(app_id);
            if let Err(e) = remove_result {
                self.status = format!("Bypass removal failed (bypass remains active): {}", e);
                return;
            }
            if let Err(e) = self.update_active_profile_rule(app_id, false) {
                self.status = format!(
                    "Bypass disabled live, but the profile change could not be saved: {}",
                    e
                );
                return;
            }
            self.recompute_paused();
            self.status = format!("Bypass disabled for {}", app.name);
            return;
        }

        // An explicit toggle also wakes a dormant active profile.
        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == pid) {
                p.enabled = true;
            }
        }
        let saved = self.update_active_profile_rule(app_id, true);

        if let Some(direct) = self.direct_interface().cloned() {
            let exe_path = PathBuf::from(&app.executable);
            let apply_result = self.manager().apply(app_id, exe_path, &direct);
            match apply_result {
                Ok(_) => {
                    self.recompute_paused();
                    self.status = match saved {
                        Ok(()) => format!(
                            "Direct bypass activated for {}! New connections will route via {}.",
                            app.name, direct.name
                        ),
                        Err(e) => format!(
                            "Direct bypass activated for {} via {}, but the profile could not be saved (restart will lose it): {}",
                            app.name, direct.name, e
                        ),
                    };
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
            self.status = format!(
                "Cannot launch bypass: {} is currently blocked from internet.",
                app.name
            );
            return;
        }

        let Some(direct) = self.direct_interface().cloned() else {
            self.status = "Please select a direct physical network adapter first.".into();
            return;
        };

        // Single-instance apps (browsers, launchers) hand a launch request
        // to the already-running instance and exit; that instance is not
        // hooked, so warn instead of silently claiming a bypassed launch.
        let exe_path = PathBuf::from(&app.executable);
        let already_running = !injector::find_pids_by_exe_path(&exe_path).is_empty();
        let launch_result = self.manager().launch(app_id, &exe_path, &direct);
        match launch_result {
            Ok((pid, unelevated)) => {
                self.recompute_paused();
                let _ = self.update_active_profile_rule(app_id, true);
                // Honest disclosure: hooking Chromium requires disabling its
                // renderer code integrity and ignoring the system proxy.
                let file_name = Path::new(&app.executable)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                let chromium_note = if matches!(
                    file_name.as_str(),
                    "chrome.exe" | "msedge.exe" | "brave.exe"
                ) {
                    " Note: launched with RendererCodeIntegrity disabled and --no-proxy-server (required for hooking)."
                } else {
                    ""
                };
                let elevation_note = if unelevated {
                    ""
                } else {
                    " Warning: the app had to be launched with administrator rights on this system."
                };
                let running_note = if already_running {
                    " Note: this app was already running; if it forwards launches to the existing instance, that instance is not bypassed — close it first."
                } else {
                    ""
                };
                self.status = format!(
                    "Launched {} (PID: {}) with the bypass hook installed via {}. Egress route is not verified — compare public IP to confirm.{}{}{}",
                    app.name, pid, direct.name, chromium_note, elevation_note, running_note
                );
            }
            Err(e) => {
                self.status = format!("Failed to launch app: {}", e);
            }
        }
    }

    pub fn disable_all(&mut self) {
        // A failed manager clear restores the entries (fail-closed), so it
        // must be reported as "still active", not as "paused".
        let clear_result = self.manager().clear_all();
        if let Err(e) = clear_result {
            self.recompute_paused();
            self.status = format!("Could not pause bypasses (they remain active): {}", e);
            return;
        }
        let file_err = injector::clear_target_ip().err();
        self.recompute_paused();
        self.status = match file_err {
            Some(e) => format!(
                "Bypasses paused in memory, but policy file cleanup failed ({}); already-injected processes may keep bypassing until cleanup succeeds",
                e
            ),
            None => "All active bypasses paused. Profile rules preserved — use Resume Bypasses to re-apply them.".into(),
        };
    }

    pub fn bypasses_paused(&self) -> bool {
        self.bypass_paused
    }

    pub fn resume_all(&mut self) {
        // An explicit resume also wakes a dormant active profile; the
        // recompute below keeps Resume visible if any rule still failed.
        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == pid) {
                p.enabled = true;
            }
        }
        let (applied, failed) = self.apply_active_profile_rules();
        self.recompute_paused();
        self.status = if failed > 0 {
            format!(
                "Bypasses resumed from the active profile rules ({} applied, {} failed).",
                applied, failed
            )
        } else {
            "Bypasses resumed from the active profile rules.".into()
        };
    }

    pub fn switch_profile(&mut self, profile_id: Uuid) {
        // 1. Clear active live bypass enforcement in memory without altering stored profile rules
        let _ = self.manager().clear_all();

        // 2. Set active profile. Switching to a profile is an explicit
        // activation, so a dormant profile wakes up here.
        self.store.active_profile = Some(profile_id);
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == profile_id) {
            p.enabled = true;
        }

        // 3. Apply adapter preference from this profile if saved and valid
        if let Some(p) = self.store.profiles.iter().find(|p| p.id == profile_id) {
            if p.adapter_id.is_some() || p.adapter_index.is_some() {
                if let Some(idx) = Self::resolve_adapter(
                    &self.interfaces,
                    p.adapter_id.as_deref(),
                    p.adapter_index,
                ) {
                    self.selected_direct_if = Some(idx);
                    self.store.selected_adapter_index = Some(idx);
                    self.store.selected_adapter_id = p.adapter_id.clone();
                    if let Ok(mut wa) = self.watchdog_adapter.lock() {
                        *wa = Some(idx);
                    }
                }
            }
        }

        // The baseline tracks the last PERSISTED rules: only move it when
        // the save succeeds, or "Modified" would describe a change that was
        // never actually saved.
        let baseline = self
            .store
            .profiles
            .iter()
            .find(|p| p.id == profile_id)
            .map(|p| p.rules.clone());
        let saved = self.save();
        if saved.is_ok() {
            if let Some(rules) = baseline {
                self.active_profile_baseline = rules;
            }
        }

        // 4. Apply all enabled rules from the new active profile
        let _ = self.apply_active_profile_rules();
        self.recompute_paused();

        if let Some(p) = self.store.profiles.iter().find(|x| x.id == profile_id) {
            let active_count = p.rules.iter().filter(|r| r.enabled).count();
            self.status = match saved {
                Ok(()) => format!("Activated profile '{}' ({} rules active).", p.name, active_count),
                Err(e) => format!(
                    "Activated profile '{}' ({} rules active), but the switch could not be saved: {}",
                    p.name, active_count, e
                ),
            };
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
            {
                let mgr = self.manager();
                for (app_id, bypass) in &mgr.active {
                    if !current_rules.iter().any(|r| r.app_id == *app_id) {
                        current_rules.push(BypassRule {
                            app_id: *app_id,
                            enabled: true,
                            exe_path: Some(bypass.exe_path.to_string_lossy().to_string()),
                        });
                    }
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

        // Resolve the adapter GUID from the selected interface: a profile
        // created from an auto-detected selection must not carry only an
        // unstable IfIndex.
        let adapter_id = self
            .selected_direct_if
            .and_then(|idx| {
                self.interfaces
                    .iter()
                    .find(|i| i.index == idx)
                    .map(|i| i.adapter_id.clone())
            })
            .or_else(|| self.store.selected_adapter_id.clone());
        let new_profile = Profile {
            id: new_id,
            name: name.clone(),
            enabled: true,
            priority: 100,
            rules: rules.clone(),
            adapter_index: self.selected_direct_if,
            adapter_id,
        };

        self.store.profiles.push(new_profile);
        self.store.active_profile = Some(new_id);
        let saved = self.save();
        if saved.is_ok() {
            self.active_profile_baseline = rules;
        }

        let _ = self.manager().clear_all();
        let _ = self.apply_active_profile_rules();
        self.recompute_paused();

        self.status = match saved {
            Ok(()) => format!("Created and activated profile '{}'.", name),
            Err(e) => format!(
                "Created and activated profile '{}', but it could not be saved: {}",
                name, e
            ),
        };
        new_id
    }

    pub fn delete_profile(&mut self, profile_id: Uuid) -> Result<(), String> {
        if self.store.profiles.len() <= 1 {
            return Err("Cannot delete the only remaining profile.".into());
        }

        let is_active = self.store.active_profile == Some(profile_id);

        let removed_name =
            if let Some(pos) = self.store.profiles.iter().position(|p| p.id == profile_id) {
                let p = self.store.profiles.remove(pos);
                p.name
            } else {
                return Err("Profile not found.".into());
            };

        if is_active {
            let next_id = self.store.profiles[0].id;
            self.switch_profile(next_id);
        } else if self.save().is_err() {
            // save() left the error in self.status; the deletion is live
            // but will not survive restart.
            return Ok(());
        }

        self.status = format!("Deleted profile '{}'.", removed_name);
        Ok(())
    }

    pub fn duplicate_profile(&mut self, profile_id: Uuid) -> Option<Uuid> {
        let profile = self
            .store
            .profiles
            .iter()
            .find(|p| p.id == profile_id)?
            .clone();
        let new_id = Uuid::new_v4();
        let new_name = format!("{} (Copy)", profile.name);
        let new_profile = Profile {
            id: new_id,
            name: new_name.clone(),
            enabled: true,
            priority: profile.priority,
            rules: profile.rules.clone(),
            adapter_index: profile.adapter_index,
            adapter_id: profile.adapter_id.clone(),
        };
        self.store.profiles.push(new_profile);
        self.status = match self.save() {
            Ok(()) => format!("Duplicated profile to '{}'.", new_name),
            Err(e) => format!(
                "Duplicated profile to '{}', but it could not be saved: {}",
                new_name, e
            ),
        };
        Some(new_id)
    }

    pub fn rename_profile(&mut self, profile_id: Uuid, new_name: String) {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == profile_id) {
            p.name = trimmed.to_string();
            if self.save().is_err() {
                return;
            }
            self.status = format!("Renamed profile to '{}'.", trimmed);
        }
    }

    pub fn save_current_bypasses_to_active_profile(&mut self) {
        let Some(active_pid) = self.store.active_profile else {
            return;
        };

        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == active_pid) {
            p.adapter_index = self.selected_direct_if;
            // Resolve the GUID from the selected interface as well, so a
            // saved profile never carries only an unstable IfIndex.
            p.adapter_id = self
                .selected_direct_if
                .and_then(|idx| {
                    self.interfaces
                        .iter()
                        .find(|i| i.index == idx)
                        .map(|i| i.adapter_id.clone())
                })
                .or_else(|| p.adapter_id.clone());
            let count = p.rules.iter().filter(|r| r.enabled).count();
            let name = p.name.clone();
            let rules = p.rules.clone();
            // Baseline tracks the last PERSISTED rules: only move it when
            // the save succeeds.
            if self.save().is_ok() {
                self.active_profile_baseline = rules;
                self.status = format!(
                    "Saved {} bypass rules into active profile '{}'.",
                    count, name
                );
            }
        }
    }

    pub fn remove_rule_from_profile(&mut self, profile_id: Uuid, app_id: Uuid) {
        if let Some(p) = self.store.profiles.iter_mut().find(|p| p.id == profile_id) {
            p.rules.retain(|r| r.app_id != app_id);
            let rules = p.rules.clone();
            // Keep the baseline honest for the active profile: a saved
            // removal must not leave "Modified" behind.
            if self.save().is_ok() && self.store.active_profile == Some(profile_id) {
                self.active_profile_baseline = rules;
            }
        }
        if self.store.active_profile == Some(profile_id) {
            let _ = self.manager().remove(app_id);
        }
    }

    /// Updates the active profile's rule for one app and persists it
    /// immediately. The baseline moves only when the save succeeds, so a
    /// toggle can never be both "already saved" and "Modified", and
    /// Revert can never undo a change that is already on disk.
    fn update_active_profile_rule(&mut self, app_id: Uuid, enabled: bool) -> Result<(), String> {
        let exe_path = self
            .apps
            .iter()
            .find(|a| a.id == app_id)
            .map(|a| a.executable.clone());

        if let Some(pid) = self.store.active_profile {
            if let Some(p) = self.store.profiles.iter_mut().find(|x| x.id == pid) {
                if enabled {
                    if let Some(r) = p.rules.iter_mut().find(|r| {
                        r.app_id == app_id || (r.exe_path.is_some() && r.exe_path == exe_path)
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
                            || (r.exe_path.is_some()
                                && exe_path.is_some()
                                && r.exe_path == exe_path))
                    });
                }
            }
            let rules = self
                .store
                .profiles
                .iter()
                .find(|x| x.id == pid)
                .map(|p| p.rules.clone());
            self.save()?;
            if let Some(rules) = rules {
                self.active_profile_baseline = rules;
            }
        }
        Ok(())
    }

    /// Applies the active profile's enabled rules to the enforcement
    /// manager. Returns (applied, failed). A disabled profile applies
    /// nothing: its rules are dormant until an explicit action wakes it.
    /// A rule whose app was never discovered is still registered (by its
    /// stored exe_path), so the watchdog injects the process when it later
    /// appears instead of silently dropping the rule at startup.
    pub fn apply_active_profile_rules(&mut self) -> (usize, usize) {
        let Some(pid) = self.store.active_profile else {
            return (0, 0);
        };
        let (enabled, rules) = match self.store.profiles.iter().find(|p| p.id == pid) {
            Some(p) => (p.enabled, p.rules.clone()),
            None => return (0, 0),
        };
        if !enabled {
            return (0, 0);
        }

        let Some(direct) = self.direct_interface().cloned() else {
            return (0, 0);
        };

        let mut applied = 0;
        let mut failed = 0;
        for rule in rules {
            if rule.enabled {
                let app = self.apps.iter().find(|a| a.id == rule.app_id).or_else(|| {
                    if let Some(exe) = &rule.exe_path {
                        self.apps
                            .iter()
                            .find(|a| a.executable.eq_ignore_ascii_case(exe))
                    } else {
                        None
                    }
                });

                let target: Option<(Uuid, PathBuf)> = if let Some(app) = app {
                    Some((app.id, PathBuf::from(&app.executable)))
                } else if let Some(exe) = &rule.exe_path {
                    Some((rule.app_id, PathBuf::from(exe)))
                } else {
                    None
                };
                if let Some((id, exe)) = target {
                    match self.manager().apply(id, exe, &direct) {
                        Ok(()) => applied += 1,
                        Err(_) => failed += 1,
                    }
                }
            }
        }
        (applied, failed)
    }

    /// UI-cadence refresh tick (process cache + adapter list). Enforcement
    /// itself lives on the background watchdog thread; this only keeps the
    /// data the UI renders fresh.
    pub fn tick_watchdog(&mut self) {
        if self.last_watchdog.elapsed().as_millis() > 1500 {
            self.last_watchdog = Instant::now();
            self.update_running_cache();
        }
    }
}
