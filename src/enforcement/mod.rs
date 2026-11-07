use crate::{config, models::InterfaceInfo, network, windows::injector};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// One definition of the process-map shape for the whole crate (the
/// injector produces it, the watchdog consumes it). It used to be
/// re-declared here as a second, identical tuple type.
pub type ProcessMaps = injector::ProcessMaps;

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
    /// Executable paths of descendant/helper processes the watchdog
    /// injects for this app (same install tree, verified parent chain).
    /// The hook only bypasses processes whose own path is on the policy
    /// allow-list, so these paths are published alongside the app's own:
    /// without them a helper was hooked (and shown Live) but never
    /// actually bypassed. Maintained by watchdog_plan/watchdog_commit.
    pub helper_paths: HashSet<String>,
    /// True when the app was not running at apply time; the watchdog injects on launch.
    pub awaiting_process: bool,
    /// Set when the app was running but every injection attempt failed.
    pub inject_error: Option<String>,
}

/// Honest live status of a bypass, so the UI never claims an active bypass
/// when the hook DLL is not actually inside the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassLiveStatus {
    /// Hook DLL is injected into every known live process of the app,
    /// with no recorded injection failure.
    Live,
    /// Hook DLL is injected into at least one live process, but
    /// injection failed for at least one other process of the same app:
    /// only the hooked processes bypass.
    Partial,
    /// App is not running; the watchdog will inject when it starts.
    Pending,
    /// App is running but injection failed for every process.
    Failed,
}

/// Snapshot of enforcement state for one watchdog cycle. Cloned under
/// a short lock so the blocking injection work (remote-thread waits,
/// hook-status waits) happens WITHOUT holding the manager mutex: UI
/// status reads must never queue behind an injection.
pub struct WatchdogSnapshot {
    pub entries: Vec<ActiveBypass>,
}

/// Per-entry plan computed from a snapshot + process maps (no locks,
/// no injection): which PIDs are current, which injected PIDs survive,
/// which PIDs still need injection.
pub struct WatchdogPlanEntry {
    pub app_id: Uuid,
    /// The entry's injected-PID map as the plan saw it. Commit compares
    /// the live entry against this: if they differ, a UI operation
    /// changed the entry while the watchdog was injecting, and the
    /// plan's bookkeeping must not overwrite the newer live state.
    pub base_injected: HashMap<u32, u64>,
    pub pruned_injected: HashMap<u32, u64>,
    pub had_pids: bool,
    pub to_inject: Vec<u32>,
    /// Executable paths of currently-running descendant processes (the
    /// allow-list additions for this cycle; see ActiveBypass::helper_paths).
    pub helper_paths: Vec<String>,
}

#[derive(Debug, Default)]
pub struct EnforcementManager {
    pub active: HashMap<Uuid, ActiveBypass>,
    target_ip: Option<String>,
    /// Consecutive watchdog cycles that saw no usable direct adapter IPv4.
    /// After two cycles the policy is fail-closed (see watchdog_commit).
    adapter_missing_cycles: u32,
    /// Lowercased allow-list paths as last successfully published, so the
    /// watchdog can republish only when the effective set changes (a new
    /// helper appeared, a helper exited) instead of rewriting the policy
    /// files every cycle.
    published_allow: HashSet<String>,
    /// The most recent policy-publish failure, cleared by the next
    /// successful publish. Surfaced through live_status_map so the UI can
    /// warn that on-disk policy may be a stale generation instead of
    /// deriving "Live" from in-memory bookkeeping alone.
    last_policy_error: Option<String>,
}

impl EnforcementManager {
    /// Writes the target-IP file and the bypassed-apps allow-list so the
    /// injected hook DLLs pick up the current policy (or its removal).
    /// When nothing is active, all policy files are deleted, which the hook
    /// interprets as "bypass disabled". Failures are returned: a caller
    /// must never treat a bypass as live when its policy was not published.
    fn sync_policy_files(&mut self) -> Result<(), String> {
        let result: Result<(), String> = match &self.target_ip {
            Some(ip) if !self.active.is_empty() => {
                // Publish the allow-list FIRST and the target IP second:
                // during the intermediate state (new list, previous or
                // absent IP file) the hook either binds to the previous
                // generation's address or stays off, whereas IP-first
                // would pair the NEW address with the PREVIOUS allow-list
                // generation for the window between the two renames.
                // The allow-list is every path the hook must bypass: each
                // app's own executable PLUS the helper/descendant paths the
                // watchdog injected for it. A hooked process whose path is
                // missing here loads the DLL but never bypasses.
                let mut set: HashSet<String> = HashSet::new();
                for b in self.active.values() {
                    set.insert(b.exe_path.to_string_lossy().to_string());
                    for h in &b.helper_paths {
                        set.insert(h.clone());
                    }
                }
                let mut paths: Vec<String> = set.iter().cloned().collect();
                paths.sort();
                // No `?` inside these arms (AUD-002): this match is a
                // plain expression, not a closure, so `?` would return
                // from sync_policy_files itself and skip the
                // last_policy_error bookkeeping below — the latch would
                // never be set on exactly the failures it exists for.
                // Capture the result instead and let it flow through.
                let r = injector::update_bypass_app_list(&paths)
                    .and_then(|()| injector::update_target_ip(ip));
                if r.is_ok() {
                    self.published_allow = set.iter().map(|s| s.to_ascii_lowercase()).collect();
                }
                r
            }
            _ => {
                let r = injector::clear_target_ip();
                if r.is_ok() {
                    self.published_allow.clear();
                }
                r
            }
        };
        // A failed publish is remembered until the next successful one:
        // the UI's "Live" derivation otherwise has no way to know the
        // on-disk policy may be a stale generation.
        match &result {
            Ok(()) => self.last_policy_error = None,
            Err(e) => self.last_policy_error = Some(e.clone()),
        }
        result
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
        // An APIPA (link-local) address is not a usable source: the adapter
        // has no DHCP lease, so binding to it cannot reach anything. Treat
        // it exactly like a missing IPv4 instead of publishing it.
        if network::is_apipa_ipv4(&source_ip) {
            return Err(
                "Direct interface has only an APIPA (link-local) address; no usable IPv4".into(),
            );
        }

        // Validate BEFORE mutating any state: an empty exe name used to
        // insert a permanently-Failed entry whose path still landed on
        // the published allow-list, and an earlier revision of this check
        // ran after target_ip had already been overwritten — the error
        // path then left the manager pointing at an IP no entry used.
        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        if exe_name.is_empty() {
            return Err("Executable path has no file name".into());
        }

        let dll_path = injector::ensure_dll_extracted()?;
        let prev_ip = self.target_ip.clone();
        self.target_ip = Some(source_ip);
        self.adapter_missing_cycles = 0;

        let mut injected_pids: HashMap<u32, u64> = HashMap::new();
        let mut awaiting_process = false;
        let mut inject_error: Option<String> = None;
        let mut partial_error: Option<String> = None;

        {
            // Match by full executable path so same-name binaries in other
            // folders are never injected by accident.
            let pids = injector::find_pids_by_exe_path(&exe);
            if pids.is_empty() {
                awaiting_process = true;
            } else {
                let total_pids = pids.len();
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
                    inject_error = last_err.or_else(|| Some("DLL injection failed".into()));
                } else if let Some(e) = &last_err {
                    // Partial injection is real information: some PIDs of
                    // this app are hooked, others are not. It used to
                    // vanish (only total failure was recorded anywhere);
                    // now it is also recorded on the entry itself, so the
                    // derived status is Partial instead of a blanket Live
                    // (AUD-004).
                    let failed = total_pids - injected_pids.len();
                    config::append_log(&format!(
                        "INJECT_PARTIAL app={} exe={} ok={} err={}",
                        app_id,
                        exe.display(),
                        injected_pids.len(),
                        e
                    ));
                    partial_error = Some(format!(
                        "Injection failed for {} of {} processes: {}",
                        failed, total_pids, e
                    ));
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
                helper_paths: HashSet::new(),
                awaiting_process,
                inject_error: inject_error.clone().or(partial_error),
            },
        );
        // Publish the policy before claiming success. On failure, roll the
        // entry back and restore the previous policy so a half-published
        // state can never masquerade as an active bypass.
        if let Err(e) = self.sync_policy_files() {
            self.active.remove(&app_id);
            self.target_ip = prev_ip;
            let _ = self.sync_policy_files();
            return Err(format!(
                "Bypass configured, but policy could not be published: {}",
                e
            ));
        }

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
                return Err(format!(
                    "Bypass configured, but live injection failed: {}",
                    err
                ));
            }
        }

        Ok(())
    }

    pub fn launch(
        &mut self,
        app_id: Uuid,
        exe: &Path,
        direct: &InterfaceInfo,
    ) -> Result<(u32, bool), String> {
        let source_ip = direct
            .ipv4
            .clone()
            .ok_or("Direct interface has no valid IPv4 address")?;
        if network::is_apipa_ipv4(&source_ip) {
            return Err(
                "Direct interface has only an APIPA (link-local) address; no usable IPv4".into(),
            );
        }

        let exe_name = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        if exe_name.is_empty() {
            return Err("Executable path has no file name".into());
        }
        self.adapter_missing_cycles = 0;

        // Register the bypass and publish the policy files BEFORE the
        // process starts, so the hook DLL finds the allow-list (including
        // this exe) the moment it initializes. A publication failure aborts
        // the launch: starting the app without its policy would leave it
        // running un-bypassed while the UI claimed a bypass launch.
        let prev_ip = self.target_ip.clone();
        self.target_ip = Some(source_ip.clone());
        self.active.insert(
            app_id,
            ActiveBypass {
                app_id,
                exe_path: exe.to_path_buf(),
                exe_name: exe_name.clone(),
                injected_pids: HashMap::new(),
                helper_paths: HashSet::new(),
                awaiting_process: false,
                inject_error: None,
            },
        );
        if let Err(e) = self.sync_policy_files() {
            self.active.remove(&app_id);
            self.target_ip = prev_ip;
            let _ = self.sync_policy_files();
            return Err(format!("Bypass policy could not be published: {}", e));
        }

        let outcome = match injector::launch_with_bypass(exe, &source_ip) {
            Ok(o) => o,
            Err(e) => {
                self.active.remove(&app_id);
                if self.active.is_empty() {
                    self.target_ip = None;
                }
                let _ = self.sync_policy_files();
                return Err(e);
            }
        };

        if let Some(entry) = self.active.get_mut(&app_id) {
            entry.injected_pids.insert(
                outcome.pid,
                injector::process_creation_time(outcome.pid).unwrap_or(0),
            );
            entry.awaiting_process = false;
            entry.inject_error = None;
        }
        // The process is already running at this point, so a sync failure
        // cannot abort the launch; instead the policy is cleared (fail
        // closed: the hook stops binding new sockets) and the error is
        // reported while the entry is removed.
        if let Err(e) = self.sync_policy_files() {
            self.active.remove(&app_id);
            if self.active.is_empty() {
                self.target_ip = None;
            }
            let _ = self.sync_policy_files();
            return Err(format!(
                "Launched, but policy re-publication failed so the bypass was disabled: {}",
                e
            ));
        }

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
        self.adapter_missing_cycles = 0;
        let removed = self.active.remove(&app_id);
        let removed_name = removed.as_ref().map(|e| e.exe_name.clone());
        let prev_ip = self.target_ip.clone();
        if self.active.is_empty() {
            self.target_ip = None;
        }
        // Rewrites the allow-list without the removed app so its injected
        // processes stop bypassing on new sockets; deletes everything when
        // no bypass remains. On publication failure the removal is rolled
        // back: the stale allow-list would otherwise keep bypassing an app
        // the UI reports as disabled.
        if let Err(e) = self.sync_policy_files() {
            if let Some(entry) = removed {
                self.active.insert(app_id, entry);
            }
            self.target_ip = prev_ip;
            let _ = self.sync_policy_files();
            return Err(format!("Bypass removal could not be published: {}", e));
        }
        if let Some(name) = removed_name {
            config::append_log(&format!("DISABLE_BYPASS app={} exe={}", app_id, name));
        }
        Ok(())
    }

    pub fn clear_all(&mut self) -> Result<(), String> {
        self.adapter_missing_cycles = 0;
        let prev_active = std::mem::take(&mut self.active);
        let prev_ip = self.target_ip.take();
        if let Err(e) = self.sync_policy_files() {
            self.active = prev_active;
            self.target_ip = prev_ip;
            let _ = self.sync_policy_files();
            return Err(format!("Bypass clear could not be published: {}", e));
        }
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
        self.active.get(&app_id).map(Self::derive_live_status)
    }

    /// The single derivation of live status from an entry (live_status
    /// and live_status_map used to carry verbatim copies of this logic).
    fn derive_live_status(b: &ActiveBypass) -> BypassLiveStatus {
        if !b.injected_pids.is_empty() {
            // Hooked somewhere, but a recorded injection failure for
            // another process of the same app must not render as full
            // success (AUD-004).
            if b.inject_error.is_some() {
                BypassLiveStatus::Partial
            } else {
                BypassLiveStatus::Live
            }
        } else if b.awaiting_process {
            BypassLiveStatus::Pending
        } else {
            BypassLiveStatus::Failed
        }
    }

    pub fn count(&self) -> usize {
        self.active.len()
    }

    pub fn watchdog_snapshot(&self) -> WatchdogSnapshot {
        WatchdogSnapshot {
            entries: self.active.values().cloned().collect(),
        }
    }

    pub fn watchdog_plan(
        snapshot: &WatchdogSnapshot,
        maps: &ProcessMaps,
    ) -> Vec<WatchdogPlanEntry> {
        let (parents, paths) = maps;
        // Lowercase every path ONCE per plan: the filters below used to
        // allocate a fresh lowercase String per process per bypassed app
        // (O(apps × processes) short-lived strings per watchdog cycle).
        let lower_paths: HashMap<u32, String> = paths
            .iter()
            .map(|(pid, p)| (*pid, p.to_ascii_lowercase()))
            .collect();
        let mut out = Vec::new();
        for bypass in &snapshot.entries {
            if bypass.exe_name.is_empty() {
                continue;
            }
            let target = bypass.exe_path.to_string_lossy().to_ascii_lowercase();
            let app_dir = bypass
                .exe_path
                .parent()
                .map(|p| p.to_string_lossy().to_ascii_lowercase());

            // Primary processes: exact exe path match.
            let mut current: HashSet<u32> = lower_paths
                .iter()
                .filter(|(_, p)| **p == target)
                .map(|(pid, _)| *pid)
                .collect();

            // Descendants running from the same install tree (helper
            // processes of launchers/multi-process apps).
            let mut helper_paths: Vec<String> = Vec::new();
            if let Some(dir) = &app_dir {
                let prefix = format!("{}\\", dir.trim_end_matches('\\'));
                // Breadth guard: when the install dir is itself a
                // near-root folder (e.g. the exe sits directly in
                // "C:\Program Files" or "D:\"), the prefix matches a huge
                // unrelated tree, so descendants must live in a
                // SUBdirectory of it, not directly inside it.
                let shallow_dir = dir.matches('\\').count() <= 1;
                let descendants: Vec<u32> = lower_paths
                    .iter()
                    .filter(|(pid, p)| {
                        if current.contains(pid) || !p.starts_with(&prefix) {
                            return false;
                        }
                        if shallow_dir && !p[prefix.len()..].contains('\\') {
                            return false;
                        }
                        true
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
                // The descendants' own paths go on the policy allow-list:
                // the hook checks each process against ITS OWN path, so an
                // injected helper that is not listed never bypasses.
                for pid in &descendants {
                    if let Some(p) = paths.get(pid) {
                        if !p.eq_ignore_ascii_case(&bypass.exe_path.to_string_lossy())
                            && !helper_paths.iter().any(|h| h.eq_ignore_ascii_case(p))
                        {
                            helper_paths.push(p.clone());
                        }
                    }
                }
                current.extend(descendants);
            }

            // Purge dead PIDs and entries whose creation time no longer
            // matches (the PID was recycled by a different process).
            let mut pruned = bypass.injected_pids.clone();
            pruned.retain(|pid, created| {
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
            let to_inject: Vec<u32> = current
                .iter()
                .filter(|pid| !pruned.contains_key(pid))
                .copied()
                .collect();
            out.push(WatchdogPlanEntry {
                app_id: bypass.app_id,
                base_injected: bypass.injected_pids.clone(),
                pruned_injected: pruned,
                had_pids: !current.is_empty(),
                to_inject,
                helper_paths,
            });
        }
        out
    }

    /// Commit a watchdog cycle under a short lock. `injected` maps app_id to
    /// newly injected (pid, creation) pairs; `errors` maps app_id to the
    /// last injection error. Also handles adapter-IP drift and adapter
    /// loss: after two consecutive cycles with no usable direct IPv4, the
    /// policy is fail-closed (files deleted, entries marked Failed) instead
    /// of leaving injected processes bound to a stale address while the UI
    /// still reports Live.
    pub fn watchdog_commit(
        &mut self,
        plan: Vec<WatchdogPlanEntry>,
        injected: &HashMap<Uuid, Vec<(u32, u64)>>,
        errors: &HashMap<Uuid, String>,
        direct_ip: Option<&str>,
    ) {
        match direct_ip {
            Some(ip) => {
                self.adapter_missing_cycles = 0;
                if self.target_ip.as_deref() != Some(ip) {
                    let prev = self.target_ip.clone();
                    config::append_log(&format!(
                        "ADAPTER_IP_CHANGED old={} new={}",
                        prev.as_deref().unwrap_or("?"),
                        ip
                    ));
                    self.target_ip = Some(ip.to_string());
                    if let Err(e) = self.sync_policy_files() {
                        config::append_log(&format!("ADAPTER_IP_PUBLISH_FAILED {}", e));
                        self.target_ip = prev;
                        let _ = self.sync_policy_files();
                    }
                }
            }
            None => {
                self.adapter_missing_cycles += 1;
                if self.adapter_missing_cycles >= 2 {
                    self.target_ip = None;
                    // The fail-close is only real once the policy files
                    // are actually deleted. A failed deletion used to be
                    // discarded silently while the entries were marked
                    // Failed anyway — the hooks kept binding to the stale
                    // address behind a UI that said "suspended". On
                    // failure: log it, do NOT mark the entries suspended,
                    // and fall through so this cycle's real injections
                    // (the plan below) are still recorded — discarding
                    // them made the next cycles re-inject PIDs that were
                    // already hooked. The branch re-enters next cycle
                    // and retries the deletion.
                    match self.sync_policy_files() {
                        Ok(()) => {
                            config::append_log("ADAPTER_LOST policy fail-closed");
                            for bypass in self.active.values_mut() {
                                bypass.injected_pids.clear();
                                bypass.awaiting_process = false;
                                bypass.inject_error =
                                    Some("Direct adapter unavailable; bypass suspended".into());
                            }
                            return;
                        }
                        Err(e) => {
                            config::append_log(&format!("ADAPTER_LOST_POLICY_DELETE_FAILED {}", e));
                        }
                    }
                }
            }
        }

        for entry in plan {
            let Some(bypass) = self.active.get_mut(&entry.app_id) else {
                continue;
            };
            // Race guard: the plan was computed from a snapshot taken
            // before this cycle's (seconds-long) injection phase. If a
            // UI operation changed this entry's bookkeeping in that
            // window (remove + re-apply is the common case), the live
            // entry is NEWER than the plan — overwriting it with the
            // snapshot's pruned set would resurrect stale state and
            // flicker the entry to Failed until the next cycle. Skip
            // the entry; the next cycle re-plans from a fresh snapshot.
            if bypass.injected_pids != entry.base_injected {
                config::append_log(&format!(
                    "WATCHDOG_COMMIT_RACE_SKIPPED app={}",
                    entry.app_id
                ));
                continue;
            }
            let mut injected_pids = entry.pruned_injected;
            if let Some(new) = injected.get(&entry.app_id) {
                for (pid, created) in new {
                    injected_pids.insert(*pid, *created);
                }
            }
            bypass.injected_pids = injected_pids;
            bypass.helper_paths = entry.helper_paths.iter().cloned().collect();
            if bypass.injected_pids.is_empty() {
                if entry.had_pids {
                    bypass.awaiting_process = false;
                    bypass.inject_error = errors
                        .get(&entry.app_id)
                        .cloned()
                        .or_else(|| Some("DLL injection failed".into()));
                } else {
                    bypass.awaiting_process = true;
                    bypass.inject_error = None;
                }
            } else {
                bypass.awaiting_process = false;
                // A PID that failed injection THIS cycle keeps the entry
                // Partial (AUD-004); when nothing failed, any stale
                // partial note clears — the failing PID has exited or
                // finally accepted the hook.
                bypass.inject_error = errors.get(&entry.app_id).cloned();
            }
        }

        // Keep the published allow-list in step with the processes the
        // watchdog actually injected this cycle (helpers appearing or
        // exiting change the effective set). Republish only on change, so
        // the policy files are not rewritten every cycle.
        if self.target_ip.is_some() && !self.active.is_empty() {
            let mut desired: HashSet<String> = HashSet::new();
            for b in self.active.values() {
                desired.insert(b.exe_path.to_string_lossy().to_ascii_lowercase());
                for h in &b.helper_paths {
                    desired.insert(h.to_ascii_lowercase());
                }
            }
            if desired != self.published_allow {
                if let Err(e) = self.sync_policy_files() {
                    config::append_log(&format!("POLICY_SYNC_FAILED {}", e));
                }
            }
        }
    }

    /// One-shot status map for the UI: a single lock for a whole frame
    /// instead of two locks per rendered row. The value carries the live
    /// status, a displayable problem text (the entry's injection error,
    /// or a manager-wide policy-publish problem when there is one), and
    /// the helper-process paths currently bypassed for the app — which
    /// used to widen the bypass invisibly, with no UI surface at all.
    pub fn live_status_map(
        &self,
    ) -> HashMap<Uuid, (BypassLiveStatus, Option<String>, Vec<String>)> {
        self.active
            .iter()
            .map(|(id, b)| {
                let status = Self::derive_live_status(b);
                let problem = match (&b.inject_error, &self.last_policy_error) {
                    (Some(e), Some(p)) => Some(format!("{}\nPolicy sync problem: {}", e, p)),
                    (Some(e), None) => Some(e.clone()),
                    (None, Some(p)) => Some(format!("Policy sync problem: {}", p)),
                    (None, None) => None,
                };
                let mut helpers: Vec<String> = b.helper_paths.iter().cloned().collect();
                helpers.sort();
                (*id, (status, problem, helpers))
            })
            .collect()
    }

    pub fn active_ids(&self) -> HashSet<Uuid> {
        self.active.keys().copied().collect()
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
                helper_paths: HashSet::new(),
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

        // Injected somewhere but a failure is still recorded for the
        // entry: Partial, not Live (AUD-004).
        let b = m.active.get_mut(&id).unwrap();
        b.injected_pids.insert(1234, 42);
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Partial));

        let b = m.active.get_mut(&id).unwrap();
        b.inject_error = None;
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Live));
    }

    fn entry(id: Uuid, injected: &[(u32, u64)]) -> ActiveBypass {
        ActiveBypass {
            app_id: id,
            exe_path: PathBuf::from("C:\\a.exe"),
            exe_name: "a.exe".into(),
            injected_pids: injected.iter().copied().collect(),
            helper_paths: HashSet::new(),
            awaiting_process: false,
            inject_error: None,
        }
    }

    #[test]
    fn apply_refuses_empty_exe_name_before_mutating_state() {
        // Round-2 regression: the empty-name refusal in apply() used to
        // run AFTER target_ip was overwritten, and the error path left
        // the manager pointing at an IP nothing used. The check now runs
        // before any mutation (and before DLL extraction), so the error
        // must surface with the manager untouched.
        let mut m = EnforcementManager::default();
        let direct = crate::models::InterfaceInfo {
            name: "Ethernet".into(),
            index: 1,
            adapter_id: "{TEST}".into(),
            status: "Up".into(),
            description: "test".into(),
            ipv4: Some("192.168.1.10".into()),
            gateway: None,
            virtual_adapter: false,
        };
        // "C:\\" has no file_name component.
        let err = m
            .apply(Uuid::new_v4(), PathBuf::from("C:\\"), &direct)
            .unwrap_err();
        assert!(err.contains("no file name"), "unexpected error: {}", err);
        assert!(m.active.is_empty());
        assert!(m.target_ip.is_none());
    }

    #[test]
    fn watchdog_commit_skips_entries_raced_by_the_ui() {
        // Round-2 race: the plan is computed from a snapshot taken
        // before the (seconds-long) injection phase. If the UI changed
        // the entry in that window, commit must not overwrite the newer
        // live bookkeeping with the snapshot's pruned set.
        let mut m = EnforcementManager::default();
        let id = Uuid::new_v4();
        m.active.insert(id, entry(id, &[(111, 42)]));
        // Plan was made when the entry had NO injections (base differs).
        let plan = vec![WatchdogPlanEntry {
            app_id: id,
            base_injected: HashMap::new(),
            pruned_injected: HashMap::new(),
            had_pids: true,
            to_inject: vec![],
            helper_paths: vec!["C:\\helper.exe".into()],
        }];
        m.watchdog_commit(plan, &HashMap::new(), &HashMap::new(), Some("192.168.1.10"));
        let b = &m.active[&id];
        assert_eq!(b.injected_pids.len(), 1);
        assert!(b.injected_pids.contains_key(&111));
        assert!(b.helper_paths.is_empty());
    }

    #[test]
    fn watchdog_commit_applies_plan_when_not_raced() {
        let mut m = EnforcementManager::default();
        let id = Uuid::new_v4();
        m.active.insert(id, entry(id, &[(111, 42)]));
        let plan = vec![WatchdogPlanEntry {
            app_id: id,
            base_injected: [(111, 42)].into_iter().collect(),
            pruned_injected: [(111, 42)].into_iter().collect(),
            had_pids: true,
            to_inject: vec![222],
            helper_paths: vec![],
        }];
        let mut injected = HashMap::new();
        injected.insert(id, vec![(222, 7)]);
        m.watchdog_commit(plan, &injected, &HashMap::new(), Some("192.168.1.10"));
        let b = &m.active[&id];
        assert_eq!(b.injected_pids.len(), 2);
        assert_eq!(b.injected_pids.get(&222), Some(&7));
    }

    #[test]
    fn watchdog_commit_keeps_partial_failure_visible() {
        // AUD-004: one PID stays hooked while another refuses injection
        // this cycle — the entry must derive Partial, not Live.
        let mut m = EnforcementManager::default();
        let id = Uuid::new_v4();
        m.active.insert(id, entry(id, &[(111, 42)]));
        let plan = vec![WatchdogPlanEntry {
            app_id: id,
            base_injected: [(111, 42)].into_iter().collect(),
            pruned_injected: [(111, 42)].into_iter().collect(),
            had_pids: true,
            to_inject: vec![222],
            helper_paths: vec![],
        }];
        let mut errors = HashMap::new();
        errors.insert(id, "denied".to_string());
        m.watchdog_commit(plan, &HashMap::new(), &errors, Some("192.168.1.10"));
        let b = &m.active[&id];
        assert_eq!(b.injected_pids.len(), 1);
        assert_eq!(m.live_status(id), Some(BypassLiveStatus::Partial));
    }
}
