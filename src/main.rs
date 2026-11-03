#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod discovery;
mod enforcement;
mod models;
mod network;
mod windows;

use app::AppState;
use eframe::egui;
use enforcement::BypassLiveStatus;
use std::time::Duration;
use uuid::Uuid;
use windows::tray::BiFlowTray;

fn main() -> eframe::Result<()> {
    if !cfg!(windows) {
        panic!("BiFlow is Windows-only");
    }

    // BiFlow requires Administrator privileges for real Windows Defender Firewall and network packet filtering.
    // On success this function never returns (the elevated copy takes over).
    if !windows::privilege::is_elevated() {
        let _ = windows::privilege::restart_as_administrator();
    }

    // NOTE: SeDebugPrivilege is intentionally NOT enabled (not needed for
    // PROCESS_QUERY_LIMITED_INFORMATION on the user's own processes, and a
    // standing SeDebugPrivilege is both an attack surface and an AV signal).

    // Single instance: two BiFlow processes would race over the same policy
    // and config files. A second launch just focuses the running instance.
    if !acquire_single_instance() {
        windows::bring_window_to_front();
        return Ok(());
    }

    // A previous run may have crashed or been killed before it could clean
    // up: stale policy files would keep already-injected processes bypassing
    // with a dead adapter address. AppState re-applies the saved profile
    // rules right after this, so clearing first is safe.
    if let Err(e) = windows::injector::clear_target_ip() {
        config::append_log(&format!("STARTUP_POLICY_CLEANUP_FAILED {}", e));
    }
    windows::injector::clear_stale_hook_status();

    let start_minimized = std::env::args().any(|a| a == "--minimized");

    let tray = match BiFlowTray::new() {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("Warning: Tray icon initialization failed: {}", e);
            None
        }
    };

    let icon_data = egui::IconData {
        rgba: include_bytes!("../assets/icon_64.rgba").to_vec(),
        width: 64,
        height: 64,
    };

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("BiFlow - Windows Split Routing")
            .with_icon(std::sync::Arc::new(icon_data))
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([920.0, 580.0])
            .with_visible(!start_minimized),
        ..Default::default()
    };

    eframe::run_native(
        "BiFlow",
        opts,
        Box::new(|cc| {
            setup_custom_style(&cc.egui_ctx);
            windows::tray::set_egui_context(cc.egui_ctx.clone());
            Ok(Box::new(BiFlowApp::new(cc, tray, start_minimized)))
        }),
    )
}

/// Creates the single-instance named mutex. Returns false when another
/// BiFlow instance already holds it. The handle is deliberately leaked so
/// the mutex lives for the whole process lifetime.
fn acquire_single_instance() -> bool {
    use std::os::windows::ffi::OsStrExt;
    let name: Vec<u16> = std::ffi::OsStr::new("Local\\BiFlow-SingleInstance-Mutex")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let handle = windows_sys::Win32::System::Threading::CreateMutexW(
            std::ptr::null_mut(),
            0,
            name.as_ptr(),
        );
        if handle.is_null() {
            // If the mutex cannot be created, do not block startup.
            return true;
        }
        if windows_sys::Win32::Foundation::GetLastError()
            == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS
        {
            windows_sys::Win32::Foundation::CloseHandle(handle);
            return false;
        }
        // Intentionally not closed: the mutex handle must stay open for the
        // whole process lifetime (the OS releases it when we exit).
        true
    }
}

fn setup_custom_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();

    visuals.override_text_color = Some(egui::Color32::from_rgb(240, 244, 250));
    visuals.panel_fill = egui::Color32::from_rgb(13, 17, 23);
    visuals.window_fill = egui::Color32::from_rgb(18, 24, 34);

    // Non-interactive widgets (cards, panels)
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(22, 30, 44);
    visuals.widgets.noninteractive.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(36, 48, 68));
    visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(8);

    // Inactive buttons
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(28, 38, 56);
    visuals.widgets.inactive.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(44, 60, 88));
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(6);

    // Hovered buttons
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(40, 56, 82);
    visuals.widgets.hovered.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(70, 110, 170));
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(6);

    // Active buttons
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(37, 99, 235);
    visuals.widgets.active.bg_stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(96, 165, 250));
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(6);

    visuals.selection.bg_fill = egui::Color32::from_rgb(37, 99, 235);
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(147, 197, 253));

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    ctx.set_style(style);
}

struct BiFlowApp {
    state: AppState,
    tab: Tab,
    new_profile_name: String,
    tray: Option<BiFlowTray>,
    is_hidden: bool,
    suppress_minimize_to_tray: bool,
    save_notification: Option<String>,
    editing_profile_id: Option<Uuid>,
    editing_profile_name: String,
    expanded_profile_id: Option<Uuid>,
    /// A destructive action waiting for the user's confirmation. Until
    /// now every destructive control (delete profile, remove rule,
    /// unblock all, picking a VPN as the direct adapter) fired instantly.
    pending_confirm: Option<PendingConfirm>,
    last_tray_tooltip: String,
    search_focus_requested: bool,
}

/// Destructive actions that require an explicit confirmation click.
#[derive(Clone)]
enum PendingConfirm {
    DeleteProfile(Uuid),
    RemoveRule(Uuid, Uuid),
    UnblockAll,
    SetVpnAdapter(u32, String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Network,
    Settings,
    About,
}

impl BiFlowApp {
    fn new(
        _cc: &eframe::CreationContext<'_>,
        tray: Option<BiFlowTray>,
        start_minimized: bool,
    ) -> Self {
        Self {
            state: AppState::new(),
            tab: Tab::Apps,
            new_profile_name: String::new(),
            tray,
            is_hidden: start_minimized,
            suppress_minimize_to_tray: false,
            save_notification: None,
            editing_profile_id: None,
            editing_profile_name: String::new(),
            expanded_profile_id: None,
            pending_confirm: None,
            last_tray_tooltip: String::new(),
            search_focus_requested: false,
        }
    }

    fn check_tray_and_window_state(&mut self, ctx: &egui::Context) {
        // Periodic repaint drives the watchdog and tray-state handling.
        ctx.request_repaint_after(Duration::from_millis(500));

        // 1. Handle Restore Request from Tray (fired immediately by Windows callback)
        if windows::tray::take_restore_requested() {
            self.is_hidden = false;
            self.suppress_minimize_to_tray = true;
            windows::bring_window_to_front();
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
        }

        // 2. Handle Disable All / Resume Requests from Tray
        if windows::tray::take_disable_all_requested() {
            self.state.disable_all();
        }
        if windows::tray::take_resume_requested() && self.state.bypasses_paused() {
            self.state.resume_all();
        }

        // 2b. Handle Exit Request from Tray (orderly shutdown on this
        // thread, so no config save can be interrupted mid-write). Exit
        // only happens when the bypass cleanup actually succeeded: if the
        // policy files could not be deleted, already-injected processes
        // would keep bypassing with no UI left, so the app stays alive.
        // A refused exit must become VISIBLE: the window comes back so
        // the user sees the reason in the status bar instead of an app
        // that silently refuses to die from the tray.
        if windows::tray::take_exit_requested() {
            if self.state.exit_cleanup().is_ok() {
                std::process::exit(0);
            }
            self.is_hidden = false;
            windows::bring_window_to_front();
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
        }

        // 2c. Keep the tray tooltip honest: it shows live engine state
        // (how many bypasses are live, whether they are paused) instead
        // of a static product string.
        let active = self.state.active_bypass_count();
        let tooltip = if self.state.bypasses_paused() {
            "BiFlow — bypasses paused".to_string()
        } else if active > 0 {
            format!("BiFlow — {} bypass(es) live", active)
        } else {
            "BiFlow — no active bypasses".to_string()
        };
        if tooltip != self.last_tray_tooltip {
            if let Some(tray) = &self.tray {
                tray.set_tooltip(&tooltip);
            }
            self.last_tray_tooltip = tooltip;
        }

        // 3. Handle Window Close Request (X button)
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.state.store.close_to_tray {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.is_hidden = true;
                windows::hide_main_window();
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else if self.state.exit_cleanup().is_ok() {
                std::process::exit(0);
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
        }

        // 4. Handle Window Minimization to system tray
        let is_minimized = ctx.input(|i| i.viewport().minimized == Some(true));
        if self.suppress_minimize_to_tray {
            if !is_minimized {
                self.suppress_minimize_to_tray = false;
            }
        } else if !self.is_hidden && self.state.store.minimize_to_tray && is_minimized {
            self.is_hidden = true;
            windows::hide_main_window();
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // 5. Periodic background watchdog
        self.state.tick_watchdog();
    }

    fn top_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(2.0);

            // App Brand
            ui.label(
                egui::RichText::new("⚡ BiFlow")
                    .strong()
                    .size(19.0)
                    .color(egui::Color32::from_rgb(56, 189, 248)),
            );

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            // Administrator Badge
            let elevated = windows::privilege::is_elevated();
            if elevated {
                ui.label(
                    egui::RichText::new("🛡️ Administrator")
                        .size(12.0)
                        .color(egui::Color32::from_rgb(52, 211, 153)),
                );
            } else {
                let elev_btn = ui.add(
                    egui::Button::new(
                        egui::RichText::new("⚠️ Standard User (Click to Elevate)")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(251, 191, 36)),
                    )
                    .fill(egui::Color32::from_rgb(45, 35, 20)),
                );
                if elev_btn
                    .on_hover_text("Click to restart BiFlow as Administrator for instant 1-click firewall control")
                    .clicked()
                {
                    let _ = windows::privilege::restart_as_administrator();
                }
            }

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            // Direct Interface Status Pill
            if let Some(direct) = self.state.direct_interface() {
                let ip_str = direct.ipv4.as_deref().unwrap_or("No IP");
                ui.label(
                    egui::RichText::new(format!("🌐 Direct: {} ({})", direct.name, ip_str))
                        .size(12.0)
                        .strong()
                        .color(egui::Color32::from_rgb(125, 211, 252)),
                );
            } else {
                ui.label(
                    egui::RichText::new("⚠️ No Direct Adapter Selected")
                        .size(12.0)
                        .color(egui::Color32::from_rgb(248, 113, 113)),
                );
            }

            ui.separator();

            // Profile Switcher Dropdown in Top Bar
            let active_pid_opt = self.state.store.active_profile;
            let active_p_name = self.state.store.profiles
                .iter()
                .find(|p| Some(p.id) == active_pid_opt)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Default".into());

            let mut switch_from_top_bar: Option<Uuid> = None;

            egui::ComboBox::from_id_salt("top_bar_profile_combo")
                .selected_text(egui::RichText::new(format!("📋 {}", active_p_name)).strong().color(egui::Color32::from_rgb(52, 211, 153)))
                .show_ui(ui, |ui| {
                    for p in &self.state.store.profiles {
                        let is_curr = Some(p.id) == active_pid_opt;
                        let count = p.rules.iter().filter(|r| r.enabled).count();
                        let text = format!("{} ({} rules)", p.name, count);
                        if !is_curr && ui.selectable_label(is_curr, text).clicked() {
                            switch_from_top_bar = Some(p.id);
                        }
                    }
                });

            if self.state.has_unsaved_changes() {
                ui.label(egui::RichText::new("● Modified").size(11.0).color(egui::Color32::from_rgb(251, 191, 36)));
                if ui.small_button("💾 Save").on_hover_text("Save current changes to this profile").clicked() {
                    self.state.save_current_bypasses_to_active_profile();
                    self.save_notification = Some(format!("✔ Saved changes to profile '{}'.", active_p_name));
                }
                if ui.small_button("↩ Revert").on_hover_text("Revert changes to last saved state").clicked() {
                    self.state.revert_active_profile();
                    self.save_notification = Some(format!("✔ Reverted profile '{}'.", active_p_name));
                }
            }

            if let Some(id) = switch_from_top_bar {
                self.state.switch_profile(id);
                self.save_notification = Some("✔ Switched active profile.".into());
            }

            // Right-aligned header actions
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("❌ Exit")
                                .color(egui::Color32::from_rgb(248, 113, 113)),
                        )
                        .fill(egui::Color32::from_rgb(45, 20, 25)),
                    )
                    .on_hover_text("Close BiFlow and stop all bypasses (firewall block rules you created stay in Windows Firewall until you unblock them)")
                    .clicked()
                    && self.state.exit_cleanup().is_ok()
                {
                    std::process::exit(0);
                }

                if ui
                    .button("🗕 Hide to Tray")
                    .on_hover_text("Dock BiFlow into the Windows system tray")
                    .clicked()
                {
                    self.is_hidden = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }

                if ui
                    .button("🛑 Disable All")
                    .on_hover_text("Disable all active application bypasses immediately")
                    .clicked()
                {
                    self.state.disable_all();
                }

                if self.state.bypasses_paused()
                    && ui
                        .button("▶ Resume Bypasses")
                        .on_hover_text("Re-apply the active profile's bypass rules")
                        .clicked()
                {
                    self.state.resume_all();
                }

                if ui
                    .button("🔄 Refresh")
                    .on_hover_text("Scan for newly started apps and network adapters")
                    .clicked()
                {
                    self.state.refresh();
                }

                let active_count = self.state.active_bypass_count();
                if active_count > 0 {
                    ui.label(
                        egui::RichText::new(format!("⚡ {} Active", active_count))
                            .strong()
                            .color(egui::Color32::from_rgb(52, 211, 153)),
                    );
                    ui.separator();
                }
            });
        });
    }

    fn nav_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(2.0);

            let app_count = self.state.apps.len();
            let iface_count = self.state.interfaces.len();

            // Notifications are global now (rendered above every tab and
            // dismissed explicitly): switching tabs no longer deletes an
            // unread result — the Settings-only banner used to vanish the
            // moment the user clicked another tab.
            ui.selectable_value(
                &mut self.tab,
                Tab::Apps,
                format!("📱 Applications ({})", app_count),
            );
            ui.selectable_value(
                &mut self.tab,
                Tab::Network,
                format!("🌐 Network Adapters ({})", iface_count),
            );
            ui.selectable_value(&mut self.tab, Tab::Settings, "⚙ Settings & Startup");
            ui.selectable_value(&mut self.tab, Tab::About, "ℹ About & Developer");
        });
    }

    fn tab_apps(&mut self, ui: &mut egui::Ui) {
        // Quick Stats Banner
        let total_apps = self.state.apps.len();
        let running_apps_count = self
            .state
            .apps
            .iter()
            .filter(|a| self.state.app_running_cached(a))
            .count();
        let online_apps_count = self
            .state
            .apps
            .iter()
            .filter(|a| self.state.app_network_cached(a))
            .count();
        let active_bypasses_count = self
            .state
            .apps
            .iter()
            .filter(|a| self.state.is_app_bypassed(a.id))
            .count();

        ui.horizontal(|ui| {
            // Stat Card 1: Total
            ui.group(|ui| {
                ui.set_min_width(140.0);
                ui.label(egui::RichText::new("📦 Total Apps").size(11.0).weak());
                ui.label(
                    egui::RichText::new(format!("{}", total_apps))
                        .strong()
                        .size(16.0)
                        .color(egui::Color32::from_rgb(220, 230, 245)),
                );
            });

            // Stat Card 2: Open connections (a socket snapshot, not a
            // traffic meter — the label must not promise more).
            ui.group(|ui| {
                ui.set_min_width(160.0);
                ui.label(egui::RichText::new("🌐 Open Connections").size(11.0).weak());
                ui.label(
                    egui::RichText::new(format!("{} Apps", online_apps_count))
                        .strong()
                        .size(16.0)
                        .color(egui::Color32::from_rgb(56, 189, 248)),
                );
            });

            // Stat Card 3: Running
            ui.group(|ui| {
                ui.set_min_width(140.0);
                ui.label(egui::RichText::new("🟢 Running Now").size(11.0).weak());
                ui.label(
                    egui::RichText::new(format!("{} Active", running_apps_count))
                        .strong()
                        .size(16.0)
                        .color(egui::Color32::from_rgb(52, 211, 153)),
                );
            });

            // Stat Card 4: Bypassed
            ui.group(|ui| {
                ui.set_min_width(130.0);
                ui.label(egui::RichText::new("⚡ Direct Bypasses").size(11.0).weak());
                ui.label(
                    egui::RichText::new(format!("{} Bypassed", active_bypasses_count))
                        .strong()
                        .size(16.0)
                        .color(if active_bypasses_count > 0 {
                            egui::Color32::from_rgb(52, 211, 153)
                        } else {
                            egui::Color32::from_rgb(148, 163, 184)
                        }),
                );
            });

            // Stat Card 5: Blocked from Internet
            let blocked_apps_count = self.state.store.blocked_apps.len();
            ui.group(|ui| {
                ui.set_min_width(130.0);
                ui.label(egui::RichText::new("🚫 Blocked Internet").size(11.0).weak());
                ui.label(
                    egui::RichText::new(format!("{} Blocked", blocked_apps_count))
                        .strong()
                        .size(16.0)
                        .color(if blocked_apps_count > 0 {
                            egui::Color32::from_rgb(239, 68, 68)
                        } else {
                            egui::Color32::from_rgb(148, 163, 184)
                        }),
                );
            });
        });

        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(
                "⚡ Live = hook active in the process · Configured = activates when the app starts · Failed = the reason shows under the row",
            )
            .size(11.0)
            .weak(),
        );
        ui.add_space(2.0);

        // Search & Filter Toolbar
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔍").size(14.0));
            let search_resp = ui.add(
                egui::TextEdit::singleline(&mut self.state.search)
                    .hint_text("Search application by name or executable... (Ctrl+F)")
                    .desired_width(260.0),
            );
            if self.search_focus_requested {
                search_resp.request_focus();
                self.search_focus_requested = false;
            }

            if !self.state.search.is_empty() && ui.button("✖").clicked() {
                self.state.search.clear();
            }

            ui.separator();

            // Filter Chips
            if ui
                .selectable_label(
                    !self.state.filter_running_only
                        && !self.state.filter_net_only
                        && !self.state.filter_bypassed_only
                        && !self.state.filter_blocked_only,
                    "All",
                )
                .clicked()
            {
                self.state.filter_running_only = false;
                self.state.filter_net_only = false;
                self.state.filter_bypassed_only = false;
                self.state.filter_blocked_only = false;
            }

            if ui
                .selectable_label(self.state.filter_net_only, "🌐 Open Connections")
                .clicked()
            {
                self.state.filter_net_only = !self.state.filter_net_only;
                if self.state.filter_net_only {
                    self.state.filter_running_only = false;
                    self.state.filter_bypassed_only = false;
                    self.state.filter_blocked_only = false;
                }
            }

            if ui
                .selectable_label(self.state.filter_running_only, "🟢 Running Only")
                .clicked()
            {
                self.state.filter_running_only = !self.state.filter_running_only;
                if self.state.filter_running_only {
                    self.state.filter_net_only = false;
                    self.state.filter_bypassed_only = false;
                    self.state.filter_blocked_only = false;
                }
            }

            if ui
                .selectable_label(self.state.filter_bypassed_only, "⚡ Bypassed Only")
                .clicked()
            {
                self.state.filter_bypassed_only = !self.state.filter_bypassed_only;
                if self.state.filter_bypassed_only {
                    self.state.filter_running_only = false;
                    self.state.filter_net_only = false;
                    self.state.filter_blocked_only = false;
                }
            }

            if ui
                .selectable_label(self.state.filter_blocked_only, "🚫 Blocked Only")
                .clicked()
            {
                self.state.filter_blocked_only = !self.state.filter_blocked_only;
                if self.state.filter_blocked_only {
                    self.state.filter_running_only = false;
                    self.state.filter_net_only = false;
                    self.state.filter_bypassed_only = false;
                }
            }

            ui.separator();

            if ui
                .button("➕ Add Custom .exe...")
                .on_hover_text("Select any executable file from your computer")
                .clicked()
            {
                self.state.add_custom_file();
            }
        });

        ui.separator();

        // Application list
        // Unicode-aware lowercase: ASCII-only folding made non-ASCII app
        // names unsearchable in their own language.
        let q = self.state.search.to_lowercase();
        let selected_id = self.state.selected_app;

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let mut clicked_selection: Option<Uuid> = None;
                let mut toggle_target: Option<Uuid> = None;
                let mut launch_target: Option<Uuid> = None;
                let mut block_toggle_target: Option<Uuid> = None;
                let mut remove_custom_target: Option<Uuid> = None;
                let mut rendered_rows = 0usize;

                // One manager snapshot for the whole frame (one lock
                // instead of three locks per rendered row).
                let live_map = self.state.live_status_map();
                let bypassed_ids = self.state.active_bypass_ids();

                for app in &self.state.apps {
                    // Search query filter
                    if !q.is_empty()
                        && !app.name.to_lowercase().contains(&q)
                        && !app.executable.to_lowercase().contains(&q)
                    {
                        continue;
                    }

                    // Cached per-app status, refreshed with the process
                    // cache (no repeated scans on the render path)
                    let is_running = self.state.app_running_cached(app);
                    let has_net = self.state.app_network_cached(app);
                    let is_bypassed = self.state.is_app_bypassed_cached(app.id, &bypassed_ids);
                    let (live_status, problem, helpers) = match live_map.get(&app.id) {
                        Some((s, e, h)) => (Some(*s), e.clone(), h.clone()),
                        None => (None, None, Vec::new()),
                    };
                    let is_blocked = self.state.is_app_blocked(app.id);

                    if self.state.filter_running_only && !is_running {
                        continue;
                    }
                    if self.state.filter_net_only && !has_net {
                        continue;
                    }
                    if self.state.filter_bypassed_only && !is_bypassed {
                        continue;
                    }
                    if self.state.filter_blocked_only && !is_blocked {
                        continue;
                    }

                    let is_selected = selected_id == Some(app.id);
                    rendered_rows += 1;

                    // App card container
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            // Selection radio
                            let sel_resp =
                                ui.selectable_label(is_selected, if is_selected { "▶" } else { " " });
                            if sel_resp.clicked() {
                                clicked_selection = Some(app.id);
                            }

                            // App Icon / Initial badge
                            let initial = app
                                .name
                                .chars()
                                .next()
                                .unwrap_or('A')
                                .to_uppercase()
                                .to_string();

                            let icon_color = if is_blocked {
                                egui::Color32::from_rgb(239, 68, 68)
                            } else if is_bypassed {
                                egui::Color32::from_rgb(16, 185, 129)
                            } else if has_net {
                                egui::Color32::from_rgb(56, 189, 248)
                            } else if is_running {
                                egui::Color32::from_rgb(59, 130, 246)
                            } else {
                                egui::Color32::from_rgb(100, 116, 139)
                            };

                            ui.label(
                                egui::RichText::new(format!("[{}]", initial))
                                    .strong()
                                    .color(icon_color),
                            );

                            // App Title
                            let title_resp = ui.link(
                                egui::RichText::new(&app.name)
                                    .strong()
                                    .size(15.0)
                                    .color(if is_blocked {
                                        egui::Color32::from_rgb(248, 113, 113)
                                    } else if is_selected {
                                        egui::Color32::from_rgb(96, 165, 250)
                                    } else {
                                        egui::Color32::from_rgb(241, 245, 249)
                                    }),
                            );
                            if title_resp.clicked() {
                                clicked_selection = Some(app.id);
                            }

                            // Status Pills
                            if is_blocked {
                                ui.label(
                                    egui::RichText::new("🚫 INTERNET BLOCKED")
                                        .size(11.0)
                                        .strong()
                                        .color(egui::Color32::from_rgb(248, 113, 113)),
                                );
                            } else {
                                if has_net {
                                    ui.label(
                                        egui::RichText::new("🌐 Open Connection")
                                            .size(11.0)
                                            .color(egui::Color32::from_rgb(56, 189, 248)),
                                    );
                                }

                                if is_running {
                                    ui.label(
                                        egui::RichText::new("🟢 Running")
                                            .size(11.0)
                                            .color(egui::Color32::from_rgb(52, 211, 153)),
                                    );
                                }

                                if is_bypassed {
                                    // Honest status: only claim a live bypass when the
                                    // hook DLL is actually inside the target process.
                                    let (pill_text, pill_color, hover): (&str, egui::Color32, String) = match live_status {
                                        Some(BypassLiveStatus::Live) => {
                                            let mut h = "Hook installed in the process (5/5 hooks reported). New connections are bound to the direct adapter; egress route is not verified — compare public IP to confirm.".to_string();
                                            if !helpers.is_empty() {
                                                h.push_str(&format!(
                                                    "\nAlso bypassing {} helper process(es) from the same install folder: {}",
                                                    helpers.len(),
                                                    helpers.join(", ")
                                                ));
                                            }
                                            if let Some(p) = &problem {
                                                h.push_str(&format!("\n⚠ {}", p));
                                            }
                                            (
                                                "⚡ BYPASSING VPN",
                                                egui::Color32::from_rgb(52, 211, 153),
                                                h,
                                            )
                                        }
                                        Some(BypassLiveStatus::Pending) => (
                                            "⚡ BYPASS CONFIGURED",
                                            // Amber, not green: configured is a
                                            // promise, not a live bypass yet.
                                            egui::Color32::from_rgb(251, 191, 36),
                                            "Configured. The bypass activates automatically when the app starts.".to_string(),
                                        ),
                                        Some(BypassLiveStatus::Failed) => (
                                            "⚠ BYPASS FAILED",
                                            egui::Color32::from_rgb(248, 113, 113),
                                            problem.clone().unwrap_or_else(|| {
                                                "DLL injection failed for the running process."
                                                    .to_string()
                                            }),
                                        ),
                                        None => (
                                            "⚡ BYPASS CONFIGURED",
                                            egui::Color32::from_rgb(148, 163, 184),
                                            "Saved in the active profile.".to_string(),
                                        ),
                                    };
                                    ui.label(
                                        egui::RichText::new(pill_text)
                                            .size(11.0)
                                            .strong()
                                            .color(pill_color),
                                    )
                                    .on_hover_text(hover);
                                }
                            }

                            // Right controls: Action buttons
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    // 1. Internet Block / Unblock Button
                                    let (block_btn_text, block_btn_color) = if is_blocked {
                                        ("✅ Unblock Internet", egui::Color32::from_rgb(16, 185, 129))
                                    } else {
                                        ("🚫 Block Internet", egui::Color32::from_rgb(190, 30, 45))
                                    };

                                    if ui
                                        .add(
                                            egui::Button::new(
                                                egui::RichText::new(block_btn_text)
                                                    .color(egui::Color32::WHITE),
                                            )
                                            .fill(block_btn_color),
                                        )
                                        .on_hover_text(if is_blocked {
                                            "Click to restore full network and internet access for this application"
                                        } else {
                                            "Block NEW connections for this app via Windows Firewall (both directions, verified by readback). Its existing IPv4 connections are terminated where possible; existing IPv6 connections end on their own."
                                        })
                                        .clicked()
                                    {
                                        block_toggle_target = Some(app.id);
                                    }

                                    // 2. Direct Bypass & Launch Buttons (only available if not blocked)
                                    if !is_blocked {
                                        let btn_text = if is_bypassed {
                                            "🛑 Disable Bypass"
                                        } else {
                                            "⚡ Enable Direct Bypass"
                                        };
                                        let btn_color = if is_bypassed {
                                            egui::Color32::from_rgb(180, 40, 50)
                                        } else {
                                            egui::Color32::from_rgb(37, 99, 235)
                                        };

                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    egui::RichText::new(btn_text)
                                                        .color(egui::Color32::WHITE),
                                                )
                                                .fill(btn_color),
                                            )
                                            .clicked()
                                        {
                                            toggle_target = Some(app.id);
                                        }

                                        if ui
                                            .button("🚀 Launch Direct")
                                            .on_hover_text("Start the app with the bypass hook installed. If the app is already running and forwards launches to its existing instance (browsers, launchers), that instance is NOT bypassed — close it first.")
                                            .clicked()
                                        {
                                            launch_target = Some(app.id);
                                        }

                                        // Custom apps can be removed again —
                                        // adding one used to be a one-way door.
                                        if app.source == "Custom"
                                            && ui
                                                .small_button("✖ Remove")
                                                .on_hover_text("Remove this custom app entry (does not uninstall anything)")
                                                .clicked()
                                        {
                                            remove_custom_target = Some(app.id);
                                        }
                                    }
                                },
                            );
                        });

                        // Executable path & details (clicking selects too,
                        // not only the tiny radio/title targets)
                        ui.horizontal(|ui| {
                            let path_resp = ui
                                .label(
                                    egui::RichText::new(&app.executable)
                                        .monospace()
                                        .size(11.0)
                                        .color(egui::Color32::from_rgb(148, 163, 184)),
                                )
                                .on_hover_cursor(egui::CursorIcon::PointingHand);
                            if path_resp.clicked() {
                                clicked_selection = Some(app.id);
                            }
                            if let Some(pub_name) = &app.publisher {
                                ui.label(
                                    egui::RichText::new(format!("• {}", pub_name))
                                        .size(11.0)
                                        .weak(),
                                );
                            }
                            if let Some(ver) = &app.version {
                                ui.label(
                                    egui::RichText::new(format!("• v{}", ver))
                                        .size(11.0)
                                        .weak(),
                                );
                            }
                            ui.label(
                                egui::RichText::new(format!("• {}", app.source))
                                    .size(11.0)
                                    .weak(),
                            );
                        });

                        // A failed bypass shows its reason right here —
                        // not only inside a hover tooltip most users
                        // never open.
                        if live_status == Some(BypassLiveStatus::Failed) {
                            if let Some(p) = &problem {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "⚠ {} (toggle the bypass off and on to retry)",
                                        p
                                    ))
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(248, 113, 113)),
                                );
                            }
                        }
                    });
                }

                // Empty state: a filtered-to-nothing list used to be a
                // silent blank area; say why and offer the way out.
                if rendered_rows == 0 {
                    ui.add_space(24.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("No applications match the current search / filters.")
                                .size(14.0)
                                .weak(),
                        );
                        ui.add_space(6.0);
                        if ui.button("Clear search & filters").clicked() {
                            self.state.search.clear();
                            self.state.filter_running_only = false;
                            self.state.filter_net_only = false;
                            self.state.filter_bypassed_only = false;
                            self.state.filter_blocked_only = false;
                        }
                    });
                }

                if let Some(id) = clicked_selection {
                    self.state.selected_app = Some(id);
                }
                if let Some(id) = remove_custom_target {
                    self.state.remove_custom_app(id);
                }
                if let Some(id) = block_toggle_target {
                    self.state.selected_app = Some(id);
                    self.state.toggle_block_internet(id);
                }
                if let Some(id) = toggle_target {
                    self.state.selected_app = Some(id);
                    self.state.toggle_bypass();
                }
                if let Some(id) = launch_target {
                    self.state.selected_app = Some(id);
                    self.state.launch_selected();
                }
            });
    }

    fn tab_network(&mut self, ui: &mut egui::Ui) {
        ui.heading("🌐 Network Adapters");
        ui.label(
            "Select which physical network adapter (Wi-Fi or Ethernet) should handle bypassed applications. \
            All other system applications will remain routed through your active VPN tunnel. \
            Changing the adapter clears and re-applies all active bypasses.",
        );
        ui.separator();

        let mut new_selection: Option<u32> = None;
        let mut vpn_selection: Option<(u32, String)> = None;
        let interfaces = self.state.interfaces.clone();

        egui::ScrollArea::vertical().show(ui, |ui| {
            for iface in &interfaces {
                let is_vpn = network::is_likely_vpn(iface);
                let is_selected = self.state.selected_direct_if == Some(iface.index);

                let card_fill = if is_selected {
                    egui::Color32::from_rgb(20, 42, 68)
                } else if is_vpn {
                    egui::Color32::from_rgb(32, 24, 40)
                } else {
                    egui::Color32::from_rgb(22, 30, 44)
                };

                ui.group(|ui| {
                    ui.painter()
                        .rect_filled(ui.available_rect_before_wrap(), 8.0, card_fill);

                    // An adapter that cannot route (down, no IPv4, or
                    // only a link-local APIPA address) must not be
                    // selectable as Direct: the bypass would fail-close
                    // invisibly while the UI implied a working choice.
                    let usable = iface.status.eq_ignore_ascii_case("Up")
                        && iface
                            .ipv4
                            .as_deref()
                            .map(|ip| !network::is_apipa_ipv4(ip))
                            .unwrap_or(false);
                    let unusable_reason = if !iface.status.eq_ignore_ascii_case("Up") {
                        "adapter is down"
                    } else if iface.ipv4.is_none() {
                        "no IPv4 address"
                    } else {
                        "only a link-local (APIPA) address — no DHCP lease"
                    };

                    ui.horizontal(|ui| {
                        let radio = ui.add_enabled(
                            usable,
                            egui::RadioButton::new(is_selected, &iface.name),
                        );
                        if radio.clicked() {
                            if is_vpn {
                                vpn_selection = Some((iface.index, iface.name.clone()));
                            } else {
                                new_selection = Some(iface.index);
                            }
                        }

                        if is_selected {
                            ui.label(
                                egui::RichText::new("✓ ACTIVE DIRECT ADAPTER")
                                    .strong()
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(52, 211, 153)),
                            );
                        }

                        if is_vpn {
                            ui.label(
                                egui::RichText::new("[VPN / Tunnel Adapter]")
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(192, 132, 252)),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("[Physical Adapter]")
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(52, 211, 153)),
                            );
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let status_color = if iface.status.eq_ignore_ascii_case("Up") {
                                egui::Color32::from_rgb(52, 211, 153)
                            } else {
                                egui::Color32::from_rgb(148, 163, 184)
                            };
                            ui.colored_label(status_color, &iface.status);

                            if !is_selected
                                && ui
                                    .add_enabled(usable, egui::Button::new("Set as Direct Adapter"))
                                    .clicked()
                            {
                                if is_vpn {
                                    vpn_selection = Some((iface.index, iface.name.clone()));
                                } else {
                                    new_selection = Some(iface.index);
                                }
                            }
                        });
                    });

                    if is_vpn && usable {
                        ui.label(
                            egui::RichText::new(
                                "⚠ VPN/tunnel adapter: the VPN detection is a name heuristic, and picking a tunnel as Direct routes bypassed apps INTO the VPN — the opposite of a bypass.",
                            )
                            .size(11.0)
                            .color(egui::Color32::from_rgb(248, 113, 113)),
                        );
                    }
                    if !usable {
                        ui.label(
                            egui::RichText::new(format!(
                                "⚠ Not selectable: {}",
                                unusable_reason
                            ))
                            .size(11.0)
                            .color(egui::Color32::from_rgb(248, 113, 113)),
                        );
                    }

                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "IPv4: {}",
                                iface.ipv4.as_deref().unwrap_or("No IPv4")
                            ))
                            .monospace(),
                        );
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!(
                                "Gateway: {}",
                                iface.gateway.as_deref().unwrap_or("None")
                            ))
                            .monospace(),
                        );
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!("Interface Index: {}", iface.index)).weak(),
                        );
                    });

                    if !iface.description.is_empty() {
                        ui.label(egui::RichText::new(&iface.description).weak().size(11.0));
                    }
                });
            }
        });

        if let Some(idx) = new_selection {
            self.state.set_selected_adapter(idx);
        }
        if let Some((idx, name)) = vpn_selection {
            self.pending_confirm = Some(PendingConfirm::SetVpnAdapter(idx, name));
        }
    }

    fn tab_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙ Settings & Startup Configuration");
        ui.label("Configure Windows startup behavior, system tray docking, and profiles.");
        ui.separator();
        // (Action results render in the global banner above all tabs.)

        // Section 1: Windows Startup & System Behavior
        ui.group(|ui| {
            ui.heading("🚀 Windows Startup & System Behavior");
            ui.add_space(4.0);

            // Windows Autostart Checkbox
            let mut autostart_val = self.state.store.autostart;
            if ui
                .checkbox(
                    &mut autostart_val,
                    "⚡ Start BiFlow automatically when Windows starts",
                )
                .on_hover_text(
                    "Automatically start BiFlow at Windows boot in the background to ensure your bypass rules stay active",
                )
                .changed()
            {
                // The notification follows the real result: a failed toggle
                // (protected-location refusal, task creation/removal
                // failure) must never render as a green success.
                self.save_notification = Some(match self.state.toggle_autostart(autostart_val) {
                    Ok(()) => {
                        if autostart_val {
                            "✔ Windows startup enabled successfully.".into()
                        } else {
                            "✔ Windows startup disabled.".into()
                        }
                    }
                    Err(_) => format!("✖ {}", self.state.status.clone()),
                });
            }

            ui.add_space(4.0);

            // Tray Checkboxes: they save on change, exactly like the
            // autostart checkbox above them. They used to mutate the store
            // silently and persist only if an unrelated Save happened (or
            // at exit), while looking identical to the instant-apply
            // control right above.
            let mut tray_pref_changed = false;
            if ui
                .checkbox(
                    &mut self.state.store.minimize_to_tray,
                    "🗕 Minimize to System Tray when minimized",
                )
                .changed()
            {
                tray_pref_changed = true;
            }
            if ui
                .checkbox(
                    &mut self.state.store.close_to_tray,
                    "❌ Keep running in background when window is closed (X button)",
                )
                .changed()
            {
                tray_pref_changed = true;
            }
            if tray_pref_changed {
                if self.state.save().is_err() {
                    self.save_notification = Some(format!("✖ {}", self.state.status.clone()));
                } else {
                    self.save_notification = Some("✔ Tray preferences saved.".into());
                }
            }

            ui.add_space(6.0);
            if ui.button("💾 Save Preferences").clicked() {
                if self.state.save().is_err() {
                    // save() left the error in state.status; surface it.
                    self.save_notification = Some(format!("✖ {}", self.state.status.clone()));
                } else {
                    self.save_notification = Some("✔ Settings saved successfully.".into());
                }
            }
        });

        ui.add_space(10.0);

        // Section 2: Profiles
        ui.group(|ui| {
            ui.heading("📋 Routing Profiles");
            ui.label("Save different sets of bypass rules for different VPN networks or tasks.");
            ui.add_space(6.0);

            // Active Profile Banner
            let active_pid_opt = self.state.store.active_profile;
            let active_profile_name = self.state.store.profiles
                .iter()
                .find(|p| Some(p.id) == active_pid_opt)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "None".into());

            let current_rules_count = self.state.store.profiles
                .iter()
                .find(|p| Some(p.id) == active_pid_opt)
                .map(|p| p.rules.iter().filter(|r| r.enabled).count())
                .unwrap_or(0);

            let live_count = self.state.active_bypass_count();

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("Current Active Profile: {}", active_profile_name)).strong().color(egui::Color32::from_rgb(52, 211, 153)));
                ui.label(format!("({} rules configured, {} active in memory)", current_rules_count, live_count));

                if self.state.has_unsaved_changes() {
                    ui.label(egui::RichText::new("● Unsaved changes").strong().color(egui::Color32::from_rgb(251, 191, 36)));
                }

                if ui.button("💾 Save Profile Changes").on_hover_text("Save current bypass rules & adapter into this active profile").clicked() {
                    self.state.save_current_bypasses_to_active_profile();
                    self.save_notification = Some(format!("✔ Saved changes to profile '{}'.", active_profile_name));
                }

                if self.state.has_unsaved_changes()
                    && ui.button("↩ Revert").on_hover_text("Discard changes and revert to last saved state").clicked()
                {
                    self.state.revert_active_profile();
                    self.save_notification = Some(format!("✔ Reverted profile '{}'.", active_profile_name));
                }
            });

            ui.separator();

            // Create New Profile
            ui.horizontal(|ui| {
                let name_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.new_profile_name)
                        .hint_text("New profile name (e.g. Gaming, Work)...")
                        .desired_width(220.0),
                );

                let has_name = !self.new_profile_name.trim().is_empty();
                // Enter in the name field is the form's primary action.
                let enter_pressed = name_resp.has_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                // Two profiles with the same name make the switcher and
                // every "activated profile X" message ambiguous: refuse
                // duplicates with a visible reason.
                let trimmed_name = self.new_profile_name.trim().to_string();
                let name_taken = has_name
                    && self
                        .state
                        .store
                        .profiles
                        .iter()
                        .any(|p| p.name.eq_ignore_ascii_case(&trimmed_name));

                let create_current = ui.add_enabled(has_name && !name_taken, egui::Button::new("📋 Save Current As New Profile"))
                    .on_hover_text("Save current bypasses as a new independent profile (preserves previous profile untouched)")
                    .clicked()
                    || (enter_pressed && has_name && !name_taken);

                if create_current {
                    let name = trimmed_name.clone();
                    self.state.create_profile(name.clone(), true);
                    self.new_profile_name.clear();
                    self.save_notification = Some(format!("✔ Created independent profile '{}' with current bypasses.", name));
                }

                if ui.add_enabled(has_name && !name_taken, egui::Button::new("✨ Create Blank Profile"))
                    .on_hover_text("Create a new empty profile with zero rules to configure from scratch")
                    .clicked()
                {
                    let name = trimmed_name.clone();
                    self.state.create_profile(name.clone(), false);
                    self.new_profile_name.clear();
                    self.save_notification = Some(format!("✔ Created clean profile '{}'.", name));
                }

                if name_taken {
                    ui.label(
                        egui::RichText::new("A profile with this name already exists.")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(251, 191, 36)),
                    );
                }
            });

            ui.add_space(6.0);

            // Profile List
            let profiles = self.state.store.profiles.clone();
            let mut switch_to: Option<Uuid> = None;
            let mut delete_target: Option<Uuid> = None;
            let mut duplicate_target: Option<Uuid> = None;
            let mut rename_target: Option<(Uuid, String)> = None;
            let mut remove_rule_target: Option<(Uuid, Uuid)> = None;
            let mut rule_toggle_target: Option<(Uuid, Uuid, bool)> = None;

            for p in &profiles {
                let is_active = self.state.store.active_profile == Some(p.id);
                let rules_count = p.rules.iter().filter(|r| r.enabled).count();

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        // Profile Name or Inline Rename
                        if self.editing_profile_id == Some(p.id) {
                            ui.add(egui::TextEdit::singleline(&mut self.editing_profile_name).desired_width(150.0));
                            if ui.button("✔ Save").clicked() {
                                if self.editing_profile_name.trim().is_empty() {
                                    // An empty rename used to close the
                                    // editor with NO message at all.
                                    self.save_notification = Some(
                                        "✖ Profile name cannot be empty.".into(),
                                    );
                                } else {
                                    rename_target =
                                        Some((p.id, self.editing_profile_name.clone()));
                                    self.editing_profile_id = None;
                                }
                            }
                            if ui.button("✖ Cancel").clicked() {
                                self.editing_profile_id = None;
                            }
                        } else {
                            ui.label(egui::RichText::new(&p.name).strong().size(14.0));
                            if ui.small_button("✏").on_hover_text("Rename profile").clicked() {
                                self.editing_profile_id = Some(p.id);
                                self.editing_profile_name = p.name.clone();
                            }
                        }

                        ui.label(format!("({} bypass rules)", rules_count));

                        if let Some(idx) = p.adapter_index {
                            if let Some(iface) = self.state.interfaces.iter().find(|i| i.index == idx) {
                                ui.label(egui::RichText::new(format!("🌐 {}", iface.name)).weak().size(11.0));
                            }
                        }

                        // Right aligned actions
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if profiles.len() > 1
                                && ui.button("🗑 Delete").on_hover_text("Delete this profile").clicked()
                            {
                                delete_target = Some(p.id);
                            }

                            if ui.button("📋 Duplicate").on_hover_text("Clone this profile").clicked() {
                                duplicate_target = Some(p.id);
                            }

                            let is_expanded = self.expanded_profile_id == Some(p.id);
                            if ui.button(if is_expanded { "▲ Hide Rules" } else { "👁 View Rules" }).clicked() {
                                self.expanded_profile_id = if is_expanded { None } else { Some(p.id) };
                            }

                            if is_active {
                                ui.colored_label(egui::Color32::from_rgb(52, 211, 153), "● Active Profile");
                            } else if ui.button("⚡ Activate").on_hover_text("Switch to this profile").clicked() {
                                switch_to = Some(p.id);
                            }
                        });
                    });

                    // Expanded Rules View
                    if self.expanded_profile_id == Some(p.id) {
                        ui.separator();
                        if p.rules.is_empty() {
                            ui.label(egui::RichText::new("No bypass rules saved in this profile. Toggle bypass on apps in the Applications tab to add them.").weak().italics());
                        } else {
                            for r in &p.rules {
                                ui.horizontal(|ui| {
                                    let app_name = self.state.apps
                                        .iter()
                                        .find(|a| a.id == r.app_id)
                                        .map(|a| a.name.clone())
                                        .or_else(|| {
                                            r.exe_path.as_ref().and_then(|p| {
                                                std::path::Path::new(p)
                                                    .file_stem()
                                                    .map(|s| s.to_string_lossy().to_string())
                                            })
                                        })
                                        .unwrap_or_else(|| "Unknown App".into());

                                    let path_str = r.exe_path
                                        .as_deref()
                                        .unwrap_or("No stored path (the app must be discovered to apply this rule)");

                                    ui.label(egui::RichText::new(format!("• {}", app_name)).strong());
                                    ui.label(egui::RichText::new(path_str).weak().size(11.0));
                                    // The engine honors a rule's enabled
                                    // flag; show it and let it be toggled
                                    // here (previously only hand-edited
                                    // JSON could produce a disabled rule).
                                    if r.enabled {
                                        ui.label(
                                            egui::RichText::new("● Enabled")
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(52, 211, 153)),
                                        );
                                    } else {
                                        ui.label(
                                            egui::RichText::new("○ Disabled")
                                                .size(11.0)
                                                .color(egui::Color32::from_rgb(148, 163, 184)),
                                        );
                                    }

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.small_button("✖ Remove").on_hover_text("Remove from this profile").clicked() {
                                            remove_rule_target = Some((p.id, r.app_id));
                                        }
                                        if ui
                                            .small_button(if r.enabled { "Disable" } else { "Enable" })
                                            .on_hover_text("Toggle this rule without deleting it")
                                            .clicked()
                                        {
                                            rule_toggle_target = Some((p.id, r.app_id, !r.enabled));
                                        }
                                    });
                                });
                            }
                        }
                    }
                });
            }

            if let Some(id) = switch_to {
                self.state.switch_profile(id);
                self.save_notification = Some("✔ Switched active profile.".into());
            }
            if let Some((id, new_name)) = rename_target {
                self.state.rename_profile(id, new_name);
                self.save_notification = Some("✔ Profile renamed.".into());
            }
            if let Some(id) = duplicate_target {
                self.state.duplicate_profile(id);
                self.save_notification = Some("✔ Profile duplicated.".into());
            }
            if let Some(id) = delete_target {
                self.pending_confirm = Some(PendingConfirm::DeleteProfile(id));
            }
            if let Some((pid, aid)) = remove_rule_target {
                self.pending_confirm = Some(PendingConfirm::RemoveRule(pid, aid));
            }
            if let Some((pid, aid, enabled)) = rule_toggle_target {
                self.state.set_rule_enabled(pid, aid, enabled);
                self.save_notification = Some(if enabled {
                    "✔ Rule enabled.".into()
                } else {
                    "✔ Rule disabled.".into()
                });
            }
        });

        ui.add_space(10.0);

        // Section 3: Windows Firewall & Internet Killswitch
        ui.group(|ui| {
            ui.heading("🛡️ Windows Firewall & Internet Killswitch");
            ui.label(
                "BiFlow controls Windows Defender Firewall to block new network connections \
                for any application (verified by readback after every change).",
            );
            ui.add_space(4.0);

            let blocked_count = self.state.store.blocked_apps.len();
            ui.horizontal(|ui| {
                ui.label(format!("Currently Blocked: {} applications", blocked_count));
                if blocked_count > 0 && ui.button("🧹 Unblock All Applications").clicked() {
                    self.pending_confirm = Some(PendingConfirm::UnblockAll);
                }
            });

            // The blocked apps themselves, manageable from here (this
            // used to be a bare count whose items were reachable only by
            // hunting them in the Applications tab).
            if blocked_count > 0 {
                let blocked_ids = self.state.store.blocked_apps.clone();
                let mut unblock_one: Option<Uuid> = None;
                for bid in &blocked_ids {
                    let label = self
                        .state
                        .apps
                        .iter()
                        .find(|a| a.id == *bid)
                        .map(|a| format!("🚫 {} — {}", a.name, a.executable))
                        .unwrap_or_else(|| format!("🚫 {}", bid));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(label).size(12.0));
                        if ui.small_button("✅ Unblock").clicked() {
                            unblock_one = Some(*bid);
                        }
                    });
                }
                if let Some(bid) = unblock_one {
                    self.state.selected_app = Some(bid);
                    self.state.toggle_block_internet(bid);
                }
            }

            ui.add_space(4.0);
            let elevated = windows::privilege::is_elevated();
            if !elevated {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("⚠️ BiFlow is running as Standard User.")
                            .color(egui::Color32::from_rgb(251, 191, 36)),
                    );
                    if ui.button("⚡ Relaunch as Administrator").clicked() {
                        let _ = windows::privilege::restart_as_administrator();
                    }
                });
                ui.label(
                    egui::RichText::new(
                        "Running as Administrator enables instant 1-click silent blocking without UAC prompts.",
                    )
                    .weak()
                    .size(11.0),
                );
            } else {
                ui.label(
                    egui::RichText::new(
                        "🛡️ Administrator mode active: 1-click silent firewall rule management enabled.",
                    )
                    .color(egui::Color32::from_rgb(52, 211, 153))
                    .size(11.0),
                );
            }
        });

        ui.add_space(10.0);

        // Section 4: Diagnostic & Developer Attribution
        ui.group(|ui| {
            ui.heading("ℹ Application Info & Developer");
            ui.label(
                egui::RichText::new("Developer: Farzad Sholeh")
                    .strong()
                    .size(14.0)
                    .color(egui::Color32::from_rgb(56, 189, 248)),
            );
            ui.label(format!(
                "BiFlow - Windows Per-App Split Routing Tool • Version {}",
                env!("CARGO_PKG_VERSION")
            ));
            ui.label(format!(
                "Configuration path: {}",
                config::store_path().display()
            ));
            ui.label(format!(
                "Diagnostic log path: {}",
                config::log_path().display()
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui
                    .button("📂 Open Data & Log Folder")
                    .on_hover_text(
                        "Open the folder containing the configuration and the diagnostic log",
                    )
                    .clicked()
                {
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(crate::config::data_dir())
                        .spawn();
                }
                if let Some(pd) = crate::windows::injector::biflow_programdata_dir() {
                    if ui
                        .button("📂 Open Policy Folder")
                        .on_hover_text(
                            "Open the protected ProgramData folder holding the hook policy files",
                        )
                        .clicked()
                    {
                        let _ = std::process::Command::new("explorer.exe").arg(pd).spawn();
                    }
                }
            });
        });
    }

    fn tab_about(&mut self, ui: &mut egui::Ui) {
        // Hero Card
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.heading(
                egui::RichText::new("⚡ BiFlow")
                    .size(24.0)
                    .strong()
                    .color(egui::Color32::from_rgb(56, 189, 248)),
            );
            ui.label(
                egui::RichText::new("Windows Per-App Split Routing Engine")
                    .size(15.0)
                    .color(egui::Color32::from_rgb(203, 213, 225)),
            );
            ui.add_space(4.0);
            ui.label(
                "BiFlow provides precision socket-level routing to allow designated Windows \
                applications to connect directly via your physical network adapter while the rest of \
                your operating system routes through an encrypted VPN tunnel.",
            );
        });

        ui.add_space(8.0);

        // Developer Card (Prominently featuring Farzad Sholeh)
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.heading("👨‍💻 Lead Developer");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Developer:")
                        .strong()
                        .size(16.0)
                        .color(egui::Color32::from_rgb(148, 163, 184)),
                );
                ui.label(
                    egui::RichText::new("Farzad Sholeh")
                        .strong()
                        .size(17.0)
                        .color(egui::Color32::from_rgb(52, 211, 153)),
                );
            });
            ui.add_space(4.0);
            ui.label("Project: BiFlow Split Routing System for Windows");
            ui.label("Architecture: Winsock Socket Hooking & Process Injection Subsystem");
            ui.label("Platform: Windows 10 / Windows 11 (64-bit)");
        });

        ui.add_space(8.0);

        // Feature Highlights
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.heading("🌟 Core Capabilities");
            ui.add_space(4.0);
            ui.label("• Cached Process Scanning: Process and connection snapshots are computed on a background thread, so the list stays fluid without rescanning every frame.");
            ui.label("• Open-Connection Detection: Lists apps holding established TCP connections or UDP endpoints (a socket snapshot, not a traffic meter).");
            ui.label("• Seamless System Tray Docking: Minimize, restore, and safe background execution; the tray tooltip shows how many bypasses are live.");
            ui.label("• Windows Startup Integration: Task Scheduler logon task (protected install locations only).");
            ui.label("• Non-Destructive Winsock Hooking: No routing table corruption, no global IP metric manipulation.");
        });

        ui.add_space(8.0);

        // Usage Instructions
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.heading("📖 How to Use");
            ui.add_space(4.0);
            ui.label("1. Go to 'Network Adapters' and select your physical Wi-Fi or Ethernet card as Direct.");
            ui.label("2. Go to 'Applications' and find the software you want to exclude from the VPN.");
            ui.label("3. Click 'Enable Direct Bypass' (or 'Launch Direct' to start a new instance).");
            ui.label("4. When minimized, BiFlow docks to your system tray next to the Windows clock.");
            ui.label("5. Read the status pill on each app: 'BYPASSING VPN' means the hook is verified live in the process, 'BYPASS CONFIGURED' means it activates when the app starts, and 'BYPASS FAILED' shows the reason under the row. Live still does not prove the egress route — compare the app's public IP against your VPN's to confirm.");
        });
    }
}

/// Color for the status bar: failures read as failures. The bar used to
/// render every message — errors included — in one calm blue.
fn status_color(status: &str) -> egui::Color32 {
    let lower = status.to_lowercase();
    if lower.starts_with('⚠')
        || ["failed", "error", "could not", "blocked:", "aborted", "✖"]
            .iter()
            .any(|k| lower.contains(k))
    {
        egui::Color32::from_rgb(248, 113, 113)
    } else if status.starts_with('✅') || status.starts_with('✔') {
        egui::Color32::from_rgb(52, 211, 153)
    } else {
        egui::Color32::from_rgb(186, 230, 253)
    }
}

impl BiFlowApp {
    /// Modal confirmation for destructive actions. Renders above
    /// everything; the action runs only on an explicit Confirm click.
    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(pending) = self.pending_confirm.clone() else {
            return;
        };
        let (title, body, confirm_label) = match &pending {
            PendingConfirm::DeleteProfile(id) => {
                let name = self
                    .state
                    .store
                    .profiles
                    .iter()
                    .find(|p| p.id == *id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "?".into());
                let was_active = self.state.store.active_profile == Some(*id);
                (
                    "Delete profile?",
                    format!(
                        "Delete profile '{}'? Its bypass rules are removed with it.{}",
                        name,
                        if was_active {
                            " It is the ACTIVE profile: the first remaining profile becomes active and its rules are applied."
                        } else {
                            ""
                        }
                    ),
                    "🗑 Delete",
                )
            }
            PendingConfirm::RemoveRule(pid, aid) => {
                let app_name = self
                    .state
                    .apps
                    .iter()
                    .find(|a| a.id == *aid)
                    .map(|a| a.name.clone())
                    .unwrap_or_else(|| "this app".into());
                let is_active_profile = self.state.store.active_profile == Some(*pid);
                (
                    "Remove rule?",
                    format!(
                        "Remove the bypass rule for {} from this profile?{}",
                        app_name,
                        if is_active_profile {
                            " The profile is active, so the live bypass stops too."
                        } else {
                            ""
                        }
                    ),
                    "✖ Remove",
                )
            }
            PendingConfirm::UnblockAll => (
                "Unblock all applications?",
                "Remove every BiFlow block rule from Windows Firewall? All currently blocked applications regain full internet access.".to_string(),
                "🧹 Unblock All",
            ),
            PendingConfirm::SetVpnAdapter(_, name) => (
                "Use a VPN adapter as Direct?",
                format!(
                    "'{}' looks like a VPN / tunnel adapter. Setting it as the Direct adapter routes bypassed apps INTO the tunnel — the opposite of a bypass. Continue only if you really mean it.",
                    name
                ),
                "Use Anyway",
            ),
        };

        let mut decision: Option<bool> = None;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.label(body);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(confirm_label).color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(190, 30, 45)),
                        )
                        .clicked()
                    {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });

        if let Some(ok) = decision {
            self.pending_confirm = None;
            if ok {
                match pending {
                    PendingConfirm::DeleteProfile(id) => {
                        self.save_notification = Some(match self.state.delete_profile(id) {
                            Ok(msg) => msg,
                            Err(e) => format!("✖ {}", e),
                        });
                    }
                    PendingConfirm::RemoveRule(pid, aid) => {
                        self.state.remove_rule_from_profile(pid, aid);
                        self.save_notification = Some("✔ Rule removed from profile.".into());
                    }
                    PendingConfirm::UnblockAll => {
                        self.save_notification = Some(match self.state.unblock_all_apps() {
                            Ok(()) => {
                                "✔ All applications have been unblocked from Windows Firewall."
                                    .into()
                            }
                            Err(_) => format!("✖ {}", self.state.status.clone()),
                        });
                    }
                    PendingConfirm::SetVpnAdapter(idx, _) => {
                        self.state.set_selected_adapter(idx);
                    }
                }
            }
        }
    }
}

impl eframe::App for BiFlowApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle Tray & Window state
        self.check_tray_and_window_state(ctx);

        // If the window is currently hidden in the system tray, skip GUI drawing
        if self.is_hidden {
            return;
        }

        // Ctrl+F jumps to the Applications search box from anywhere.
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::F)) {
            self.tab = Tab::Apps;
            self.search_focus_requested = true;
        }

        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(4.0);
            self.top_header(ui);
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(2.0);
            self.nav_bar(ui);
            ui.add_space(2.0);
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(&self.state.status)
                        .size(12.0)
                        .color(status_color(&self.state.status)),
                );
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Global action-result banner: visible on every tab, colored
            // by outcome (an error must not render green), dismissed only
            // by the user. It used to exist only inside the Settings tab.
            let mut dismiss = false;
            if let Some(msg) = &self.save_notification {
                let color = if msg.starts_with('✖') || msg.starts_with('❌') {
                    egui::Color32::from_rgb(248, 113, 113)
                } else if msg.starts_with('✔') || msg.starts_with('✅') {
                    egui::Color32::from_rgb(52, 211, 153)
                } else {
                    egui::Color32::from_rgb(226, 232, 240)
                };
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(msg.as_str()).strong().color(color));
                    if ui.small_button("✖").on_hover_text("Dismiss").clicked() {
                        dismiss = true;
                    }
                });
                ui.add_space(4.0);
            }
            if dismiss {
                self.save_notification = None;
            }

            match self.tab {
                Tab::Apps => self.tab_apps(ui),
                Tab::Network => self.tab_network(ui),
                Tab::Settings => self.tab_settings(ui),
                Tab::About => self.tab_about(ui),
            }
        });

        self.confirm_dialog(ctx);
    }
}
