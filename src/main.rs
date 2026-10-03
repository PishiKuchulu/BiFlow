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
use std::time::Duration;
use uuid::Uuid;
use windows::tray::BiFlowTray;

fn main() -> eframe::Result<()> {
    if !cfg!(windows) {
        panic!("BiFlow is Windows-only");
    }

    // BiFlow requires Administrator privileges for real Windows Defender Firewall and network packet filtering
    if !windows::privilege::is_elevated() {
        if windows::privilege::restart_as_administrator().is_ok() {
            return Ok(());
        }
    }

    // Enable SeDebugPrivilege to query process paths and network endpoints across all sessions
    let _ = windows::privilege::enable_debug_privilege();

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
            .with_min_inner_size([920.0, 580.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BiFlow",
        opts,
        Box::new(|cc| {
            setup_custom_style(&cc.egui_ctx);
            windows::tray::set_egui_context(cc.egui_ctx.clone());
            Ok(Box::new(BiFlowApp::new(cc, tray)))
        }),
    )
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
    visuals.selection.stroke =
        egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(147, 197, 253));

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    ctx.set_style(style);
}

struct BiFlowApp {
    state: AppState,
    tab: Tab,
    new_profile_name: String,
    _tray: Option<BiFlowTray>,
    is_hidden: bool,
    suppress_minimize_to_tray: bool,
    save_notification: Option<String>,
    editing_profile_id: Option<Uuid>,
    editing_profile_name: String,
    expanded_profile_id: Option<Uuid>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Network,
    Settings,
    About,
}

impl BiFlowApp {
    fn new(_cc: &eframe::CreationContext<'_>, tray: Option<BiFlowTray>) -> Self {
        Self {
            state: AppState::new(),
            tab: Tab::Apps,
            new_profile_name: String::new(),
            _tray: tray,
            is_hidden: false,
            suppress_minimize_to_tray: false,
            save_notification: None,
            editing_profile_id: None,
            editing_profile_name: String::new(),
            expanded_profile_id: None,
        }
    }

    fn check_tray_and_window_state(&mut self, ctx: &egui::Context) {
        ctx.request_repaint_after(Duration::from_millis(150));

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

        // 2. Handle Disable All Request from Tray
        if windows::tray::take_disable_all_requested() {
            self.state.disable_all();
        }

        // 3. Handle Window Close Request (X button)
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.state.store.close_to_tray {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.is_hidden = true;
                windows::hide_main_window();
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                self.state.disable_all();
                windows::injector::clear_target_ip();
                std::process::exit(0);
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
                        if ui.selectable_label(is_curr, text).clicked() {
                            if !is_curr {
                                switch_from_top_bar = Some(p.id);
                            }
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
                    .on_hover_text("Safely close BiFlow and restore standard routing")
                    .clicked()
                {
                    self.state.disable_all();
                    windows::injector::clear_target_ip();
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

                if ui
                    .button("🔄 Refresh")
                    .on_hover_text("Scan for newly started apps and network adapters")
                    .clicked()
                {
                    self.state.refresh();
                }

                let active_count = self.state.manager.count();
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

            let apps_btn = ui.selectable_value(
                &mut self.tab,
                Tab::Apps,
                format!("📱 Applications ({})", app_count),
            );
            if apps_btn.clicked() {
                self.save_notification = None;
            }

            let net_btn = ui.selectable_value(
                &mut self.tab,
                Tab::Network,
                format!("🌐 Network Adapters ({})", iface_count),
            );
            if net_btn.clicked() {
                self.save_notification = None;
            }

            let set_btn = ui.selectable_value(
                &mut self.tab,
                Tab::Settings,
                "⚙ Settings & Startup",
            );
            if set_btn.clicked() {
                self.save_notification = None;
            }

            let about_btn = ui.selectable_value(&mut self.tab, Tab::About, "ℹ About & Developer");
            if about_btn.clicked() {
                self.save_notification = None;
            }
        });
    }

    fn tab_apps(&mut self, ui: &mut egui::Ui) {
        // Quick Stats Banner
        let total_apps = self.state.apps.len();
        let running_apps_count = self
            .state
            .apps
            .iter()
            .filter(|a| self.state.is_app_running(a))
            .count();
        let online_apps_count = self
            .state
            .apps
            .iter()
            .filter(|a| self.state.has_active_network(a))
            .count();
        let active_bypasses_count = self.state.apps.iter().filter(|a| self.state.is_app_bypassed(a.id)).count();

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

            // Stat Card 2: Online with Internet
            ui.group(|ui| {
                ui.set_min_width(160.0);
                ui.label(egui::RichText::new("🌐 Active Internet Sockets").size(11.0).weak());
                ui.label(
                    egui::RichText::new(format!("{} Online", online_apps_count))
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

        // Search & Filter Toolbar
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔍").size(14.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.state.search)
                    .hint_text("Search application by name or executable...")
                    .desired_width(260.0),
            );

            if !self.state.search.is_empty() {
                if ui.button("✖").clicked() {
                    self.state.search.clear();
                }
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
                .selectable_label(self.state.filter_net_only, "🌐 Active Internet")
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

        // High-Performance Zero-Lag Application List
        let q = self.state.search.to_ascii_lowercase();
        let selected_id = self.state.selected_app;

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let mut clicked_selection: Option<Uuid> = None;
                let mut toggle_target: Option<Uuid> = None;
                let mut launch_target: Option<Uuid> = None;
                let mut block_toggle_target: Option<Uuid> = None;

                for app in &self.state.apps {
                    // Search query filter
                    if !q.is_empty()
                        && !app.name.to_ascii_lowercase().contains(&q)
                        && !app.executable.to_ascii_lowercase().contains(&q)
                    {
                        continue;
                    }

                    // Fast in-memory state lookups (0 syscalls, 0 latency)
                    let is_running = self.state.is_app_running(app);
                    let has_net = self.state.has_active_network(app);
                    let is_bypassed = self.state.is_app_bypassed(app.id);
                    let is_live = self.state.manager.is_active(app.id);
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
                                        egui::RichText::new("🌐 Active Internet")
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
                                    let pill_text = if is_live {
                                        "⚡ BYPASSING VPN"
                                    } else {
                                        "⚡ BYPASS CONFIGURED"
                                    };
                                    ui.label(
                                        egui::RichText::new(pill_text)
                                            .size(11.0)
                                            .strong()
                                            .color(egui::Color32::from_rgb(52, 211, 153)),
                                    );
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
                                            "Click to completely cut off and block all internet access for this application via Windows Firewall"
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

                                        if ui.button("🚀 Launch Direct").clicked() {
                                            launch_target = Some(app.id);
                                        }
                                    }
                                },
                            );
                        });

                        // Executable path & details
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(&app.executable)
                                    .monospace()
                                    .size(11.0)
                                    .color(egui::Color32::from_rgb(148, 163, 184)),
                            );
                            if let Some(pub_name) = &app.publisher {
                                ui.label(
                                    egui::RichText::new(format!("• {}", pub_name))
                                        .size(11.0)
                                        .weak(),
                                );
                            }
                        });
                    });
                }

                if let Some(id) = clicked_selection {
                    self.state.selected_app = Some(id);
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
            All other system applications will remain routed through your active VPN tunnel.",
        );
        ui.separator();

        let mut new_selection: Option<u32> = None;
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

                    ui.horizontal(|ui| {
                        let radio = ui.radio(is_selected, &iface.name);
                        if radio.clicked() {
                            new_selection = Some(iface.index);
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

                            if !is_selected && ui.button("Set as Direct Adapter").clicked() {
                                new_selection = Some(iface.index);
                            }
                        });
                    });

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
                        ui.label(egui::RichText::new(format!("Interface Index: {}", iface.index)).weak());
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
    }

    fn tab_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙ Settings & Startup Configuration");
        ui.label("Configure Windows startup behavior, system tray docking, and profiles.");
        ui.separator();

        if let Some(msg) = &self.save_notification {
            ui.label(
                egui::RichText::new(msg)
                    .strong()
                    .color(egui::Color32::from_rgb(52, 211, 153)),
            );
            ui.add_space(4.0);
        }

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
                self.state.toggle_autostart(autostart_val);
                self.save_notification = Some(if autostart_val {
                    "✔ Windows startup enabled successfully.".into()
                } else {
                    "✔ Windows startup disabled.".into()
                });
            }

            ui.add_space(4.0);

            // Tray Checkboxes
            ui.checkbox(
                &mut self.state.store.minimize_to_tray,
                "🗕 Minimize to System Tray when minimized",
            );

            ui.checkbox(
                &mut self.state.store.close_to_tray,
                "❌ Keep running in background when window is closed (X button)",
            );

            ui.add_space(6.0);
            if ui.button("💾 Save Preferences").clicked() {
                self.state.save();
                self.save_notification = Some("✔ Settings saved successfully.".into());
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

            let live_count = self.state.manager.count();

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

                if self.state.has_unsaved_changes() {
                    if ui.button("↩ Revert").on_hover_text("Discard changes and revert to last saved state").clicked() {
                        self.state.revert_active_profile();
                        self.save_notification = Some(format!("✔ Reverted profile '{}'.", active_profile_name));
                    }
                }
            });

            ui.separator();

            // Create New Profile
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_profile_name)
                        .hint_text("New profile name (e.g. Gaming, Work)...")
                        .desired_width(220.0),
                );

                let has_name = !self.new_profile_name.trim().is_empty();

                if ui.add_enabled(has_name, egui::Button::new("📋 Save Current As New Profile"))
                    .on_hover_text("Save current bypasses as a new independent profile (preserves previous profile untouched)")
                    .clicked()
                {
                    let name = self.new_profile_name.trim().to_string();
                    self.state.create_profile(name.clone(), true);
                    self.new_profile_name.clear();
                    self.save_notification = Some(format!("✔ Created independent profile '{}' with current bypasses.", name));
                }

                if ui.add_enabled(has_name, egui::Button::new("✨ Create Blank Profile"))
                    .on_hover_text("Create a new empty profile with zero rules to configure from scratch")
                    .clicked()
                {
                    let name = self.new_profile_name.trim().to_string();
                    self.state.create_profile(name.clone(), false);
                    self.new_profile_name.clear();
                    self.save_notification = Some(format!("✔ Created clean profile '{}'.", name));
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

            for p in &profiles {
                let is_active = self.state.store.active_profile == Some(p.id);
                let rules_count = p.rules.iter().filter(|r| r.enabled).count();

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        // Profile Name or Inline Rename
                        if self.editing_profile_id == Some(p.id) {
                            ui.add(egui::TextEdit::singleline(&mut self.editing_profile_name).desired_width(150.0));
                            if ui.button("✔ Save").clicked() {
                                rename_target = Some((p.id, self.editing_profile_name.clone()));
                                self.editing_profile_id = None;
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
                            if profiles.len() > 1 {
                                if ui.button("🗑 Delete").on_hover_text("Delete this profile").clicked() {
                                    delete_target = Some(p.id);
                                }
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

                                    let path_str = r.exe_path.as_deref().unwrap_or("Dynamic executable");

                                    ui.label(egui::RichText::new(format!("• {}", app_name)).strong());
                                    ui.label(egui::RichText::new(path_str).weak().size(11.0));

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.small_button("✖ Remove").on_hover_text("Remove from this profile").clicked() {
                                            remove_rule_target = Some((p.id, r.app_id));
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
                if let Err(e) = self.state.delete_profile(id) {
                    self.save_notification = Some(format!("❌ {}", e));
                } else {
                    self.save_notification = Some("✔ Profile deleted.".into());
                }
            }
            if let Some((pid, aid)) = remove_rule_target {
                self.state.remove_rule_from_profile(pid, aid);
                self.save_notification = Some("✔ Rule removed from profile.".into());
            }
        });

        ui.add_space(10.0);

        // Section 3: Windows Firewall & Internet Killswitch
        ui.group(|ui| {
            ui.heading("🛡️ Windows Firewall & Internet Killswitch");
            ui.label(
                "BiFlow directly controls Windows Defender Firewall to instantly and completely block \
                network and internet access for any application.",
            );
            ui.add_space(4.0);

            let blocked_count = self.state.store.blocked_apps.len();
            ui.horizontal(|ui| {
                ui.label(format!("Currently Blocked: {} applications", blocked_count));
                if blocked_count > 0 {
                    if ui.button("🧹 Unblock All Applications").clicked() {
                        self.state.unblock_all_apps();
                        self.save_notification =
                            Some("✔ All applications have been unblocked from Windows Firewall.".into());
                    }
                }
            });

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
            ui.label("BiFlow - Windows Per-App Split Routing Tool • Version 0.2.0");
            ui.label(format!(
                "Configuration path: {}",
                config::store_path().display()
            ));
            ui.label(format!("Diagnostic log path: {}", config::log_path().display()));
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
            ui.label("• Zero-Lag Process Scanning: Instant in-memory cache lookup for 120 FPS fluid scrolling.");
            ui.label("• Active Internet Connection Detection: Automatic detection of apps with open TCP/UDP sockets.");
            ui.label("• Seamless System Tray Docking: Instant minimize, restore, and safe background execution.");
            ui.label("• Windows Startup Integration: Built-in registry auto-run for effortless persistence.");
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
        });
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
                        .color(egui::Color32::from_rgb(186, 230, 253)),
                );
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Apps => self.tab_apps(ui),
            Tab::Network => self.tab_network(ui),
            Tab::Settings => self.tab_settings(ui),
            Tab::About => self.tab_about(ui),
        });
    }
}
