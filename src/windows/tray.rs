use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

static RESTORE_REQUESTED: AtomicBool = AtomicBool::new(false);
static DISABLE_ALL_REQUESTED: AtomicBool = AtomicBool::new(false);
static RESUME_REQUESTED: AtomicBool = AtomicBool::new(false);
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);
static EGUI_CTX: Mutex<Option<eframe::egui::Context>> = Mutex::new(None);

pub fn set_egui_context(ctx: eframe::egui::Context) {
    if let Ok(mut lock) = EGUI_CTX.lock() {
        *lock = Some(ctx);
    }
}

pub fn take_restore_requested() -> bool {
    RESTORE_REQUESTED.swap(false, Ordering::SeqCst)
}

pub fn take_disable_all_requested() -> bool {
    DISABLE_ALL_REQUESTED.swap(false, Ordering::SeqCst)
}

pub fn take_resume_requested() -> bool {
    RESUME_REQUESTED.swap(false, Ordering::SeqCst)
}

pub fn take_exit_requested() -> bool {
    EXIT_REQUESTED.swap(false, Ordering::SeqCst)
}

fn trigger_repaint() {
    if let Ok(lock) = EGUI_CTX.lock() {
        if let Some(ctx) = &*lock {
            ctx.request_repaint();
        }
    }
}

pub struct BiFlowTray {
    tray_icon: TrayIcon,
}

impl BiFlowTray {
    /// Pushes live engine state into the tray tooltip. Without this the
    /// tray is a one-way surface: it accepts actions but never reflects
    /// how many bypasses are actually live, so a user whose bypasses
    /// silently fail-closed (adapter unplugged) gets no hint from the
    /// place they are most likely to glance at.
    pub fn set_tooltip(&self, text: &str) {
        let _ = self.tray_icon.set_tooltip(Some(text));
    }

    pub fn new() -> Result<Self, String> {
        let icon = create_app_icon()?;

        let menu = Menu::new();
        let show_item = MenuItem::new("Open BiFlow", true, None);
        let disable_all_item = MenuItem::new("Disable All Bypasses", true, None);
        let resume_item = MenuItem::new("Resume Bypasses", true, None);
        let separator = PredefinedMenuItem::separator();
        let exit_item = MenuItem::new("Exit", true, None);

        let show_id = show_item.id().clone();
        let disable_id = disable_all_item.id().clone();
        let resume_id = resume_item.id().clone();
        let exit_id = exit_item.id().clone();

        // A silently swallowed append failure means a menu item simply
        // never exists and nobody ever learns why; record it.
        for (label, res) in [
            ("Open BiFlow", menu.append(&show_item)),
            ("Disable All Bypasses", menu.append(&disable_all_item)),
            ("Resume Bypasses", menu.append(&resume_item)),
            ("separator", menu.append(&separator)),
            ("Exit", menu.append(&exit_item)),
        ] {
            if let Err(e) = res {
                crate::config::append_log(&format!(
                    "TRAY_MENU_APPEND_FAILED item={} err={}",
                    label, e
                ));
            }
        }

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("BiFlow - Windows Split Routing")
            .with_icon(icon)
            .build()
            .map_err(|e| format!("Failed to create system tray icon: {}", e))?;

        // 1. Menu click handler: Executes immediately in the Windows message callback!
        //    It only sets flags: exiting from inside this callback used to
        //    kill the process with process::exit(0) while the UI thread might
        //    be halfway through a config save. The main thread polls the
        //    flags and performs an orderly shutdown itself.
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if event.id == exit_id {
                EXIT_REQUESTED.store(true, Ordering::SeqCst);
                trigger_repaint();
            } else if event.id == show_id {
                RESTORE_REQUESTED.store(true, Ordering::SeqCst);
                crate::windows::bring_window_to_front();
                trigger_repaint();
            } else if event.id == disable_id {
                DISABLE_ALL_REQUESTED.store(true, Ordering::SeqCst);
                trigger_repaint();
            } else if event.id == resume_id {
                RESUME_REQUESTED.store(true, Ordering::SeqCst);
                trigger_repaint();
            }
        }));

        // 2. Tray icon click/double-click handler: Executes immediately on click!
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| match event {
            TrayIconEvent::Click { button, .. } => {
                if button == tray_icon::MouseButton::Left {
                    RESTORE_REQUESTED.store(true, Ordering::SeqCst);
                    crate::windows::bring_window_to_front();
                    trigger_repaint();
                }
            }
            TrayIconEvent::DoubleClick { .. } => {
                RESTORE_REQUESTED.store(true, Ordering::SeqCst);
                crate::windows::bring_window_to_front();
                trigger_repaint();
            }
            _ => {}
        }));

        Ok(Self { tray_icon })
    }
}

const EMBEDDED_ICON_32: &[u8] = include_bytes!("../../assets/icon_32.rgba");

fn create_app_icon() -> Result<Icon, String> {
    Icon::from_rgba(EMBEDDED_ICON_32.to_vec(), 32, 32)
        .map_err(|e| format!("Failed to create RGBA icon: {}", e))
}
