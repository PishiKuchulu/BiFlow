use crate::models::AppEntry;
use crate::windows::injector;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;
use winreg::{enums::*, RegKey};

pub fn generate_app_id(executable: &str) -> Uuid {
    let normalized = executable.trim().trim_matches('"').to_ascii_lowercase();
    Uuid::new_v5(&Uuid::NAMESPACE_URL, normalized.as_bytes())
}

pub fn discover() -> Vec<AppEntry> {
    let mut map: HashMap<String, AppEntry> = HashMap::new();
    // Discovery failures used to be indistinguishable from "no apps":
    // every registry error was swallowed silently, so a broken hive read
    // looked exactly like an empty catalog.
    let mut failures = 0usize;

    for (hive, source) in [
        (RegKey::predef(HKEY_LOCAL_MACHINE), "HKLM"),
        (RegKey::predef(HKEY_CURRENT_USER), "HKCU"),
    ] {
        let paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ];

        for base_path in paths {
            let Ok(base) = hive.open_subkey(base_path) else {
                failures += 1;
                continue;
            };
            for key_name in base.enum_keys().flatten() {
                let Ok(key) = base.open_subkey(&key_name) else {
                    failures += 1;
                    continue;
                };

                let name: String = key.get_value("DisplayName").unwrap_or_default();
                if name.trim().is_empty() {
                    continue;
                }

                // 1. Try DisplayIcon
                let mut executable = String::new();
                let icon: String = key.get_value("DisplayIcon").unwrap_or_default();
                if !icon.is_empty() {
                    let clean = icon
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"');
                    if clean.to_ascii_lowercase().ends_with(".exe") && Path::new(clean).exists() {
                        executable = clean.to_string();
                    }
                }

                // 2. Try InstallLocation if DisplayIcon wasn't an executable.
                //    Collect all plausible main executables first, then pick
                //    the best one: previously the FIRST exe in arbitrary
                //    read_dir order won, which could select a helper such as
                //    crashpad_handler.exe or a redistributable installer.
                if executable.is_empty() {
                    let location: String = key.get_value("InstallLocation").unwrap_or_default();
                    if !location.is_empty() {
                        let loc_path = Path::new(location.trim().trim_matches('"'));
                        if loc_path.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(loc_path) {
                                let mut candidates: Vec<std::path::PathBuf> = Vec::new();
                                for entry in entries.flatten() {
                                    let p = entry.path();
                                    if p.extension()
                                        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                                    {
                                        let file_stem = p
                                            .file_stem()
                                            .unwrap_or_default()
                                            .to_string_lossy()
                                            .to_ascii_lowercase();
                                        // Skip uninstallers, installers, updaters,
                                        // crash reporters and redistributables.
                                        const SKIP: &[&str] = &[
                                            "unins",
                                            "setup",
                                            "update",
                                            "crashpad",
                                            "vc_redist",
                                            "redist",
                                            "installer",
                                        ];
                                        if !SKIP.iter().any(|s| file_stem.contains(s)) {
                                            candidates.push(p);
                                        }
                                    }
                                }
                                if !candidates.is_empty() {
                                    // Prefer the exe whose stem matches the
                                    // product's display name; else the first
                                    // candidate in stable (sorted) order.
                                    candidates.sort();
                                    let name_key: String = name
                                        .to_ascii_lowercase()
                                        .chars()
                                        .filter(|c| c.is_ascii_alphanumeric())
                                        .collect();
                                    let best = candidates
                                        .iter()
                                        .find(|p| {
                                            let stem: String = p
                                                .file_stem()
                                                .unwrap_or_default()
                                                .to_string_lossy()
                                                .to_ascii_lowercase()
                                                .chars()
                                                .filter(|c| c.is_ascii_alphanumeric())
                                                .collect();
                                            !stem.is_empty()
                                                && (name_key.starts_with(&stem)
                                                    || stem.starts_with(&name_key))
                                        })
                                        .unwrap_or(&candidates[0]);
                                    executable = best.to_string_lossy().to_string();
                                }
                            }
                        }
                    }
                }

                if executable.is_empty() {
                    continue;
                }

                let publisher = key.get_value("Publisher").ok();
                let version = key.get_value("DisplayVersion").ok();
                let normalized = executable.to_ascii_lowercase();

                let id = generate_app_id(&executable);
                map.entry(normalized).or_insert_with(|| AppEntry {
                    id,
                    name: name.trim().to_string(),
                    publisher,
                    executable,
                    version,
                    source: source.to_string(),
                });
            }
        }

        // Also scan App Paths in HKLM and HKCU
        let app_paths_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
        if let Ok(base) = hive.open_subkey(app_paths_key) {
            for key_name in base.enum_keys().flatten() {
                let Ok(key) = base.open_subkey(&key_name) else {
                    continue;
                };
                let exe_val: String = key.get_value("").unwrap_or_default();
                let clean = exe_val.trim().trim_matches('"');
                if clean.to_ascii_lowercase().ends_with(".exe") && Path::new(clean).exists() {
                    let normalized = clean.to_ascii_lowercase();
                    let name = Path::new(clean)
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| key_name.clone());

                    let id = generate_app_id(clean);
                    map.entry(normalized).or_insert_with(|| AppEntry {
                        id,
                        name,
                        publisher: Some("System Application".into()),
                        executable: clean.to_string(),
                        version: None,
                        source: format!("{} AppPaths", source),
                    });
                }
            }
        }
    }

    if failures > 0 {
        crate::config::append_log(&format!(
            "DISCOVERY_PARTIAL failures={} apps={}",
            failures,
            map.len()
        ));
    }

    let mut out: Vec<_> = map.into_values().collect();
    out.sort_by_key(|a| a.name.to_ascii_lowercase());
    out
}

pub fn pick_executable_file() -> Option<AppEntry> {
    let file = rfd::FileDialog::new()
        .add_filter("Executable File", &["exe"])
        .set_title("Select Application Executable")
        .pick_file()?;

    // The dialog's filter is advisory only ("All files" bypasses it):
    // re-validate what came back before it becomes a persistent custom
    // app that rules and firewall entries will trust.
    let is_exe = file
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"));
    if !is_exe || !file.exists() {
        return None;
    }

    let file_name = file
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Custom App".into());

    let exe_str = file.to_string_lossy().to_string();
    let id = generate_app_id(&exe_str);

    Some(AppEntry {
        id,
        name: file_name,
        publisher: Some("User Added".into()),
        executable: exe_str,
        version: None,
        source: "Custom".into(),
    })
}

pub fn discover_running_processes() -> Vec<AppEntry> {
    let procs = injector::get_running_gui_processes();
    let mut out = Vec::new();

    for (_pid, name, path) in procs {
        // An entry without a full path is unusable everywhere downstream
        // (rules, injection, firewall all key on paths) and its
        // name-derived ID could collide with ANY same-named binary. The
        // producer already guarantees absolute paths; this filter keeps
        // the junk-entry class out even if that ever changes.
        if path.is_empty() {
            continue;
        }
        let display_name = Path::new(&path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| name.clone());

        let id = generate_app_id(&path);

        out.push(AppEntry {
            id,
            name: display_name,
            publisher: Some("Active Process".into()),
            executable: path,
            version: None,
            source: "Running".into(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_is_deterministic_and_case_insensitive() {
        let a = generate_app_id("C:\\Program Files\\App\\app.exe");
        let b = generate_app_id("c:\\program files\\app\\app.exe");
        assert_eq!(a, b, "same path in different case must map to one id");
        let c = generate_app_id("C:\\Program Files\\Other\\app.exe");
        assert_ne!(a, c, "different paths must map to different ids");
    }

    #[test]
    fn app_id_trims_quotes_and_whitespace() {
        let a = generate_app_id("\"C:\\App\\app.exe\"");
        let b = generate_app_id("  C:\\App\\app.exe  ");
        assert_eq!(a, b);
    }
}
