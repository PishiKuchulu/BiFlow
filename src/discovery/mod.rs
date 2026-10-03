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

    for (hive, source) in [
        (RegKey::predef(HKEY_LOCAL_MACHINE), "HKLM"),
        (RegKey::predef(HKEY_CURRENT_USER), "HKCU"),
    ] {
        let paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ];

        for base_path in paths {
            let Ok(base) = hive.open_subkey(base_path) else { continue; };
            for key_name in base.enum_keys().flatten() {
                let Ok(key) = base.open_subkey(&key_name) else { continue; };

                let name: String = key.get_value("DisplayName").unwrap_or_default();
                if name.trim().is_empty() {
                    continue;
                }

                // 1. Try DisplayIcon
                let mut executable = String::new();
                let icon: String = key.get_value("DisplayIcon").unwrap_or_default();
                if !icon.is_empty() {
                    let clean = icon.split(',').next().unwrap_or("").trim().trim_matches('"');
                    if clean.to_ascii_lowercase().ends_with(".exe") && Path::new(clean).exists() {
                        executable = clean.to_string();
                    }
                }

                // 2. Try InstallLocation if DisplayIcon wasn't an executable
                if executable.is_empty() {
                    let location: String = key.get_value("InstallLocation").unwrap_or_default();
                    if !location.is_empty() {
                        let loc_path = Path::new(location.trim().trim_matches('"'));
                        if loc_path.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(loc_path) {
                                for entry in entries.flatten() {
                                    let p = entry.path();
                                    if p.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("exe")) {
                                        let file_stem = p.file_stem().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
                                        // Skip uninstallers
                                        if !file_stem.contains("unins") && !file_stem.contains("setup") && !file_stem.contains("update") {
                                            executable = p.to_string_lossy().to_string();
                                            break;
                                        }
                                    }
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
                    valid: true,
                });
            }
        }

        // Also scan App Paths in HKLM and HKCU
        let app_paths_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
        if let Ok(base) = hive.open_subkey(app_paths_key) {
            for key_name in base.enum_keys().flatten() {
                let Ok(key) = base.open_subkey(&key_name) else { continue; };
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
                        valid: true,
                    });
                }
            }
        }
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
        valid: true,
    })
}

pub fn discover_running_processes() -> Vec<AppEntry> {
    let procs = injector::get_running_gui_processes();
    let mut out = Vec::new();

    for (_pid, name, path) in procs {
        let display_name = Path::new(&path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| name.clone());

        let id = if !path.is_empty() {
            generate_app_id(&path)
        } else {
            generate_app_id(&name)
        };

        out.push(AppEntry {
            id,
            name: display_name,
            publisher: Some("Active Process".into()),
            executable: path,
            version: None,
            source: "Running".into(),
            valid: true,
        });
    }

    out
}
