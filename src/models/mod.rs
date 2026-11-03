use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Every nested field carries a serde default: without them, a single
// malformed or partially-written entry inside custom_apps / profiles /
// rules made the WHOLE config unparseable and the loader reset
// everything. With defaults, damage stays local to the bad entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppEntry {
    #[serde(default)]
    pub id: Uuid,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BypassRule {
    #[serde(default)]
    pub app_id: Uuid,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub exe_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    #[serde(default)]
    pub id: Uuid,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<BypassRule>,
    #[serde(default)]
    pub adapter_index: Option<u32>,
    /// Stable adapter identity (the Windows adapter GUID). Preferred over
    /// `adapter_index`, which is an IfIndex and is NOT stable across
    /// reboots or driver reinstalls.
    #[serde(default)]
    pub adapter_id: Option<String>,
}

impl Profile {
    #[allow(dead_code)]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            enabled: true,
            rules: Vec::new(),
            adapter_index: None,
            adapter_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    // Every field carries a serde default so that a config written by an
    // older/newer build (or with one field missing) loads with defaults
    // instead of being renamed to .corrupt and reset wholesale.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub active_profile: Option<Uuid>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub custom_apps: Vec<AppEntry>,
    #[serde(default)]
    pub blocked_apps: Vec<Uuid>,
    #[serde(default)]
    pub blocked_executables: Vec<String>,
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub selected_adapter_index: Option<u32>,
    /// Stable GUID of the selected adapter; preferred over the IfIndex in
    /// `selected_adapter_index` whenever both are present.
    #[serde(default)]
    pub selected_adapter_id: Option<String>,
}

fn default_true() -> bool {
    true
}

/// The config schema version this build writes and understands. The
/// loader refuses a HIGHER version (a downgrade must not silently
/// rewrite a newer config it cannot fully understand); lower versions
/// load through the per-field serde defaults.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

impl Default for Store {
    fn default() -> Self {
        let default_id = Uuid::new_v4();
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            active_profile: Some(default_id),
            profiles: vec![Profile {
                id: default_id,
                name: "Default".into(),
                enabled: true,
                rules: vec![],
                adapter_index: None,
                adapter_id: None,
            }],
            custom_apps: vec![],
            blocked_apps: vec![],
            blocked_executables: vec![],
            minimize_to_tray: true,
            close_to_tray: true,
            autostart: false,
            selected_adapter_index: None,
            selected_adapter_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    /// Windows adapter GUID (AdapterName from GetAdaptersAddresses).
    /// Stable across reboots, unlike `index` (an IfIndex).
    pub adapter_id: String,
    pub status: String,
    pub description: String,
    pub ipv4: Option<String>,
    pub gateway: Option<String>,
    pub virtual_adapter: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_store_has_single_default_profile() {
        let s = Store::default();
        assert_eq!(s.profiles.len(), 1);
        assert_eq!(s.profiles[0].name, "Default");
        assert_eq!(s.active_profile, Some(s.profiles[0].id));
        assert!(s.minimize_to_tray);
        assert!(s.close_to_tray);
    }

    #[test]
    fn bypass_rule_serialization_is_stable() {
        let rule = BypassRule {
            app_id: Uuid::nil(),
            enabled: true,
            exe_path: Some("C:\\App\\app.exe".into()),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: BypassRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn partial_nested_entries_still_parse() {
        // One incomplete profile / custom app / rule must degrade to
        // defaults instead of making the whole config unparseable.
        let json = r#"{
            "profiles": [{"name": "P", "rules": [{"app_id": "12345678-1234-1234-1234-123456789abc"}]}],
            "custom_apps": [{"name": "Half", "executable": "C:\\a\\b.exe"}]
        }"#;
        let store: Store = serde_json::from_str(json).unwrap();
        assert_eq!(store.profiles.len(), 1);
        assert!(store.profiles[0].enabled);
        assert_eq!(store.profiles[0].rules.len(), 1);
        assert!(store.profiles[0].rules[0].enabled);
        assert_eq!(store.custom_apps.len(), 1);
        assert_eq!(store.custom_apps[0].executable, "C:\\a\\b.exe");
        assert_eq!(store.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn legacy_priority_and_valid_fields_are_ignored() {
        // Configs written before those dead fields were removed must keep
        // loading (unknown fields are ignored by serde).
        let json = r#"{
            "profiles": [{"id": "12345678-1234-1234-1234-123456789abc", "name": "P", "enabled": true, "priority": 7, "rules": []}],
            "custom_apps": [{"id": "12345678-1234-1234-1234-123456789abd", "name": "A", "publisher": null, "executable": "C:\\a.exe", "version": null, "source": "Custom", "valid": true}]
        }"#;
        let store: Store = serde_json::from_str(json).unwrap();
        assert_eq!(store.profiles.len(), 1);
        assert_eq!(store.custom_apps.len(), 1);
    }
}
