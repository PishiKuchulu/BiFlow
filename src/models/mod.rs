use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppEntry {
    pub id: Uuid,
    pub name: String,
    pub publisher: Option<String>,
    pub executable: String,
    pub version: Option<String>,
    pub source: String,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BypassRule {
    pub app_id: Uuid,
    pub enabled: bool,
    #[serde(default)]
    pub exe_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
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
            priority: 0,
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

fn default_schema_version() -> u32 {
    2
}

impl Default for Store {
    fn default() -> Self {
        let default_id = Uuid::new_v4();
        Self {
            schema_version: 2,
            active_profile: Some(default_id),
            profiles: vec![Profile {
                id: default_id,
                name: "Default".into(),
                enabled: true,
                priority: 100,
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
}
