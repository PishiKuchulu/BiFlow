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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub schema_version: u32,
    pub active_profile: Option<Uuid>,
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
}

fn default_true() -> bool {
    true
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
            }],
            custom_apps: vec![],
            blocked_apps: vec![],
            blocked_executables: vec![],
            minimize_to_tray: true,
            close_to_tray: true,
            autostart: false,
            selected_adapter_index: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub status: String,
    pub description: String,
    pub ipv4: Option<String>,
    pub gateway: Option<String>,
    pub virtual_adapter: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EnforcementStatus {
    NotConfigured,
    Applied,
    Failed(String),
}
