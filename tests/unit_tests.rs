use biflow::models::{BypassRule, Profile, Store};
use uuid::Uuid;

#[test]
fn default_store_contains_a_usable_profile() {
    let store = Store::default();
    assert_eq!(store.schema_version, 2);
    assert_eq!(store.profiles.len(), 1);
    assert!(store.profiles[0].enabled);
    assert!(!store.profiles[0].name.is_empty());
    assert_eq!(store.active_profile, Some(store.profiles[0].id));
}

#[test]
fn profile_ids_are_uuid_values() {
    let store = Store::default();
    assert_ne!(store.profiles[0].id.as_u128(), 0);
}

#[test]
fn profile_serialization_supports_adapter_index_and_rules() {
    let mut store = Store::default();
    let mut p2 = Profile::new("Gaming VPN");
    p2.adapter_index = Some(15);
    let app_uuid = Uuid::new_v4();
    p2.rules.push(BypassRule {
        app_id: app_uuid,
        enabled: true,
        exe_path: Some("C:\\Telegram\\Telegram.exe".into()),
    });
    store.profiles.push(p2);

    let json = serde_json::to_string(&store).expect("Serialization failed");
    let deserialized: Store = serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(deserialized.profiles.len(), 2);
    assert_eq!(deserialized.profiles[1].name, "Gaming VPN");
    assert_eq!(deserialized.profiles[1].adapter_index, Some(15));
    assert_eq!(deserialized.profiles[1].rules.len(), 1);
    assert_eq!(deserialized.profiles[1].rules[0].app_id, app_uuid);
    assert_eq!(
        deserialized.profiles[1].rules[0].exe_path,
        Some("C:\\Telegram\\Telegram.exe".into())
    );
}

