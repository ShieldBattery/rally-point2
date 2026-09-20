use super::*;

/// A well-formed two-region config in a deliberate, non-alphabetical order,
/// so a test can prove file order is preserved.
const VALID: &str = r#"{
    "regions": [
        {"id": "local-b", "display_name": "Local B", "beacon": "b.example:20000", "fallback": "b.example:443"},
        {"id": "local-a", "display_name": "Local A", "beacon": "a.example:20000", "fallback": "a.example:443"}
    ]
}"#;

#[test]
fn loads_a_valid_config_and_preserves_file_order() {
    let config = RegionsConfig::from_json(VALID).unwrap();
    let ids: Vec<&str> = config.regions().iter().map(|r| r.id.as_ref()).collect();
    assert_eq!(ids, vec!["local-b", "local-a"], "file order is preserved");
    assert!(config.contains(&RegionId("local-a".to_owned())));
    assert!(!config.contains(&RegionId("nope".to_owned())));
}

#[test]
fn an_empty_list_is_rejected() {
    assert!(matches!(
        RegionsConfig::from_json(r#"{"regions": []}"#),
        Err(RegionsError::Empty)
    ));
}

#[test]
fn a_duplicate_id_is_rejected() {
    let json = r#"{"regions": [
        {"id": "us", "display_name": "US", "beacon": "h:1", "fallback": "h:2"},
        {"id": "us", "display_name": "US 2", "beacon": "h:3", "fallback": "h:4"}
    ]}"#;
    assert!(matches!(
        RegionsConfig::from_json(json),
        Err(RegionsError::DuplicateId(id)) if id == "us"
    ));
}

#[test]
fn an_id_outside_the_allowed_charset_or_length_is_rejected() {
    // A region id is an opaque label the whole system keys on, so the charset and
    // the length bound are both fail-closed at startup rather than sanitized.
    let oversize = "a".repeat(MAX_REGION_ID_LEN + 1);
    for (id, why) in [
        ("US_East", "uppercase and underscores are outside [a-z0-9-]"),
        (oversize.as_str(), "longer than the length bound"),
        ("", "an empty id names nothing"),
        ("us east", "a space is outside [a-z0-9-]"),
    ] {
        let json = format!(
            r#"{{"regions": [{{"id": "{id}", "display_name": "X", "beacon": "h:1", "fallback": "h:2"}}]}}"#
        );
        assert!(
            matches!(
                RegionsConfig::from_json(&json),
                Err(RegionsError::InvalidId(_))
            ),
            "{id:?} must be refused: {why}",
        );
    }
}

#[test]
fn an_empty_required_field_is_rejected() {
    for (bad, field) in [
        (
            r#"{"id": "us", "display_name": "", "beacon": "h:1", "fallback": "h:2"}"#,
            "display_name",
        ),
        (
            r#"{"id": "us", "display_name": "US", "beacon": "", "fallback": "h:2"}"#,
            "beacon",
        ),
        (
            r#"{"id": "us", "display_name": "US", "beacon": "h:1", "fallback": ""}"#,
            "fallback",
        ),
    ] {
        let json = format!(r#"{{"regions": [{bad}]}}"#);
        match RegionsConfig::from_json(&json) {
            Err(RegionsError::EmptyField { field: got, .. }) => assert_eq!(got, field),
            other => panic!("expected EmptyField({field}), got {other:?}"),
        }
    }
}

#[test]
fn config_serializes_as_regions_object() {
    let config = RegionsConfig::from_json(VALID).unwrap();
    let json = serde_json::to_value(&config).unwrap();
    let regions = json.get("regions").unwrap().as_array().unwrap();
    // The field names are the client's contract, not an implementation detail:
    // renaming one in the derive would break every client parsing this response
    // while a round-trip through this same type still passed.
    let first = regions[0].as_object().unwrap();
    let mut keys: Vec<&str> = first.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["beacon", "display_name", "fallback", "id"]);
    assert_eq!(first.get("id").unwrap(), "local-b");
    assert_eq!(first.get("display_name").unwrap(), "Local B");
    assert_eq!(first.get("beacon").unwrap(), "b.example:20000");
    assert_eq!(first.get("fallback").unwrap(), "b.example:443");
    // Round-trips through the same shape the endpoint serves.
    let back = RegionsConfig::from_json(&serde_json::to_string(&config).unwrap()).unwrap();
    assert_eq!(back.regions(), config.regions());
}

#[test]
fn beacon_targets_pair_each_region_with_its_configured_beacon_in_file_order() {
    // The beacon push tells every relay which endpoint to measure for each
    // region. It is one target per configured region, in the config's own order,
    // carrying that region's `beacon` exactly as written — including a region
    // whose beacon hostname is the formulaic one the fleet ships for a region
    // with no live ping endpoint. That beacon is expected to be unreachable and
    // the client falls back to the region's TCP endpoint; filtering the region
    // out of the push here would instead leave it unmeasurable altogether.
    let json = r#"{"regions": [
        {"id": "us-east", "display_name": "US East", "beacon": "us-east.ping.example:20000", "fallback": "us-east.example:443"},
        {"id": "mx", "display_name": "Mexico", "beacon": "gamelift-ping.mx-central-1.api.aws:20000", "fallback": "mx.example:443"},
        {"id": "eu-west", "display_name": "EU West", "beacon": "eu-west.ping.example:20000", "fallback": "eu-west.example:443"}
    ]}"#;
    let config = RegionsConfig::from_json(json).unwrap();
    let pushed = config.beacon_targets();
    let targets: Vec<(&str, &str)> = pushed
        .iter()
        .map(|t| (t.region.as_ref(), t.beacon.as_str()))
        .collect();
    assert_eq!(
        targets,
        vec![
            ("us-east", "us-east.ping.example:20000"),
            ("mx", "gamelift-ping.mx-central-1.api.aws:20000"),
            ("eu-west", "eu-west.ping.example:20000"),
        ],
    );

    // No regions configured means no beacons to measure, and an empty vec is the
    // signal to omit the push entirely for a region-blind fleet.
    assert!(RegionsConfig::default().beacon_targets().is_empty());
}
