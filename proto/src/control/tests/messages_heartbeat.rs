use super::*;

#[test]
fn relay_to_coordinator_heartbeat_roundtrips_json() {
    let message = RelayToCoordinator::Heartbeat {
        roster_complete: false,
        sessions: vec![],
        region_rtts: vec![],
    };
    let json = serde_json::to_string(&message).unwrap();
    // An idle, un-measured relay's beat is byte-identical to the historical
    // payload-free ping: just the tag, both the empty roster and the empty
    // RTT set omitted from the wire — so an older coordinator reads it
    // unchanged.
    assert_eq!(json, r#"{"type":"heartbeat"}"#);
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn a_bare_heartbeat_decodes_with_an_empty_roster() {
    // A beat from a relay that predates the presence roster (or the backbone
    // RTT set) carries neither field; it must decode with both empty, not
    // error.
    let json = r#"{"type":"heartbeat"}"#;
    let back: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(
        back,
        RelayToCoordinator::Heartbeat {
            roster_complete: false,
            sessions: vec![],
            region_rtts: vec![],
        },
    );
}

#[test]
fn a_presence_bearing_heartbeat_roundtrips_json() {
    let message = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![SessionPresence {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slots: vec![SlotId(0), SlotId(3)],
            ever_connected: vec![],
            started: vec![],
            started_at_ms: None,
        }],
        region_rtts: vec![],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"heartbeat\""));
    assert!(json.contains("\"sessions\""));
    assert!(json.contains("\"roster_complete\":true"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn a_load_state_bearing_heartbeat_roundtrips_json() {
    // A beat for a session mid-load: two slots connected, one of them already
    // running its game loop, and this relay is the authority that latched the
    // start. The whole retained state rides every beat, which is what makes it
    // the durable record behind the droppable notices.
    let message = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![SessionPresence {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slots: vec![SlotId(0), SlotId(3)],
            ever_connected: vec![SlotId(0), SlotId(3)],
            started: vec![SlotId(3)],
            started_at_ms: Some(1_700_000_000_000),
        }],
        region_rtts: vec![],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"ever_connected\":[0,3]"));
    assert!(json.contains("\"started\":[3]"));
    assert!(json.contains("\"started_at_ms\":1700000000000"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn a_heartbeat_without_load_state_omits_the_fields_and_decodes() {
    // A relay that predates the load-state fields — or one running a session
    // with no decision-maker to retain any — sends a roster entry that is
    // byte-identical to the pre-load-state shape, and a decoder that has the
    // fields reads it as "nothing reported" rather than erroring.
    let message = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![SessionPresence {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slots: vec![SlotId(0)],
            ever_connected: vec![],
            started: vec![],
            started_at_ms: None,
        }],
        region_rtts: vec![],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(!json.contains("ever_connected"));
    assert!(!json.contains("started"));

    let json = r#"{"type":"heartbeat","roster_complete":true,"sessions":[{"tenant":"sb-staging","session":42,"slots":[0]}]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn an_rtt_bearing_heartbeat_roundtrips_and_omits_an_empty_set() {
    // A beat carrying measured backbone RTTs serializes the field; the same
    // beat with an empty set omits it entirely (byte-identical to a beat that
    // never measured anything), so an older coordinator reads either unchanged.
    let with_rtts = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts: vec![
            RegionRttReport {
                region: RegionId("eu-central".to_owned()),
                rtt_ms: 87,
            },
            RegionRttReport {
                region: RegionId("us-east".to_owned()),
                rtt_ms: 42,
            },
        ],
    };
    let json = serde_json::to_string(&with_rtts).unwrap();
    assert!(json.contains("\"region_rtts\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, with_rtts);

    let empty = RelayToCoordinator::Heartbeat {
        roster_complete: false,
        sessions: vec![],
        region_rtts: vec![],
    };
    let empty_json = serde_json::to_string(&empty).unwrap();
    assert!(
        !empty_json.contains("region_rtts"),
        "an empty RTT set stays off the wire",
    );
}

#[test]
fn an_rtt_bearing_heartbeat_decodes_on_a_pre_rtt_decoder() {
    // A coordinator whose Heartbeat variant predates `region_rtts` ignores the
    // unrecognized field rather than erroring, so a newer relay's measured beat
    // still reads as a liveness signal + its roster.
    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum PreRttRelayToCoordinator {
        Heartbeat {
            #[serde(default)]
            sessions: Vec<SessionPresence>,
        },
        #[serde(other)]
        Unknown,
    }

    let json = serde_json::to_string(&RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts: vec![RegionRttReport {
            region: RegionId("us-west".to_owned()),
            rtt_ms: 13,
        }],
    })
    .unwrap();
    let decoded: PreRttRelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(
        decoded,
        PreRttRelayToCoordinator::Heartbeat { sessions: vec![] },
    );
}

#[test]
fn a_presence_bearing_heartbeat_decodes_on_a_pre_presence_decoder() {
    // A newer relay's roster-bearing beat read by a coordinator whose enum
    // still has the payload-free unit variant: internally-tagged serde ignores
    // the unrecognized `sessions` field, so the old build reads a plain
    // heartbeat rather than erroring — the beat stays a liveness signal.
    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum PrePresenceRelayToCoordinator {
        Heartbeat,
        #[serde(other)]
        #[allow(dead_code)]
        Unknown,
    }
    let json = serde_json::to_string(&RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![SessionPresence {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slots: vec![SlotId(0)],
            ever_connected: vec![],
            started: vec![],
            started_at_ms: None,
        }],
        region_rtts: vec![],
    })
    .unwrap();
    let decoded: PrePresenceRelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, PrePresenceRelayToCoordinator::Heartbeat);
}
