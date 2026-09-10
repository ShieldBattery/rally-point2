//! Notice reporter authorization: which relay may report a departure for a
//! session, and when a notice actually signs a tenant webhook.

use super::*;

// -- Notice reporter authorization (cross-tenant forgery guard) --

#[tokio::test]
async fn a_notice_from_a_relay_not_serving_the_session_signs_no_webhook() {
    // The cross-tenant forgery guard: relay 2 never served this session, so a
    // result it reports for the victim tenant + session must not be signed with
    // the tenant's key and delivered to its webhook.
    let (url, mut rx) = spawn_webhook_receiver().await;
    let (setup, notices, lifecycle, session) = setup_with_session_and_notify(url);

    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(2),
        0, // no live connection generation in this direct-call test
        &result_message(session, 0),
        &idle_rtt_ingest(&RegionsConfig::default(), &pair_rtts::new_store()),
    );

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "a result from a relay outside the serving set delivers no webhook",
    );
}

#[tokio::test]
async fn a_notice_from_a_serving_relay_delivers_its_webhook() {
    let (url, mut rx) = spawn_webhook_receiver().await;
    let (setup, notices, lifecycle, session) = setup_with_session_and_notify(url);

    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        0, // no live connection generation in this direct-call test
        &result_message(session, 0),
        &idle_rtt_ingest(&RegionsConfig::default(), &pair_rtts::new_store()),
    );

    tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("a result from the serving relay delivers its webhook")
        .expect("the receiver got it");
}

#[tokio::test]
async fn a_notice_for_a_session_with_no_serving_record_still_delivers() {
    // Post-restart tail: the coordinator holds no serving-relay record for the
    // session (created in a previous lifetime), so there is nothing to check the
    // reporter against and the notice must still be honored.
    let (url, mut rx) = spawn_webhook_receiver().await;
    let (setup, notices, lifecycle, _created) = setup_with_session_and_notify(url);

    // A session id the coordinator never created this lifetime -> empty serving
    // set, so even an arbitrary relay id is allowed through.
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(2),
        0, // no live connection generation in this direct-call test
        &result_message(SessionId(4242), 0),
        &idle_rtt_ingest(&RegionsConfig::default(), &pair_rtts::new_store()),
    );

    tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("a notice for a session with no serving record still delivers")
        .expect("the receiver got it");
}
