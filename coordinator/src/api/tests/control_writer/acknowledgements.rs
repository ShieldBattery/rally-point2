use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use rally_point_proto::control::{CAPABILITY_DESCRIPTOR_ACK_V1, CoordinatorToRelay};
use rally_point_proto::version::ProtocolVersion;

use super::*;
use crate::api::control::DrainSend;

#[derive(Clone, Default)]
struct WireSink {
    frames: Arc<Mutex<Vec<Message>>>,
    fail: Arc<AtomicBool>,
}

impl WireSink {
    fn take(&self) -> Vec<Message> {
        std::mem::take(&mut self.frames.lock())
    }
}

impl futures_util::Sink<Message> for WireSink {
    type Error = axum::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.fail.load(Ordering::Relaxed) {
            Poll::Ready(Err(axum::Error::new(std::io::Error::other("failed send"))))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, frame: Message) -> Result<(), Self::Error> {
        self.frames.lock().push(frame);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct Fixture {
    state: CoordinatorState,
    generation: u64,
    sources: WriterSources,
    drain: tokio::sync::mpsc::UnboundedSender<DrainSend>,
    _grants: tokio::sync::mpsc::UnboundedSender<CoordinatorToRelay>,
}

fn fixture(capable: bool) -> Fixture {
    let state = state_with_relay_and_tenant();
    let mut hello = RelaySpec {
        id: 1,
        region: None,
    }
    .hello();
    if capable {
        hello
            .capabilities
            .push(CAPABILITY_DESCRIPTOR_ACK_V1.to_owned());
    }
    let generation = registry::enroll(state.setup.registry(), hello);
    state
        .setup
        .descriptors()
        .record(RelayId(1), diff_descriptor(1, &[2]));
    state
        .setup
        .descriptors()
        .record(RelayId(1), diff_descriptor(2, &[2]));
    let (drain, drain_rx) = tokio::sync::mpsc::unbounded_channel();
    let (grants, grants_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut sources = WriterSources::new(
        &state.setup,
        RelayId(1),
        &state.regions,
        drain_rx,
        grants_rx,
    );
    assert!(sources.enable_acknowledgements(&state.setup, RelayId(1), generation));
    Fixture {
        state,
        generation,
        sources,
        drain,
        _grants: grants,
    }
}

fn ack(state: &CoordinatorState, generation: u64, id: u64) {
    let message = Message::Text(
        serde_json::to_string(&RelayToCoordinator::DescriptorsApplied { ack_id: id })
            .unwrap()
            .into(),
    );
    let regions = RegionsConfig::default();
    let rtts = pair_rtts::PairRttStore::new();
    note_inbound_frame(
        &state.setup,
        &state.lifecycle,
        RelayId(1),
        generation,
        &message,
        &idle_rtt_ingest(&regions, &rtts),
    );
}

fn decoded(frames: Vec<Message>) -> Vec<CoordinatorToRelay> {
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            Message::Text(text) => Some(serde_json::from_str(text.as_str()).unwrap()),
            _ => None,
        })
        .collect()
}

fn full_id(frames: &[CoordinatorToRelay]) -> u64 {
    frames
        .iter()
        .find_map(|frame| match frame {
            CoordinatorToRelay::Descriptors { ack_id, .. } => *ack_id,
            _ => None,
        })
        .expect("capable full descriptor push requests an acknowledgement")
}

#[tokio::test]
async fn full_delta_and_drain_pushes_require_their_own_applied_acknowledgements() {
    let Fixture {
        state,
        generation,
        mut sources,
        drain,
        _grants,
    } = fixture(true);
    let delivery = state.setup.descriptors().delivery();
    let first = diff_descriptor(1, &[2]);
    let second = diff_descriptor(2, &[2]);
    let mut sink = WireSink::default();
    let wire = sink.clone();
    let mut writer = Box::pin(run_writer(
        &mut sink,
        &mut sources,
        RelayId(1),
        Duration::from_secs(5),
        ProtocolVersion::CURRENT,
    ));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let initial_id = full_id(&decoded(wire.take()));
    assert!(!delivery.is_ready(RelayId(1), generation, &first));
    ack(&state, generation + 1, initial_id);
    assert!(!delivery.is_ready(RelayId(1), generation, &first));
    ack(&state, generation, initial_id + 1);
    assert!(!delivery.is_ready(RelayId(1), generation, &first));
    ack(&state, generation, initial_id);
    assert!(delivery.is_ready(RelayId(1), generation, &first));
    assert!(delivery.is_ready(RelayId(1), generation, &second));

    let changed = diff_descriptor(2, &[3]);
    state
        .setup
        .descriptors()
        .record(RelayId(1), changed.clone());
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let frames = decoded(wire.take());
    let [
        CoordinatorToRelay::DescriptorDelta {
            ack_id: Some(delta_id),
            upserts,
            removals,
            ..
        },
    ] = frames.as_slice()
    else {
        panic!("expected one stamped delta, got {frames:?}");
    };
    assert!(*delta_id > initial_id);
    assert_eq!(upserts, std::slice::from_ref(&changed));
    assert!(removals.is_empty());
    assert!(delivery.is_ready(RelayId(1), generation, &first));
    assert!(!delivery.is_ready(RelayId(1), generation, &changed));
    ack(&state, generation, initial_id);
    assert!(!delivery.is_ready(RelayId(1), generation, &changed));
    ack(&state, generation, *delta_id);
    assert!(delivery.is_ready(RelayId(1), generation, &changed));

    let drained = diff_descriptor(2, &[4]);
    state
        .setup
        .descriptors()
        .record(RelayId(1), drained.clone());
    drain.send(DrainSend).unwrap();
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let frames = decoded(wire.take());
    let [
        CoordinatorToRelay::Descriptors {
            ack_id: Some(drain_id),
            descriptors,
            ..
        },
        CoordinatorToRelay::DrainAck,
    ] = frames.as_slice()
    else {
        panic!("expected stamped full set before drain acknowledgement, got {frames:?}");
    };
    assert!(*drain_id > *delta_id);
    assert!(descriptors.contains(&drained));
    assert!(!delivery.is_ready(RelayId(1), generation, &drained));
    ack(&state, generation, *drain_id);
    assert!(delivery.is_ready(RelayId(1), generation, &drained));
    drop(writer);
    drop(sources);
    assert!(!delivery.is_ready(RelayId(1), generation, &first));
    assert!(!delivery.is_ready(RelayId(1), generation, &drained));
}

#[tokio::test]
async fn legacy_writer_never_requests_an_acknowledgement() {
    let Fixture {
        state,
        mut sources,
        drain,
        _grants,
        ..
    } = fixture(false);
    let mut sink = WireSink::default();
    let wire = sink.clone();
    let mut writer = Box::pin(run_writer(
        &mut sink,
        &mut sources,
        RelayId(1),
        Duration::from_secs(5),
        ProtocolVersion::CURRENT,
    ));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let mut frames = wire.take();
    state
        .setup
        .descriptors()
        .record(RelayId(1), diff_descriptor(2, &[3]));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    frames.extend(wire.take());
    drain.send(DrainSend).unwrap();
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    frames.extend(wire.take());
    let mut descriptor_count = 0;
    for frame in frames {
        let Message::Text(text) = frame else { continue };
        let json: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
        if matches!(
            json["type"].as_str(),
            Some("descriptors" | "descriptor_delta")
        ) {
            descriptor_count += 1;
            assert!(json.get("ack_id").is_none(), "legacy wire must omit ack_id");
        }
    }
    assert_eq!(descriptor_count, 3);
}

#[tokio::test]
async fn coalesced_remove_and_readd_send_a_fresh_empty_delta_ack_request() {
    let Fixture {
        state,
        generation,
        mut sources,
        drain: _drain,
        _grants,
    } = fixture(true);
    let descriptor = diff_descriptor(1, &[2]);
    let delivery = state.setup.descriptors().delivery();
    let mut sink = WireSink::default();
    let wire = sink.clone();
    let mut writer = Box::pin(run_writer(
        &mut sink,
        &mut sources,
        RelayId(1),
        Duration::from_secs(5),
        ProtocolVersion::CURRENT,
    ));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let initial_id = full_id(&decoded(wire.take()));
    ack(&state, generation, initial_id);
    state
        .setup
        .descriptors()
        .remove(RelayId(1), &descriptor.tenant, descriptor.session);
    state
        .setup
        .descriptors()
        .record(RelayId(1), descriptor.clone());
    assert!(!delivery.is_ready(RelayId(1), generation, &descriptor));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let frames = decoded(wire.take());
    let [
        CoordinatorToRelay::DescriptorDelta {
            ack_id: Some(id),
            upserts,
            removals,
            ..
        },
    ] = frames.as_slice()
    else {
        panic!("expected one empty stamped delta, got {frames:?}");
    };
    assert!(upserts.is_empty() && removals.is_empty());
    assert!(*id > initial_id);
    ack(&state, generation, *id);
    assert!(delivery.is_ready(RelayId(1), generation, &descriptor));
}

#[tokio::test]
async fn a_failed_send_drops_connection_proofs_with_the_writer_sources() {
    let Fixture {
        state,
        generation,
        mut sources,
        drain: _drain,
        _grants,
    } = fixture(true);
    let descriptor = diff_descriptor(1, &[2]);
    let delivery = state.setup.descriptors().delivery();
    let mut sink = WireSink::default();
    let wire = sink.clone();
    let mut writer = Box::pin(run_writer(
        &mut sink,
        &mut sources,
        RelayId(1),
        Duration::from_secs(5),
        ProtocolVersion::CURRENT,
    ));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    ack(&state, generation, full_id(&decoded(wire.take())));
    assert!(delivery.is_ready(RelayId(1), generation, &descriptor));
    wire.fail.store(true, Ordering::Relaxed);
    state
        .setup
        .descriptors()
        .record(RelayId(1), diff_descriptor(2, &[3]));
    assert!(futures_util::poll!(writer.as_mut()).is_ready());
    drop(writer);
    drop(sources);
    assert!(!delivery.is_ready(RelayId(1), generation, &descriptor));
    ack(&state, generation, 1);
    assert!(!delivery.is_ready(RelayId(1), generation, &descriptor));
}

#[tokio::test]
async fn evidence_receipts_yield_to_descriptors_grants_and_load_state_and_closed_queue_is_idle() {
    let Fixture {
        state,
        mut sources,
        drain: _drain,
        _grants: grants,
        ..
    } = fixture(true);
    let (receipts, receipt_rx) = tokio::sync::mpsc::channel(64);
    sources = sources.with_evidence_receipts(receipt_rx);
    let mut sink = WireSink::default();
    let wire = sink.clone();
    let mut writer = Box::pin(run_writer(
        &mut sink,
        &mut sources,
        RelayId(1),
        Duration::from_secs(5),
        ProtocolVersion::CURRENT,
    ));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    wire.take();

    let receipt = rally_point_proto::control::EvidenceReceipt {
        failures: 1,
        disposition: rally_point_proto::control::EvidenceReceiptDisposition::Accepted,
        tenant: tenant_id(),
        session: SessionId(1),
        slot: SlotId(0),
        assignment_revision: 2,
        connection_id: [9; 32],
        sample_id: 3,
        sequence: 5,
    };
    receipts.send(receipt.clone()).await.unwrap();
    state
        .setup
        .descriptors()
        .record(RelayId(1), diff_descriptor(1, &[3]));
    grants
        .send(CoordinatorToRelay::FlightUploadRefused { request: 11 })
        .unwrap();
    let pending = state
        .setup
        .attest()
        .request(RelayId(1), &tenant_id(), SessionId(1), false)
        .unwrap();
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    let frames = decoded(wire.take());
    assert!(
        matches!(frames.as_slice(), [
        CoordinatorToRelay::DescriptorDelta { .. },
        CoordinatorToRelay::FlightUploadRefused { request: 11 },
        CoordinatorToRelay::LoadStateRequest { .. },
        CoordinatorToRelay::EvidenceReceipt(actual),
    ] if actual == &receipt),
        "unexpected delivery order: {frames:?}"
    );
    drop(pending);

    drop(receipts);
    struct WakeCounter(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let wakes = Arc::new(WakeCounter(std::sync::atomic::AtomicUsize::new(0)));
    let waker = std::task::Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);
    assert!(std::future::Future::poll(writer.as_mut(), &mut context).is_pending());
    assert!(std::future::Future::poll(writer.as_mut(), &mut context).is_pending());
    assert_eq!(
        wakes.0.load(Ordering::Relaxed),
        0,
        "a closed receipt queue must not repeatedly reschedule the writer"
    );
    assert!(
        wire.take().is_empty(),
        "closing only the receipt queue leaves the connection idle"
    );
    state
        .setup
        .descriptors()
        .record(RelayId(1), diff_descriptor(1, &[4]));
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    assert!(matches!(
        decoded(wire.take()).as_slice(),
        [CoordinatorToRelay::DescriptorDelta { .. }]
    ));
}
