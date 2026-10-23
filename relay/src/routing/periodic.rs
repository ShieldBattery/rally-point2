//! A bounded observation exchange isolated from the gameplay link's serve loop.

use super::*;
use rally_point_proto::control::EvidenceObservation;
use rally_point_proto::handshake::{self, EvidenceCheck, EvidenceRequest, PeriodicEvidenceContext};
use rally_point_transport::noq::{RecvStream, SendStream};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;

static EXCHANGES: Semaphore = Semaphore::const_new(32);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct EvidenceStream {
    pub send: SendStream,
    pub recv: RecvStream,
    pub request: EvidenceRequest,
}

pub(super) struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Context {
    key: SessionKey,
    slot: SlotId,
    epoch: u64,
    revision: u64,
    connection_id: [u8; 32],
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
}

impl Context {
    fn current(&self) -> Option<(crate::consensus::EvidenceConfig, bool)> {
        self.mesh
            .session
            .gates
            .with_ingress(&self.key, || {
                let roster = self.sessions.lock();
                if roster.get(&self.key)?.get(&self.slot)?.connection_epoch != self.epoch {
                    return None;
                }
                self.mesh.session.decision_makers.periodic_evidence_config(
                    &self.key,
                    self.slot,
                    self.epoch,
                    &self.connection_id,
                    self.revision,
                )
            })
            .flatten()
    }

    async fn invalidated(&self) {
        loop {
            let changed = self.mesh.session.decision_makers.descriptor_changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.current().is_none() {
                return;
            }
            changed.await;
        }
    }

    async fn delay(&self, duration: Duration) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(duration) => self.current().is_some(),
            _ = self.invalidated() => false,
        }
    }

    fn record(&self, sample_id: u64, checked: crate::auth::CheckedEvidence) -> bool {
        self.mesh
            .session
            .gates
            .with_ingress(&self.key, || {
                let roster = self.sessions.lock();
                if !roster
                    .get(&self.key)
                    .and_then(|slots| slots.get(&self.slot))
                    .is_some_and(|entry| entry.connection_epoch == self.epoch)
                {
                    return false;
                }
                self.mesh.session.decision_makers.record_periodic_evidence(
                    &self.key,
                    self.slot,
                    self.epoch,
                    EvidenceObservation {
                        sample_id,
                        connection_id: self.connection_id,
                        assignment_revision: self.revision,
                        sequence: 0,
                        verdict: checked.verdict,
                        key_id: checked.key_id,
                        body: checked.body,
                    },
                )
            })
            .unwrap_or(false)
    }
}

pub(super) fn spawn(
    stream: EvidenceStream,
    key: SessionKey,
    slot: SlotId,
    epoch: u64,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
) -> Task {
    Task(tokio::spawn(async move {
        let Some(config) = mesh.session.decision_makers.evidence_config(&key) else {
            return;
        };
        let Some(&revision) = config.assignments.get(&slot) else {
            return;
        };
        let context = Context {
            key,
            slot,
            epoch,
            revision,
            connection_id: stream.request.challenge,
            sessions,
            mesh,
        };
        run(context, stream).await;
    }))
}

fn jitter(first: bool) -> Option<Duration> {
    let mut bytes = [0; 8];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(Duration::from_millis(
        if first { 30_000 } else { 60_000 } + u64::from_le_bytes(bytes) % 30_001,
    ))
}

async fn run(context: Context, stream: EvidenceStream) {
    run_with(context, stream.send, stream.recv, stream.request).await;
}

async fn run_with(
    context: Context,
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    request: EvidenceRequest,
) {
    loop {
        let Some((_, started)) = context.current() else {
            return;
        };
        if started {
            break;
        }
        if !context.delay(Duration::from_secs(1)).await {
            return;
        }
    }
    let mut first = true;
    let mut sample_id = 1u64;
    loop {
        let Some(delay) = jitter(first) else {
            return;
        };
        if !context.delay(delay).await {
            return;
        }
        first = false;
        let Ok(_permit) = EXCHANGES.try_acquire() else {
            continue;
        };
        let Some((config, _)) = context.current() else {
            return;
        };
        let mut nonce = [0; 32];
        if SystemRandom::new().fill(&mut nonce).is_err() {
            return;
        }
        let challenge = PeriodicEvidenceContext {
            challenge_id: sample_id,
            nonce,
            assignment_revision: context.revision,
            check: EvidenceCheck::FullImage,
        };
        let response = tokio::select! {
            _ = context.invalidated() => return,
            response = tokio::time::timeout(EXCHANGE_TIMEOUT, exchange(&mut send, &mut recv, &challenge)) => response.ok().flatten(),
        };
        let request = EvidenceRequest {
            periodic: Some(challenge),
            ..request.clone()
        };
        let ended = response.is_none();
        let checked = crate::auth::verify_evidence(&request, response.flatten(), &config);
        if !context.record(sample_id, checked) {
            return;
        }
        // A partial or timed-out frame cannot be safely resumed on this stream.
        if ended {
            return;
        }
        let Some(next) = sample_id.checked_add(1) else {
            return;
        };
        sample_id = next;
    }
}

async fn exchange(
    send: &mut (impl AsyncWrite + Unpin),
    recv: &mut (impl AsyncRead + Unpin),
    challenge: &PeriodicEvidenceContext,
) -> Option<Option<handshake::Evidence>> {
    send.write_all(&handshake::encode_periodic_challenge(challenge).ok()?)
        .await
        .ok()?;
    let mut header = [0; handshake::PERIODIC_RESPONSE_HEADER_LEN];
    recv.read_exact(&mut header).await.ok()?;
    let (id, len) = handshake::decode_periodic_response_header(&header).ok()?;
    if id != challenge.challenge_id {
        return None;
    }
    let mut payload = vec![0; len];
    recv.read_exact(&mut payload).await.ok()?;
    let (_, evidence) = handshake::decode_periodic_response(&header, &payload).ok()?;
    Some(evidence)
}

#[cfg(test)]
mod tests;
