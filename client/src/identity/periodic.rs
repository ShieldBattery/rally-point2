//! Connection-owned evidence work, isolated from turn routing and game channels.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rally_point_proto::handshake::{self, EvidenceRequest, PERIODIC_CHALLENGE_LEN};
use rally_point_transport::noq;
use tokio::time::{Instant, timeout_at};

use super::evidence::Provider;

const MIN_INTERVAL: Duration = Duration::from_secs(30);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Budget(Mutex<Instant>);

impl Budget {
    pub(super) fn new() -> Self {
        Self(Mutex::new(Instant::now() + MIN_INTERVAL))
    }

    fn reserve(&self, now: Instant) -> bool {
        let Ok(mut next) = self.0.lock() else {
            return false;
        };
        if now < *next {
            return false;
        }
        *next = now + MIN_INTERVAL;
        true
    }
}

pub(super) fn start(
    connection: noq::Connection,
    mut send: noq::SendStream,
    mut recv: noq::RecvStream,
    request: EvidenceRequest,
    provider: Option<Arc<Provider>>,
    budget: Arc<Budget>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            _ = connection.closed() => {},
            _ = serve(&mut send, &mut recv, request, provider, budget) => {},
        }
        // Evidence failure cannot close the gameplay connection. Stop only the
        // auxiliary stream; malformed or excessive input never starts another task.
        let _ = recv.stop(noq::VarInt::from_u32(0));
        let _ = send.reset(noq::VarInt::from_u32(0));
    })
}

async fn serve(
    send: &mut noq::SendStream,
    recv: &mut noq::RecvStream,
    mut request: EvidenceRequest,
    provider: Option<Arc<Provider>>,
    budget: Arc<Budget>,
) {
    let mut last_id = 0;
    loop {
        let mut bytes = [0; PERIODIC_CHALLENGE_LEN];
        // Idle is normal. Once a frame starts, neither a partial challenge nor
        // a blocked response writer may keep an exchange alive without a bound.
        if recv.read_exact(&mut bytes[..1]).await.is_err() {
            return;
        }
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        let exchange = async {
            recv.read_exact(&mut bytes[1..]).await.ok()?;
            let context = handshake::decode_periodic_challenge(&bytes).ok()?;
            if context.challenge_id <= last_id || !budget.reserve(Instant::now()) {
                return None;
            }
            last_id = context.challenge_id;
            request.periodic = Some(context);
            let evidence = match &provider {
                Some(provider) => provider.collect(request.clone()).await,
                None => None,
            };
            let response =
                handshake::encode_periodic_response(context.challenge_id, evidence.as_ref())
                    .ok()?;
            send.write_all(&response).await.ok()?;
            Some(())
        };
        if !matches!(timeout_at(deadline, exchange).await, Ok(Some(()))) {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
