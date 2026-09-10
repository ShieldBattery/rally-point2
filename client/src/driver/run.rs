//! The two entry points a caller spawns, and the per-connection session they
//! share: run one connection until it ends, or keep the game seam alive across
//! a drop by re-dialing the home relay from inside the driver.

use rally_point_transport::Link;

use super::backoff::{Backoff, push_to_game};
use super::reconnect::{
    ReconnectDriver, ReconnectTarget, Reconnected, is_link_failure, reconnect_link,
};
use super::state::{ESCALATE_AFTER, ESCALATE_RETRY, GameSeam, LoopState};
use super::*;

impl LinkDriver {
    /// Runs the link over one connection until the game seam closes (a clean stop →
    /// `Ok`) or the link fails (→ [`DriverError`]). No reconnection: a link failure
    /// ends the driver and drops every channel, leaving the caller to re-dial and
    /// rebuild. Use [`run_reconnecting`](Self::run_reconnecting) to have the driver
    /// re-dial itself and keep the channels alive across a drop.
    pub async fn run(self) -> Result<(), DriverError> {
        let LinkDriver {
            mut link,
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            result_expected,
            game_started,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            skin_out,
            skin_in,
            request_drop,
            session_start,
            connectivity,
            region_labels,
            phase_status,
        } = self;
        let mut seam = GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            game_started,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            skin_out,
            skin_in,
            request_drop,
            session_start,
            connectivity,
            region_labels,
            phase_status,
        };
        let mut state = LoopState::new(result_expected);
        // The no-reconnect entry has no token to read a slot from, and it never
        // re-dials (so no resume anchor is ever computed from the unacked window).
        // It stamps slot 0 — the value the embedder already sends and the relay
        // rewrites to the authorized slot on ingress — preserving prior behavior.
        let result = Self::session(&mut link, &mut seam, &mut state, SlotId(0)).await;
        // Every exit ends this driver, so close the connection on the error
        // exits too (`session` already closed it on `Ok`): the relay's
        // slot-liveness signal is the connection, not this driver's local
        // state, so an unclosed handle would hold the relay-side slot until
        // QUIC's own idle timeout. Done here, not inside `session`, so the
        // error's classification always reads the connection state the failure
        // actually left behind.
        if result.is_err() {
            link.connection().close(0u32.into(), b"driver ended");
        }
        result
    }

    /// Runs the link and, on a mid-session link failure, re-dials the home relay
    /// *itself* — keeping every game channel alive — instead of ending.
    ///
    /// Across a drop the driver: emits its own slot's connectivity as `false` then
    /// `true` on [`connectivity`](TurnChannels::connectivity) (so the game learns of
    /// its own disconnect/reconnect from an explicit signal, not from the channels
    /// closing); re-dials with capped exponential backoff, presenting per-slot
    /// resume cursors so the relay replays the turns missed during the outage; and
    /// rebinds the link in place, so the receive-side dedup and per-slot reorder
    /// buffers survive and the replay dedups against turns already delivered. Turns
    /// the game produces during the outage are buffered and flushed in order once
    /// the link is back; turns already sent but unacked at the drop re-carry
    /// themselves over the new connection.
    ///
    /// The loop ends — dropping the channels, which the game reads as end-of-session
    /// — on a clean game shutdown (→ `Ok`), a terminal relay refusal
    /// ([`DriverError::SlotDeparted`]), an expired token
    /// ([`DriverError::TokenExpired`]), or a non-link failure the loop can't fix (a
    /// stalled game, an exhausted unacked window).
    pub async fn run_reconnecting(self, reconnect: Reconnect) -> Result<(), DriverError> {
        let Reconnect {
            endpoint,
            relay_addr,
            server_name,
            relay_id,
            identity,
            rehome,
            escalate_after,
            escalate_retry,
        } = reconnect;
        // The driver knows its own slot from its token; it labels the
        // self-connectivity signal with it.
        let own_slot = identity.token().claims.slot;
        // The reconnect machinery, its target mutable so a successful re-home moves
        // where subsequent drops reconnect to.
        let mut rc = ReconnectDriver {
            target: ReconnectTarget {
                endpoint,
                relay_addr,
                server_name,
                relay_id,
            },
            identity,
            rehome,
            escalate_after: escalate_after.unwrap_or(ESCALATE_AFTER),
            escalate_retry: escalate_retry.unwrap_or(ESCALATE_RETRY),
        };
        let LinkDriver {
            mut link,
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            result_expected,
            game_started,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            skin_out,
            skin_in,
            request_drop,
            session_start,
            connectivity,
            region_labels,
            phase_status,
        } = self;
        let mut seam = GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            game_started,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            skin_out,
            skin_in,
            request_drop,
            session_start,
            connectivity,
            region_labels,
            phase_status,
        };
        let mut state = LoopState::new(result_expected);
        let mut backoff = Backoff::new();

        loop {
            match Self::session(&mut link, &mut seam, &mut state, own_slot).await {
                // A clean game shutdown, or a link close absorbed after our own
                // leave intent went out: the session is over, not to be resumed.
                Ok(()) => return Ok(()),
                // A link/stream failure: keep the channels alive and re-dial.
                Err(error) if is_link_failure(&error) => {
                    // With the game seam already closed, re-dialing is
                    // pointless — the reconnect machinery would only bounce
                    // off the dead seam as GameGone, laundering the session's
                    // own error (say, a teardown whose clean leave never
                    // reached the relay) into a clean stop. The error keeps
                    // its classification instead.
                    // Either half counts: the seam contract stops the driver
                    // on whichever side the game drops first, so teardown may
                    // have been entered from a dropped outbound sender with
                    // the inbound receiver still held.
                    if seam.inbound.is_closed() || seam.outbound.is_closed() {
                        link.connection().close(0u32.into(), b"driver ended");
                        return Err(error);
                    }
                    // Close the failed connection now that it is classified.
                    // After a control-stream-only death the connection is still
                    // alive, and the relay's slot-liveness signal is the
                    // connection — an unclosed one holds the roster seat, so
                    // the immediate re-dial below would bounce off SLOT_TAKEN
                    // until QUIC's idle timeout. Closed here, never inside
                    // `session`, so classification (and the distinction between
                    // a dead control stream and a dead connection it rests on)
                    // always reads the state the failure actually left behind.
                    // A no-op when the connection itself is what died.
                    link.connection()
                        .close(0u32.into(), b"re-dialing after link failure");
                    // Best-effort like every connectivity delivery: a game not
                    // draining its display changes must not park the reconnect
                    // loop before it even starts re-dialing.
                    let _ = push_to_game(&seam.connectivity, (own_slot, false));
                    match reconnect_link(&mut rc, &mut link, &mut seam, &mut state, &mut backoff)
                        .await
                    {
                        Reconnected::Resumed => {
                            let _ = push_to_game(&seam.connectivity, (own_slot, true));
                            // Loop: run the next session over the rebound link.
                        }
                        Reconnected::Terminal(error) => return Err(error),
                        Reconnected::GameGone => return Ok(()),
                    }
                }
                // A non-link failure (stalled game, exhausted window) or a terminal
                // relay refusal surfaced from within the session: reconnecting can't
                // help, so end — closing the connection, which may be perfectly
                // healthy, so the relay frees this slot promptly instead of
                // serving a driver that has given up until its idle timeout.
                Err(error) => {
                    link.connection().close(0u32.into(), b"driver ended");
                    return Err(error);
                }
            }
        }
    }

    /// Runs one connection's worth of the turn loop, over the already-established
    /// [`link`](Link) and the game [`seam`](GameSeam), threading the state that must
    /// survive a reconnect ([`LoopState`]). Returns a clean stop as `Ok`, and a link
    /// or terminal failure as [`DriverError`] for the caller to re-dial through or
    /// end on.
    ///
    /// Multiplexes over one task: receiving the client's peers' turns and handing
    /// them to the game, sending the turns the game produced, flushing ack-only
    /// packets during outbound silence, driving the ack-beacon side-channel that
    /// keeps the unacked window bounded under loss, sending the game's end-of-game
    /// result report the moment it arrives, and — once the game signals its own
    /// departure — announcing that leave to the relay after the outbound queue and
    /// unacked window have drained (and the result, if one was expected, has been
    /// sent).
    ///
    /// The beacon is two uni-streams — one each direction — and its read half runs
    /// in a dedicated task so a partial stream read is never dropped mid-frame
    /// inside a `select!` branch (which would desync the framing and hand a
    /// garbage `(slot, cursor)` to `retire_through`); the task forwards each
    /// complete `(slot, cursor)` over an mpsc channel, whose `recv` *is*
    /// cancel-safe.
    pub(super) async fn session(
        link: &mut Link,
        seam: &mut GameSeam,
        state: &mut LoopState,
        own_slot: SlotId,
    ) -> Result<(), DriverError> {
        let result = Self::session_body(link, seam, state, own_slot).await;
        // A clean stop closes the connection here: the detached beacon and
        // control-stream reader tasks each hold their own `connection.clone()`,
        // parked on `accept_uni`/`accept_bi`, so `link`'s own handle going out
        // of scope alone is never the last one -- without this, a clean exit
        // leaves the connection (and the relay-side slot it holds) open until
        // QUIC's own idle timeout. Closing here wakes those readers, freeing
        // them and the slot promptly.
        //
        // Deliberately NOT done on an `Err` exit: closing the connection out
        // from under the caller here would blur the "control stream died,
        // connection didn't" distinction the reconnect classification
        // (`is_link_failure`) and its own tests rely on. The callers own the
        // error-path close instead -- `run`/`run_reconnecting` close the
        // connection once the error is classified, so the relay-side slot is
        // freed promptly there too.
        if result.is_ok() {
            link.connection().close(0u32.into(), b"session ended");
        }
        result
    }
}
