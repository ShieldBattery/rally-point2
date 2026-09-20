//! Outage rebaselining: which losses are absorbed as a dead path rather than priced as weather.

use super::*;

/// Noq declares an outage's losses only once acks resume -- the gap
/// sample itself usually shows the dead-path sends still undeclared, and
/// the lost counter jumps one or two samples later. Those late
/// declarations belong to the outage: they are absorbed against the
/// gap's undeclared sends and hidden from the restarted windows instead
/// of being priced as post-resume weather, and the interval carrying the
/// jump is no blackout -- its own traffic got through.
///
/// How much the dead path managed to transmit is incidental to all of
/// that. On a genuinely dead path Noq's congestion window collapses and
/// PTO backoff throttles actual transmissions to a handful of packets
/// however hard the maintenance flush queues, so the handful must absorb
/// exactly as a full flush's worth does -- never price as ~100%
/// post-resume weather over the two packets that followed it.
#[test]
fn outage_losses_declared_after_resume_are_absorbed_not_priced() {
    for gap_sends in [40u64, 10] {
        let (mut maker, start, step) = flowing_link_at_150ms();

        // 5s fade, `gap_sends` dead-path sends, none declared lost yet at
        // resume.
        let resume = start + Duration::from_secs(5);
        assert_eq!(
            sample_at(&mut maker, 0, 0, 100 + gap_sends, resume),
            CounterUpdate::OutageRebaselined,
            "{gap_sends} dead-path sends",
        );
        // The next flowing sample delivers 2 sends -- and the late
        // declarations land at once.
        assert_eq!(
            sample_at(&mut maker, 0, gap_sends, 102 + gap_sends, resume + step),
            CounterUpdate::Advanced,
            "{gap_sends} dead-path sends",
        );
        let state = &maker.slots[&SlotId(0)];
        assert_eq!(
            state.blackout_run, 0,
            "the jump is outage residue, not a fresh blackout ({gap_sends} dead-path sends)",
        );

        // Flow on: the windows read the actual weather, not the residue.
        for i in 2..=12u32 {
            sample_at(
                &mut maker,
                0,
                gap_sends,
                102 + gap_sends + u64::from(i - 1) * 5,
                resume + step * i,
            );
        }
        assert_eq!(
            slot_loss_rate(&maker, 0),
            Some(0.0),
            "{gap_sends} dead-path sends",
        );
        assert_eq!(
            maker.target_inputs().unwrap().burst_turns,
            0,
            "absorption leaves no synthetic burst trace ({gap_sends} dead-path sends)",
        );
    }
}

/// The absorption pool covers only the brief post-resume window in which
/// noq resolves the outage's losses. Loss past that horizon is priced
/// as the weather it is, leftover pool or not.
#[test]
fn the_outage_absorption_pool_expires() {
    let (mut maker, start, step) = flowing_link_at_150ms();

    // 40 dead-path sends, none declared: pool of 40 banked at the gap.
    let resume = start + Duration::from_secs(5);
    sample_at(&mut maker, 0, 0, 140, resume);
    // A clean resolution horizon passes with no declarations.
    for i in 1..=OUTAGE_LOSS_RESOLUTION_SAMPLES {
        sample_at(&mut maker, 0, 0, 140 + u64::from(i) * 5, resume + step * i);
    }
    // A genuine loss burst after the horizon: nothing absorbs it.
    let sent = 140 + u64::from(OUTAGE_LOSS_RESOLUTION_SAMPLES) * 5;
    sample_at(
        &mut maker,
        0,
        10,
        sent + 10,
        resume + step * (OUTAGE_LOSS_RESOLUTION_SAMPLES + 1),
    );
    let state = &maker.slots[&SlotId(0)];
    assert_eq!(
        state.blackout_run, 1,
        "an all-lost interval, priced normally"
    );
    assert!(slot_loss_rate(&maker, 0).unwrap() > 0.0);
}

/// Gaps shorter than the outage threshold are ordinary sampling cadence:
/// an all-lost interval across one still builds the blackout run and
/// prices into the rate windows exactly as before. The threshold itself
/// is inclusive, so a gap of exactly that length is already an outage --
/// the boundary a strict comparison would put one sample on the wrong
/// side of.
#[test]
fn a_sub_second_gap_still_prices_as_weather() {
    let (mut maker, start, _step) = flowing_link_at_150ms();

    let update = sample_at(&mut maker, 0, 10, 110, start + Duration::from_millis(500));
    assert_eq!(update, CounterUpdate::Advanced);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!(state.blackout_run, 1);
    assert_eq!(slot_loss_rate(&maker, 0), Some(1.0));

    let (mut at_threshold, start, _step) = flowing_link_at_150ms();
    assert_eq!(
        sample_at(&mut at_threshold, 0, 10, 110, start + OUTAGE_GAP_MIN),
        CounterUpdate::OutageRebaselined,
        "a gap of exactly the threshold is an outage",
    );
}

/// A mesh sidecar re-carries a cached snapshot of every co-homed slot's
/// conditions on any sibling's traffic, so a faded slot's stale counters
/// keep arriving at the authority for as long as its siblings keep
/// sending. Those bit-identical duplicates must not advance the
/// receive-gap clock: if they did, the authority would measure no gap at
/// the recovery jump and difference the dead-path interval into the
/// windows as weather -- the original buffer spike, recreated on every
/// relay that is not the slot's home.
#[test]
fn cached_sidecar_duplicates_do_not_defeat_gap_detection() {
    let (mut maker, start, _step) = flowing_link_at_150ms();

    // The slot fades; its siblings' traffic keeps re-delivering the
    // cached (sent=100, lost=0) snapshot every quarter second, the last
    // one only 250ms before recovery -- so an arrival-keyed clock would
    // measure no stall-length gap at all here.
    for i in 1..=19u32 {
        let update = sample_at(
            &mut maker,
            0,
            0,
            100,
            start + Duration::from_millis(250) * i,
        );
        assert_eq!(update, CounterUpdate::NonAdvancing);
    }

    // Recovery: 40 dead-path sends declared at once, five seconds after
    // the last counter *movement*. The duplicates must not have closed
    // that gap.
    let update = sample_at(&mut maker, 0, 40, 140, start + Duration::from_secs(5));
    assert_eq!(update, CounterUpdate::OutageRebaselined);
    assert_eq!(
        slot_loss_rate(&maker, 0),
        None,
        "windows restarted, not poisoned",
    );
}

/// Wi-Fi fades recur, and a second fade can begin before the first
/// fade's losses were ever declared (acks never resumed in between).
/// The first fade's declarations then land inside the *second* gap's
/// interval -- they must consume the prior pool, not cancel the new
/// gap's banking. Overwriting the pool with `delta_sent - delta_lost`
/// would zero it here and price the second fade's own late declarations
/// as ~100% post-resume weather.
#[test]
fn a_recurrent_fade_keeps_absorbing_across_overlapping_outages() {
    let (mut maker, start, step) = flowing_link_at_150ms();

    // Fade 1 resumes: 40 dead-path sends, none declared yet.
    let resume1 = start + Duration::from_secs(5);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 140, resume1),
        CounterUpdate::OutageRebaselined,
    );

    // Fade 2 begins before fade 1's losses resolve and resumes 5s
    // later: its own 40 dead-path sends are still undeclared, while
    // fade 1's 40 declarations land inside this gap's interval.
    let resume2 = resume1 + Duration::from_secs(5);
    assert_eq!(
        sample_at(&mut maker, 0, 40, 180, resume2),
        CounterUpdate::OutageRebaselined,
    );

    // Fade 2's late declarations land on the next flowing sample --
    // absorbed against the carried-forward pool, not priced as weather.
    assert_eq!(
        sample_at(&mut maker, 0, 80, 182, resume2 + step),
        CounterUpdate::Advanced,
    );
    let state = &maker.slots[&SlotId(0)];
    assert_eq!(
        state.blackout_run, 0,
        "the jump is outage residue, not a fresh blackout",
    );

    for i in 2..=12u32 {
        sample_at(
            &mut maker,
            0,
            80,
            182 + u64::from(i - 1) * 5,
            resume2 + step * i,
        );
    }
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.0));
    assert_eq!(maker.target_inputs().unwrap().burst_turns, 0);
}

/// Pool banking is unconditional but *self-limiting*: an idle gap banks
/// only its own delivered handful of sends, so the most it can ever mask
/// is that handful, briefly -- genuine post-resume loss beyond it prices
/// as the weather it is, and the delivered keepalives never materialize
/// as evidence, so the episode earns no burst credit either.
///
/// That second half is why an excluded gap deliberately leaves no burst
/// trace. Absorption is fungible bookkeeping, not provenance: a
/// cumulative counter cannot say which packets a declaration belongs to,
/// so banked idle credit will happily soak up genuine weather losses.
/// Were absorbed declarations treated as dead-path evidence instead, two
/// idle gaps' delivered keepalives plus a handful of genuine weather
/// losses would "materialize" as an outage and charge a perfectly
/// healthy link the capped credit.
#[test]
fn an_idle_gap_masks_at_most_its_own_sends() {
    let (mut maker, start, step) = flowing_link_at_150ms();

    // A 10s stall bridged by two delivered keepalive pings...
    let resume = start + Duration::from_secs(10);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 102, resume),
        CounterUpdate::OutageRebaselined,
    );
    // ...then a genuine 10-loss post-resume burst: at most the gap's own
    // 2 banked sends absorb; the other 8 price into the windows.
    sample_at(&mut maker, 0, 10, 112, resume + step);
    assert_eq!(
        slot_loss_rate(&maker, 0),
        Some(0.8),
        "8 of the 10 losses price over the 10 packets since the gap",
    );
    assert_eq!(
        maker.target_inputs().unwrap().burst_turns,
        0,
        "absorption is masking only; it never becomes burst credit",
    );

    // Two idle stalls back to back, each bridged by two delivered
    // keepalives, bank two packets of credit apiece; the first flowing
    // interval after them genuinely loses four. Those four drain what
    // idle credit is still unexpired -- the bounded masking cost -- but
    // they are weather, and no burst credit may appear for them.
    let (mut healthy, start, step) = flowing_link_at_150ms();
    assert_eq!(
        sample_at(&mut healthy, 0, 0, 102, start + Duration::from_secs(2)),
        CounterUpdate::OutageRebaselined,
    );
    let resume = start + Duration::from_secs(4);
    assert_eq!(
        sample_at(&mut healthy, 0, 0, 104, resume),
        CounterUpdate::OutageRebaselined,
    );
    sample_at(&mut healthy, 0, 4, 108, resume + step);
    assert_eq!(
        healthy.target_inputs().unwrap().burst_turns,
        0,
        "no manufactured outage credit on a healthy link",
    );
}

/// Banked credit expires on its own gap's clock, and a later gap must
/// never renew it: an idle gap arriving one sample before an old dead
/// pool's deadline banks its own two keepalives with a fresh deadline,
/// but the old forty-packet pool still dies on schedule -- genuine
/// post-idle loss meets at most the idle gap's own tiny credit.
#[test]
fn an_idle_gap_does_not_extend_a_prior_pools_deadline() {
    let (mut maker, start, step) = flowing_link_at_150ms();

    // A dead gap banks 40 undeclared sends (deadline: 24 advancing
    // samples after this gap sample).
    let resume = start + Duration::from_secs(5);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 140, resume),
        CounterUpdate::OutageRebaselined,
    );
    // 23 clean advancing samples bring the pool one sample from expiry,
    // with its declarations never arriving.
    for i in 1..=23u32 {
        sample_at(&mut maker, 0, 0, 140 + u64::from(i) * 5, resume + step * i);
    }

    // An idle gap banks its own two keepalives on a fresh deadline; the
    // old pool's deadline must not move.
    let idle_resume = resume + step * 23 + Duration::from_millis(1500);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 257, idle_resume),
        CounterUpdate::OutageRebaselined,
    );

    // Genuine loss on the next sample: the old pool expired on schedule,
    // so only the idle gap's 2 banked sends absorb -- 8 of the 10 price.
    sample_at(&mut maker, 0, 10, 262, idle_resume + step);
    sample_at(&mut maker, 0, 10, 267, idle_resume + step * 2);
    assert_eq!(
        slot_loss_rate(&maker, 0),
        Some(0.8),
        "8 of 10 losses over the 10 packets since the idle gap",
    );
    assert_eq!(
        maker.target_inputs().unwrap().burst_turns,
        1,
        "the genuine loss's own one-turn run is the only burst trace",
    );
}

/// The sample-count deadline alone would let banked credit overstay on
/// a link whose sent counter advances rarely -- advancing samples can
/// cover far more wall time than the nominal cadence suggests -- so a
/// wall-clock bound expires it too: after two seconds of connected
/// time the leftover credit is gone and genuine loss prices as
/// weather, even with the sample deadline nowhere near.
#[test]
fn banked_credit_expires_on_wall_clock_on_a_slow_advancing_link() {
    let (mut maker, start, _step) = flowing_link_at_150ms();

    // A dead gap banks 40 undeclared sends.
    let resume = start + Duration::from_secs(5);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 140, resume),
        CounterUpdate::OutageRebaselined,
    );

    // The link advances only twice a second (each spacing well under the
    // outage-gap threshold): five advancing samples span 2.5s of
    // connected time while the 24-sample deadline is nowhere near.
    let slow = Duration::from_millis(500);
    for i in 1..=5u32 {
        sample_at(&mut maker, 0, 0, 140 + u64::from(i) * 2, resume + slow * i);
    }

    // Genuine loss at 3s: the credit is wall-expired; nothing absorbs.
    sample_at(&mut maker, 0, 10, 155, resume + slow * 6);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!(
        state.blackout_run, 1,
        "an all-lost weather interval, priced"
    );
    assert!(
        slot_loss_rate(&maker, 0).unwrap() > 0.0,
        "no stale credit absorbs it",
    );
}

/// A later idle gap must not revive wall-expired credit. A receive gap
/// proves only that no fresh payload produced a sample -- ack-only
/// traffic still flows through a healthy stall and resolves pending
/// declarations mid-gap -- so credit that outlived its wall window with
/// nothing to meet at the gap's close is stale, and post-stall genuine
/// loss must meet at most the idle gap's own banked sends.
#[test]
fn an_idle_gap_does_not_revive_expired_credit() {
    let (mut maker, start, step) = flowing_link_at_150ms();

    // A dead gap banks 40 undeclared sends (wall deadline: 2s out)...
    let resume = start + Duration::from_secs(5);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 140, resume),
        CounterUpdate::OutageRebaselined,
    );
    // ...one clean flowing sample follows...
    sample_at(&mut maker, 0, 0, 145, resume + Duration::from_millis(100));

    // ...then a healthy 10s stall closes with two delivered keepalives
    // and no declarations: the old credit found nothing to meet at the
    // close and is dropped, not revived.
    let idle_close = resume + Duration::from_millis(10_100);
    assert_eq!(
        sample_at(&mut maker, 0, 0, 147, idle_close),
        CounterUpdate::OutageRebaselined,
    );

    // Genuine loss right after: only the idle gap's own two banked
    // sends absorb. Revived credit would have swallowed all ten and
    // read a clean window here.
    sample_at(&mut maker, 0, 10, 157, idle_close + step);
    assert_eq!(
        slot_loss_rate(&maker, 0),
        Some(0.8),
        "8 of the 10 losses price; only the idle gap's 2 sends mask",
    );
}
