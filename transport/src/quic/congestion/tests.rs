use std::time::{Duration, Instant};

use super::*;

const MTU: u16 = 1200;

fn floored(cubic: CubicConfig, now: Instant) -> FlooredCubic {
    FlooredCubic {
        inner: Arc::new(cubic).build(now, MTU),
    }
}

/// A congestion event a round trip after the last one, so Cubic counts it as a new one rather
/// than part of the recovery already under way.
fn lose_a_packet(controller: &mut FlooredCubic, now: Instant, persistent: bool) {
    controller.on_congestion_event(now, now, persistent, false, u64::from(MTU), 0);
}

#[test]
fn repeated_loss_never_takes_the_window_below_the_floor() {
    let start = Instant::now();
    let mut controller = floored(CubicConfig::default(), start);
    for i in 1..=20 {
        lose_a_packet(
            &mut controller,
            start + Duration::from_millis(100 * i),
            false,
        );
    }
    lose_a_packet(&mut controller, start + Duration::from_secs(5), true);

    assert_eq!(
        controller.inner.window(),
        2 * u64::from(MTU),
        "Cubic alone collapses to two packets"
    );
    assert_eq!(controller.window(), MIN_CONGESTION_WINDOW);
    assert_eq!(
        controller.metrics().congestion_window,
        MIN_CONGESTION_WINDOW,
        "the pacer reads the floored window too",
    );
    assert_eq!(
        controller.clone_box().window(),
        MIN_CONGESTION_WINDOW,
        "a copy keeps the floor"
    );
}

#[test]
fn above_the_floor_cubic_governs_alone() {
    let start = Instant::now();
    let mut cubic = CubicConfig::default();
    cubic.initial_window(4 * MIN_CONGESTION_WINDOW);
    let mut controller = floored(cubic, start);
    assert_eq!(controller.initial_window(), 4 * MIN_CONGESTION_WINDOW);
    assert_eq!(controller.window(), 4 * MIN_CONGESTION_WINDOW);

    lose_a_packet(&mut controller, start + Duration::from_millis(100), false);
    let backed_off = controller.inner.window();
    assert!(backed_off < 4 * MIN_CONGESTION_WINDOW && backed_off > MIN_CONGESTION_WINDOW);
    assert_eq!(controller.window(), backed_off);
}
