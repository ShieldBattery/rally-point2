//! Delivery-mechanics tests for `dispatch`/`send_attempt`: the whole-attempt
//! timeout (headers and body both), the response-body cap, and the
//! process-wide concurrency gate. These exercise the transport layer
//! directly rather than going through a notice handler.

use super::*;

// -- Attempt timeout --

#[tokio::test]
async fn a_hung_endpoint_times_out_the_attempt_instead_of_hanging_forever() {
    // A listener that accepts the TCP connection but never sends a response
    // headers back — the pathological case the attempt timeout exists to
    // bound. Accepted sockets are stashed in a `Vec` owned by the spawned
    // task rather than dropped, so the connection stays open (no FIN/RST)
    // without the handler ever completing a response.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{addr}/hook"))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let started = Instant::now();
    let outcome = send_attempt(request, Duration::from_millis(300)).await;
    assert!(
        matches!(outcome, Err(AttemptError::TimedOut)),
        "a hung endpoint must time out the attempt, not hang forever",
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the attempt was bounded by its own timeout, not left to hang",
    );
}

#[tokio::test]
async fn a_body_that_never_finishes_times_out_the_whole_attempt_not_just_the_headers() {
    // Response headers arrive promptly (a 200 whose `Content-Length`
    // promises far more body than ever actually arrives), then the
    // connection goes silent. A headers-only timeout would see
    // `Ok(response)` from the initial `request()` call and move on to an
    // unbounded body read; the whole-attempt timeout must catch this
    // instead, exactly like the hung-endpoint case above but with the
    // hang moved past the headers.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
                .await;
            held.push(stream); // the promised body never actually arrives
        }
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{addr}/hook"))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let started = Instant::now();
    let outcome = send_attempt(request, Duration::from_millis(300)).await;
    assert!(
        matches!(outcome, Err(AttemptError::TimedOut)),
        "a body that never finishes must time out the whole attempt, not just the headers",
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the attempt was bounded, not left to hang on the body",
    );
}

// -- Response body cap --

#[tokio::test]
async fn a_response_body_past_the_cap_counts_as_a_failed_attempt() {
    let app = Router::new().route(
        "/hook",
        post(|| async { vec![0u8; MAX_RESPONSE_BODY_BYTES + 4096] }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{addr}/hook"))
        .body(Full::new(Bytes::new()))
        .unwrap();

    // A generous timeout so only the body cap, not the attempt timeout,
    // can be what trips here.
    let outcome = send_attempt(request, Duration::from_secs(5)).await;
    assert!(
        matches!(outcome, Err(AttemptError::BodyTooLarge)),
        "a response body past the cap must fail the attempt, not buffer to completion; got {outcome:?}",
    );
}

#[tokio::test]
async fn a_response_body_at_or_under_the_cap_still_delivers() {
    let app = Router::new().route(
        "/hook",
        post(|| async { vec![0u8; MAX_RESPONSE_BODY_BYTES] }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{addr}/hook"))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let outcome = send_attempt(request, Duration::from_secs(5)).await;
    assert_eq!(
        outcome.ok(),
        Some(200),
        "a body exactly at the cap is not itself over it",
    );
}

// -- Dispatch concurrency --

#[tokio::test]
async fn the_dispatch_semaphore_bounds_concurrent_in_flight_attempts() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Tracks how many requests are simultaneously inside the handler
    // (i.e. actually in flight, not just queued), and the high-water mark
    // across the whole test -- the number the semaphore is responsible
    // for capping.
    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let (current_h, max_h) = (Arc::clone(&current), Arc::clone(&max_seen));
    let app = Router::new().route(
        "/hook",
        post(move || {
            let current = Arc::clone(&current_h);
            let max_seen = Arc::clone(&max_h);
            async move {
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                // Held open long enough that every spawned dispatch below
                // has a chance to reach the endpoint (or block on the
                // semaphore) before the first ones finish.
                tokio::time::sleep(Duration::from_millis(200)).await;
                current.fetch_sub(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("k1".to_owned()),
        TenantId("t".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();

    let url = format!("http://{addr}/hook");
    // Comfortably past MAX_CONCURRENT_DISPATCHES so the cap, if it were
    // absent, would be visibly exceeded (every request succeeds on its
    // first attempt, so nothing here depends on retry timing).
    let overshoot = MAX_CONCURRENT_DISPATCHES + 16;
    let mut handles = Vec::with_capacity(overshoot);
    for _ in 0..overshoot {
        let tenants = tenants.clone();
        let config = NotifyConfig { url: url.clone() };
        handles.push(tokio::spawn(dispatch(
            tenants,
            TenantId("t".to_owned()),
            config,
            Bytes::from_static(b"{}"),
            "test",
        )));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    let max_seen = max_seen.load(Ordering::SeqCst);
    assert!(
        max_seen <= MAX_CONCURRENT_DISPATCHES,
        "the semaphore must cap concurrent in-flight dispatches at \
         {MAX_CONCURRENT_DISPATCHES}, but {max_seen} were observed at once",
    );
}
