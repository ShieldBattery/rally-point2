use super::*;

async fn task() -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    struct Finished(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Finished {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    let (finished, receiver) = tokio::sync::oneshot::channel();
    let (started, ready) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _finished = Finished(Some(finished));
        started.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    ready.await.unwrap();
    (handle, receiver)
}

#[tokio::test]
async fn drop_and_replacement_abort_only_the_owned_task() {
    let (mut link, peer, _client, _server) = connected_links().await;
    let (old, old_done) = task().await;
    link = link.with_connection_task(old);
    let (new, mut new_done) = task().await;
    let (fresh, fresh_peer, _fresh_client, _fresh_server) = connected_links().await;
    let connection = fresh.connection().clone();
    let fresh = fresh.with_connection_task(new);
    link.rebind_from(fresh);
    old_done.await.unwrap();
    assert!(matches!(
        new_done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(connection.close_reason().is_none());
    drop(link);
    new_done.await.unwrap();
    assert!(connection.close_reason().is_none());
    assert!(fresh_peer.connection().close_reason().is_none());
    // The old link no longer owns this peer; retaining it is harmless to the new task.
    drop(peer);
}

#[tokio::test]
async fn raw_connection_rebind_cancels_auxiliary_task() {
    let (link, _peer, _client, _server) = connected_links().await;
    let (handle, done) = task().await;
    let mut link = link.with_connection_task(handle);
    link.rebind(link.connection().clone());
    done.await.unwrap();
}
