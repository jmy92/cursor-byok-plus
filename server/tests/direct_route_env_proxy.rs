//! Verifies that a Direct-route client never routes through proxy environment
//! variables. The installed app runs with whatever environment the OS shell
//! has; stale HTTP_PROXY/HTTPS_PROXY values must not hijack outbound requests.
//!
//! Runs as its own test binary so the process-wide environment it sets cannot
//! leak into other tests.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use cursor_server::network::{client_builder_for_route, OutboundRoute};

#[tokio::test]
async fn direct_route_client_ignores_proxy_env_vars() {
    // Target HTTP server that answers every request with "ok".
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = target_listener.accept().await else {
                return;
            };
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });

    // A fake proxy that records whether anything ever connects to it.
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();

    std::env::set_var("HTTP_PROXY", format!("http://{proxy_address}"));
    std::env::set_var("HTTPS_PROXY", format!("http://{proxy_address}"));
    std::env::remove_var("NO_PROXY");

    let client = client_builder_for_route(OutboundRoute::Direct)
        .unwrap()
        .build()
        .unwrap();

    let body = client
        .get(format!("http://{target_address}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "ok");

    // Give a misrouted connection a chance to appear, then assert none did.
    tokio::time::timeout(Duration::from_millis(150), proxy_listener.accept())
        .await
        .expect_err("the direct route must not connect to the proxy from the environment");

    target.abort();
    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("HTTPS_PROXY");
}
