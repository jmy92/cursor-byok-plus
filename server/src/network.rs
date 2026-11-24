//! Owns reusable outbound HTTP clients configured from persisted proxy settings.
//!
//! Outbound requests resolve to one of two routes: a primary route derived from
//! the proxy settings, and — after a connection-level failure — a fallback route
//! that stays active for [`FALLBACK_ROUTE_TTL`] before the primary is probed again.

use std::{sync::Arc, time::Duration};

use tokio::sync::RwLock;

use crate::{
    store::{ProxyMode, ProxySettingsSecret, Store},
    Error, Result,
};

const LOCAL_NO_PROXY: &str = "localhost,127.0.0.0/8,::1";

/// How long a fallback route stays active before the primary route is probed again.
const FALLBACK_ROUTE_TTL: Duration = Duration::from_secs(600);

/// Minimum interval between client recycles triggered by persistent failures.
const CLIENT_RECYCLE_INTERVAL: Duration = Duration::from_secs(60);

/// A concrete outbound proxy endpoint with optional basic auth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRoute {
    address: String,
    auth_enabled: bool,
    username: String,
    password: String,
}

/// The route outbound requests currently take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundRoute {
    Direct,
    Proxy(ProxyRoute),
}

#[derive(Default)]
struct RouteState {
    /// Fallback route activated by a connection-level failure, with its expiry.
    fallback: Option<(OutboundRoute, std::time::Instant)>,
    /// Last time the clients were recycled after a failure with no route to switch to.
    last_recycle: Option<std::time::Instant>,
}

#[derive(Clone)]
pub struct NetworkClients {
    store: Store,
    cache: Arc<RwLock<ClientCache>>,
    route: Arc<RwLock<RouteState>>,
}

#[derive(Default)]
struct ClientCache {
    default: Option<reqwest::Client>,
    cursor: Option<reqwest::Client>,
    provider: Option<(Duration, reqwest::Client)>,
}

impl NetworkClients {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            cache: Arc::new(RwLock::new(ClientCache::default())),
            route: Arc::new(RwLock::new(RouteState::default())),
        }
    }

    pub async fn default_client(&self) -> Result<reqwest::Client> {
        if let Some(client) = self.cache.read().await.default.clone() {
            return Ok(client);
        }
        let mut cache = self.cache.write().await;
        if let Some(client) = cache.default.clone() {
            return Ok(client);
        }
        let route = self.resolved_route().await?;
        let client = client_builder_for_route(route)?.build()?;
        cache.default = Some(client.clone());
        Ok(client)
    }

    pub async fn cursor_client(&self) -> Result<reqwest::Client> {
        if let Some(client) = self.cache.read().await.cursor.clone() {
            return Ok(client);
        }
        let mut cache = self.cache.write().await;
        if let Some(client) = cache.cursor.clone() {
            return Ok(client);
        }
        let route = self.resolved_route().await?;
        let client = client_builder_for_route(route)?
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        cache.cursor = Some(client.clone());
        Ok(client)
    }

    pub async fn provider_client(&self, timeout: Duration) -> Result<reqwest::Client> {
        if let Some((_, client)) = self
            .cache
            .read()
            .await
            .provider
            .as_ref()
            .filter(|(cached_timeout, _)| *cached_timeout == timeout)
        {
            return Ok(client.clone());
        }
        let mut cache = self.cache.write().await;
        if let Some((_, client)) = cache
            .provider
            .as_ref()
            .filter(|(cached_timeout, _)| *cached_timeout == timeout)
        {
            return Ok(client.clone());
        }
        let route = self.resolved_route().await?;
        let client = client_builder_for_route(route)?.timeout(timeout).build()?;
        cache.provider = Some((timeout, client.clone()));
        Ok(client)
    }

    /// The route outbound requests currently take: the persisted primary route,
    /// or the fallback route activated by a recent connection-level failure.
    async fn resolved_route(&self) -> Result<OutboundRoute> {
        let settings = self.store.proxy_settings_secret().await?;
        let expired = {
            let mut state = self.route.write().await;
            let expired = state
                .fallback
                .as_ref()
                .is_some_and(|(_, until)| std::time::Instant::now() >= *until);
            if expired {
                state.fallback = None;
            }
            expired
        };
        if expired {
            // Rebuild the clients so the next request probes the primary route.
            self.invalidate().await;
        }
        let state = self.route.read().await;
        if let Some((route, _)) = state.fallback.as_ref() {
            return Ok(route.clone());
        }
        Ok(primary_route(&settings))
    }

    /// Activates the alternate route after a connection-level outbound failure.
    ///
    /// When no route switch is possible — the fallback is already active, or no
    /// alternate route exists for the current settings — the outbound clients are
    /// recycled (throttled by [`CLIENT_RECYCLE_INTERVAL`]) so later attempts start
    /// with fresh connection pools instead of reusing the sockets that keep failing.
    pub async fn report_outbound_failure(&self) -> Result<()> {
        let settings = self.store.proxy_settings_secret().await?;
        let mut state = self.route.write().await;
        let switched;
        if state.fallback.is_some() {
            // The fallback route is active and still failing.
            switched = false;
            if !recycle_due(&mut state) {
                return Ok(());
            }
        } else {
            let primary = primary_route(&settings);
            match alternate_route(&primary, &settings) {
                Some(alternate) => {
                    state.fallback =
                        Some((alternate, std::time::Instant::now() + FALLBACK_ROUTE_TTL));
                    switched = true;
                }
                None => {
                    // No alternate route exists for the current settings.
                    switched = false;
                    if !recycle_due(&mut state) {
                        return Ok(());
                    }
                }
            }
        }
        drop(state);
        self.invalidate().await;
        if switched {
            tracing::warn!(
                "outbound failure switched routes; subsequent requests take the fallback"
            );
        } else {
            tracing::warn!(
                "outbound failure persists; recycled outbound clients for fresh connections"
            );
        }
        Ok(())
    }

    pub async fn invalidate(&self) {
        *self.cache.write().await = ClientCache::default();
    }
}

/// Whether enough time has passed to recycle the outbound clients again.
fn recycle_due(state: &mut RouteState) -> bool {
    if state
        .last_recycle
        .is_some_and(|at| at.elapsed() < CLIENT_RECYCLE_INTERVAL)
    {
        return false;
    }
    state.last_recycle = Some(std::time::Instant::now());
    true
}

fn primary_route(settings: &ProxySettingsSecret) -> OutboundRoute {
    match settings.mode {
        ProxyMode::Custom if !settings.address.is_empty() => OutboundRoute::Proxy(ProxyRoute {
            address: settings.address.clone(),
            auth_enabled: settings.auth_enabled,
            username: settings.username.clone(),
            password: settings.password.clone(),
        }),
        ProxyMode::System => system_proxy_route().unwrap_or(OutboundRoute::Direct),
        _ => OutboundRoute::Direct,
    }
}

/// The route to try when the primary route fails at the connection level.
fn alternate_route(
    primary: &OutboundRoute,
    settings: &ProxySettingsSecret,
) -> Option<OutboundRoute> {
    match primary {
        OutboundRoute::Proxy(_) => Some(OutboundRoute::Direct),
        OutboundRoute::Direct => match settings.mode {
            ProxyMode::Custom if !settings.address.is_empty() => {
                Some(OutboundRoute::Proxy(ProxyRoute {
                    address: settings.address.clone(),
                    auth_enabled: settings.auth_enabled,
                    username: settings.username.clone(),
                    password: settings.password.clone(),
                }))
            }
            _ => system_proxy_route(),
        },
    }
}

/// The proxy configured at the operating system level, when enabled.
fn system_proxy_route() -> Option<OutboundRoute> {
    let proxy = sysproxy::Sysproxy::get_system_proxy().ok()?;
    if !proxy.enable || proxy.host.is_empty() || proxy.port == 0 {
        return None;
    }
    Some(OutboundRoute::Proxy(ProxyRoute {
        address: format!("http://{}:{}", proxy.host.trim(), proxy.port),
        auth_enabled: false,
        username: String::new(),
        password: String::new(),
    }))
}

fn proxy_from_route(route: &ProxyRoute) -> Result<reqwest::Proxy> {
    let mut proxy = reqwest::Proxy::all(&route.address)?
        .no_proxy(reqwest::NoProxy::from_string(LOCAL_NO_PROXY));
    if route.auth_enabled {
        proxy = proxy.basic_auth(&route.username, &route.password);
    }
    Ok(proxy)
}

pub fn client_builder_for_route(route: OutboundRoute) -> Result<reqwest::ClientBuilder> {
    // Use the platform TLS stack for compatibility with provider gateways that
    // only offer legacy TLS 1.2 cipher suites unsupported by rustls.
    let mut builder = reqwest::Client::builder().use_native_tls();
    match route {
        OutboundRoute::Proxy(proxy) => builder = builder.proxy(proxy_from_route(&proxy)?),
        // A direct route must stay direct: without this, proxy environment
        // variables (HTTP_PROXY/HTTPS_PROXY) silently hijack every outbound
        // request — the installed app runs with whatever environment the OS
        // shell has, and stale values there caused total outbound failure.
        OutboundRoute::Direct => builder = builder.no_proxy(),
    }
    Ok(builder)
}

/// Builds a client that always takes the primary route (no runtime fallback).
pub async fn client_builder(store: &Store) -> Result<reqwest::ClientBuilder> {
    let settings = store.proxy_settings_secret().await?;
    client_builder_for_route(primary_route(&settings))
}

pub async fn client(store: &Store) -> Result<reqwest::Client> {
    Ok(client_builder(store).await?.build()?)
}

pub async fn blocking_client_builder(store: &Store) -> Result<reqwest::blocking::ClientBuilder> {
    let settings = store.proxy_settings_secret().await?;
    let mut builder = reqwest::blocking::Client::builder().use_native_tls();
    if let OutboundRoute::Proxy(proxy) = primary_route(&settings) {
        builder = builder.proxy(proxy_from_route(&proxy)?);
    }
    Ok(builder)
}

pub fn reject_self_proxy(address: &str, local_proxy_port: u16) -> Result<()> {
    if local_proxy_port == 0 {
        return Ok(());
    }
    let url = url::Url::parse(address)
        .map_err(|error| Error::Config(format!("invalid proxy address: {error}")))?;
    if url.port_or_known_default() == Some(local_proxy_port) && url_host_is_loopback(&url) {
        return Err(Error::Config(
            "proxy address cannot point to the Cursor BYOK local proxy".into(),
        ));
    }
    Ok(())
}

fn url_host_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        }
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::store::ProxyMode;

    fn custom_settings(address: String) -> ProxySettingsSecret {
        ProxySettingsSecret {
            mode: ProxyMode::Custom,
            address,
            auth_enabled: false,
            username: String::new(),
            password: String::new(),
        }
    }

    #[tokio::test]
    async fn reqwest_classifies_a_refused_connection_as_a_connect_failure() {
        // Bind then drop a listener to obtain a guaranteed-closed loopback port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = reqwest::Client::builder().use_native_tls().build().unwrap();

        let error = client
            .get(format!("http://{address}"))
            .send()
            .await
            .expect_err("a request to a closed port must fail");

        assert!(
            error.is_connect(),
            "the failure hooks rely on is_connect(); got: {error}"
        );
    }

    #[test]
    fn rejects_only_own_loopback_proxy_port() {
        for address in [
            "http://localhost:15721",
            "http://localhost.:15721",
            "http://127.0.0.2:15721",
            "http://[::1]:15721",
        ] {
            assert!(reject_self_proxy(address, 15721).is_err(), "{address}");
        }
        assert!(reject_self_proxy("http://127.0.0.1:7890", 15721).is_ok());
        assert!(reject_self_proxy("http://192.168.1.2:15721", 15721).is_ok());
        assert!(reject_self_proxy("http://127.0.0.1:15721", 0).is_ok());
    }

    #[tokio::test]
    async fn custom_proxy_bypasses_loopback_destinations() {
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut socket, _) = target_listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let settings = custom_settings(format!("http://{proxy_address}"));
        let client = reqwest::Client::builder()
            .proxy(
                proxy_from_route(&ProxyRoute {
                    address: settings.address.clone(),
                    auth_enabled: false,
                    username: String::new(),
                    password: String::new(),
                })
                .unwrap(),
            )
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
        target.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), proxy_listener.accept())
                .await
                .is_err(),
            "loopback destination unexpectedly reached the configured proxy"
        );
    }

    #[test]
    fn primary_route_follows_the_selected_mode() {
        let direct = ProxySettingsSecret {
            mode: ProxyMode::Default,
            address: String::new(),
            auth_enabled: false,
            username: String::new(),
            password: String::new(),
        };
        assert_eq!(primary_route(&direct), OutboundRoute::Direct);

        let custom = custom_settings("http://127.0.0.1:7890".into());
        let primary = primary_route(&custom);
        let OutboundRoute::Proxy(ref proxy) = primary else {
            panic!("custom mode must resolve to a proxy route");
        };
        assert_eq!(proxy.address, "http://127.0.0.1:7890");

        // A proxy primary always falls back to direct; a direct primary with a
        // configured custom address falls back to that proxy.
        assert_eq!(
            alternate_route(&primary, &custom),
            Some(OutboundRoute::Direct)
        );
        assert_eq!(
            alternate_route(&OutboundRoute::Direct, &custom),
            Some(primary)
        );
    }

    #[tokio::test]
    async fn failure_flips_to_the_alternate_route_and_stays_until_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", directory.path().join("test.db").display());
        let store = Store::connect(&url).await.unwrap();
        store
            .set_proxy_settings(crate::store::ProxySettingsInput {
                mode: ProxyMode::Custom,
                address: "http://127.0.0.1:7890".into(),
                auth_enabled: false,
                username: String::new(),
                password: None,
            })
            .await
            .unwrap();
        let clients = NetworkClients::new(store);
        let _ = clients.default_client().await.unwrap();

        clients.report_outbound_failure().await.unwrap();
        {
            let state = clients.route.read().await;
            assert_eq!(
                state.fallback.as_ref().map(|(route, _)| route),
                Some(&OutboundRoute::Direct),
                "a failing proxy primary must fall back to direct"
            );
        }

        // While the fallback is active, further failures must not flip again.
        let _ = clients.default_client().await.unwrap();
        clients.report_outbound_failure().await.unwrap();
        {
            let state = clients.route.read().await;
            assert_eq!(
                state.fallback.as_ref().map(|(route, _)| route),
                Some(&OutboundRoute::Direct),
                "repeated failures must not churn the fallback route"
            );
        }

        // The first failure on the fallback route recycles the clients.
        assert!(
            clients.cache.read().await.default.is_none(),
            "a failure on the fallback route must recycle the clients"
        );

        // Recycling is throttled: a client rebuilt right after stays in place.
        let _ = clients.default_client().await.unwrap();
        clients.report_outbound_failure().await.unwrap();
        assert!(
            clients.cache.read().await.default.is_some(),
            "recycles must be throttled by the recycle interval"
        );
    }

    #[tokio::test]
    async fn direct_mode_failure_only_flips_when_a_system_proxy_exists() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", directory.path().join("test.db").display());
        let store = Store::connect(&url).await.unwrap();
        let clients = NetworkClients::new(store);
        let _ = clients.default_client().await.unwrap();

        clients.report_outbound_failure().await.unwrap();
        match system_proxy_route() {
            None => {
                let state = clients.route.read().await;
                assert!(
                    state.fallback.is_none(),
                    "without a system proxy there is nothing to fall back to"
                );
                drop(state);
                assert!(
                    clients.cache.read().await.default.is_none(),
                    "with no alternate route the clients must still be recycled"
                );
            }
            Some(alternate) => {
                let state = clients.route.read().await;
                assert_eq!(
                    state.fallback.as_ref().map(|(route, _)| route),
                    Some(&alternate)
                );
            }
        }
    }
}
