mod auth_config;
mod policy_config;

use auth_config::load_auth_config;
use bsdm_proxy::{
    bind_http_listeners, build_hierarchy_manager, handle_connection, http_cache_key,
    icp_server_bind_addr, load_hierarchy_config, metrics_server, should_start_icp_server,
    wait_shutdown_signal, AclAction, AuthManager, CacheConfig, CertCache, IcpServer, L2CacheConfig,
    Metrics, PerfConfig, ProxyPolicy, ProxyService, RateLimitConfig, RedisL2Cache,
    UpstreamTlsConfig,
};
use policy_config::{load_policy_config, reload_acl_engine};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

async fn run_accept_loop(
    listener: Arc<TcpListener>,
    service: Arc<ProxyService>,
    connection_tasks: TaskTracker,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Accept failed: {}", e);
                        continue;
                    }
                };
                let service_clone = service.clone();
                let client_ip = addr.ip().to_string();
                let tasks = connection_tasks.clone();
                connection_tasks.spawn(async move {
                    handle_connection(stream, addr, service_clone, client_ip, tasks).await;
                });
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            // Fallback when RUST_LOG is unset — see docs/logging.md
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bsdm_proxy=debug".into()),
        )
        .init();

    let metrics = Arc::new(Metrics::new()?);
    let draining = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection_tasks = TaskTracker::new();

    let shutdown_timeout_secs = std::env::var("SHUTDOWN_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);

    let metrics_port = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9090);

    tokio::spawn(metrics_server(
        metrics.clone(),
        draining.clone(),
        shutdown_rx.clone(),
        metrics_port,
    ));

    let mitm_enabled = std::env::var("MITM_ENABLED")
        .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(true);

    let cert_cache = CertCache::load_for_startup(mitm_enabled).await?;
    let kafka_brokers = std::env::var("KAFKA_BROKERS").ok();
    let kafka_topic = std::env::var("KAFKA_TOPIC").unwrap_or_else(|_| "cache-events".to_string());
    let cache_config = CacheConfig::from_env();

    let l2_config = L2CacheConfig::from_env();
    let l2_cache = if l2_config.enabled {
        match RedisL2Cache::connect(&l2_config, metrics.clone()).await {
            Ok(cache) => {
                info!(
                    "Redis L2 cache enabled (url={}, prefix={})",
                    l2_config.url, l2_config.key_prefix
                );
                Some(cache)
            }
            Err(e) => {
                warn!("Redis L2 cache disabled: connection failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    let auth_config = load_auth_config();
    let auth = if auth_config.enabled {
        Some(Arc::new(AuthManager::new(auth_config.clone())))
    } else {
        None
    };

    let policy_config = load_policy_config();
    if policy_config.acl_enabled {
        info!("ACL enabled");
    }
    if policy_config.categorization.is_some() {
        info!("URL categorization enabled");
    }

    let proxy_policy = ProxyPolicy {
        acl_engine: policy_config.acl_engine.clone(),
        categorization: policy_config.categorization.clone(),
    };

    let hierarchy_config = load_hierarchy_config();
    let hierarchy = build_hierarchy_manager(&hierarchy_config, metrics.clone())
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

    let rate_limit_config = RateLimitConfig::from_env();
    let upstream_tls = UpstreamTlsConfig::from_env();
    let perf = PerfConfig::from_env();

    let service = Arc::new(ProxyService::new(
        cert_cache,
        cache_config.clone(),
        l2_cache,
        kafka_brokers,
        kafka_topic,
        metrics.clone(),
        mitm_enabled,
        auth,
        &proxy_policy,
        hierarchy.clone(),
        rate_limit_config.clone(),
        upstream_tls,
        perf.clone(),
    ));

    if should_start_icp_server(&hierarchy_config) {
        let icp_bind = icp_server_bind_addr();
        let cache_for_icp = service.http_cache();
        match IcpServer::new(&icp_bind, move |url: &str| {
            let key = http_cache_key("GET", url);
            cache_for_icp
                .get(&key)
                .is_some_and(|cached| !cached.is_expired())
        })
        .await
        {
            Ok(server) => {
                info!("ICP server listening on {}", icp_bind);
                let server = Arc::new(server);
                tokio::spawn(async move {
                    server.serve().await;
                });
            }
            Err(e) => warn!("ICP server disabled: failed to bind {}: {}", icp_bind, e),
        }
    }

    if hierarchy_config.enabled {
        if let Some(ref manager) = hierarchy {
            info!("{}", manager.stats_summary().await);
        }
    }

    if policy_config.acl_auto_reload {
        if let (Some(acl_engine), Some(rules_path)) = (
            policy_config.acl_engine.clone(),
            policy_config.acl_rules_path.clone(),
        ) {
            let default_action = std::env::var("ACL_DEFAULT_ACTION")
                .map(|v| match v.to_ascii_lowercase().as_str() {
                    "deny" => AclAction::Deny,
                    "redirect" => AclAction::Redirect,
                    _ => AclAction::Allow,
                })
                .unwrap_or(AclAction::Allow);
            let reload_interval = policy_config.acl_reload_interval;
            let mut shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(reload_interval);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match reload_acl_engine(&rules_path, default_action) {
                                Ok(engine) => {
                                    let mut guard = acl_engine.write().await;
                                    *guard = engine;
                                    info!("ACL rules reloaded from {}", rules_path);
                                }
                                Err(e) => warn!("ACL reload failed: {}", e),
                            }
                        }
                        changed = shutdown_rx.changed() => {
                            if changed.is_ok() && *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    }

    let http_port = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1488);

    let listeners = bind_http_listeners(http_port, perf.worker_count).await?;
    let worker_count = listeners.len();
    info!(
        "🚀 BSDM-Proxy v2.0 (optimized) on 0.0.0.0:{} ({} accept worker(s))",
        http_port, worker_count
    );
    if perf.fast_cache_hit {
        info!("⚡ PERF_FAST_CACHE_HIT enabled — L1 HIT skips policy/Kafka on hot path");
    }
    if perf.worker_count > 1 {
        info!("⚡ WORKER_COUNT={} (SO_REUSEPORT)", perf.worker_count);
    }
    info!(
        "🔐 MITM: {} (ports 443/8443)",
        if mitm_enabled { "enabled" } else { "disabled" }
    );
    if auth_config.enabled {
        info!(
            "👤 Proxy auth: enabled (backend={}, realm={})",
            auth_config.backend, auth_config.realm
        );
    } else {
        info!("👤 Proxy auth: disabled");
    }
    if rate_limit_config.enabled {
        info!(
            "⏱️  Rate limit: enabled (ip={}/{} rps/burst, user={}/{} rps/burst)",
            rate_limit_config.ip_rps,
            rate_limit_config.ip_burst,
            rate_limit_config.user_rps,
            rate_limit_config.user_burst
        );
    } else {
        info!("⏱️  Rate limit: disabled");
    }
    info!(
        "📦 Cache: {} entries, TTL: {:?}, max body: {}MB",
        service.http_cache().capacity(),
        cache_config.default_ttl,
        cache_config.max_body_size / 1024 / 1024
    );

    let metrics_clone = metrics.clone();
    let cache_clone = service.http_cache();
    let mut cache_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let entries = cache_clone.len();
                    let weight = cache_clone.weight();

                    metrics_clone.cache_entries.set(entries as f64);
                    metrics_clone.cache_size_bytes.set(weight as f64);

                    debug!(
                        "Cache stats: entries={}, weight={}KB",
                        entries,
                        weight / 1024
                    );
                }
                changed = cache_shutdown_rx.changed() => {
                    if changed.is_ok() && *cache_shutdown_rx.borrow() {
                        debug!("Cache metrics reporter stopped");
                        break;
                    }
                }
            }
        }
    });

    if let Some(auth_manager) = service.auth() {
        let mut auth_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => auth_manager.cleanup_cache().await,
                    changed = auth_shutdown_rx.changed() => {
                        if changed.is_ok() && *auth_shutdown_rx.borrow() {
                            debug!("Auth cache cleanup stopped");
                            break;
                        }
                    }
                }
            }
        });
    }

    for listener in listeners {
        let listener = Arc::new(listener);
        let service_clone = service.clone();
        let tasks = connection_tasks.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(run_accept_loop(listener, service_clone, tasks, shutdown_rx));
    }

    wait_shutdown_signal().await;
    info!("Shutdown signal received, stopping accept loops");
    let _ = shutdown_tx.send(true);

    draining.store(true, Ordering::SeqCst);

    let in_flight = service.metrics().requests_in_flight.get() as usize;
    info!(
        "Draining connections: {} tracked tasks, {} in-flight HTTP requests",
        connection_tasks.len(),
        in_flight
    );

    connection_tasks.close();
    tokio::select! {
        _ = connection_tasks.wait() => info!("All proxy connections closed"),
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!(
                "Shutdown timeout after {}s, {} tasks still active",
                shutdown_timeout_secs,
                connection_tasks.len()
            );
        }
    }

    service
        .flush_kafka(shutdown_timeout.min(Duration::from_secs(10)))
        .await;
    info!("Graceful shutdown complete");
    Ok(())
}
