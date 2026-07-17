//! HTTP proxy server: metrics endpoint, shutdown handling, and connection routing.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::acl_api::AclApiState;
use crate::auth::ConnAuthCache;
use crate::auth::UserInfo;
use crate::control_api::ControlApiState;
use crate::http_types::{empty, full};
use crate::metrics::Metrics;
use crate::pipeline::{new_event_id, CacheEvent};
use crate::proxy_service::ProxyService;
use crate::tls::{parse_authority, rewrite_mitm_request, should_mitm_port};

fn tune_client_tcp(stream: &TcpStream, addr: SocketAddr) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("set_nodelay failed for {}: {}", addr, e);
    }
    let sndbuf = std::env::var("TCP_SNDBUF_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512 * 1024);
    if sndbuf == 0 {
        return;
    }
    #[cfg(unix)]
    {
        use socket2::SockRef;
        if let Err(e) = SockRef::from(stream).set_send_buffer_size(sndbuf) {
            debug!(
                "set_send_buffer_size({}) failed for {}: {}",
                sndbuf, addr, e
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = sndbuf;
    }
}

pub async fn metrics_server(
    metrics: Arc<Metrics>,
    draining: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
    metrics_port: u16,
    acl_api: Option<Arc<AclApiState>>,
    control_api: Option<Arc<ControlApiState>>,
) {
    let bind_addr = format!("0.0.0.0:{}", metrics_port);
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind metrics server on {}: {}", bind_addr, e);
            return;
        }
    };

    info!("📊 Metrics server started on {}", bind_addr);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to accept metrics connection: {}", e);
                        continue;
                    }
                };

                let metrics = metrics.clone();
                let draining = draining.clone();
                let acl_api = acl_api.clone();
                let control_api = control_api.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let metrics = metrics.clone();
                        let draining = draining.clone();
                        let acl_api = acl_api.clone();
                        let control_api = control_api.clone();
                        async move {
                            let path = req.uri().path();
                            debug!("Metrics request from {}: {}", addr, path);

                            if let Some(api) = &acl_api {
                                if path.starts_with("/api/acl/") {
                                    return Ok::<_, Infallible>(api.handle_request(req).await);
                                }
                            }

                            if let Some(api) = &control_api {
                                if path == "/api/stats"
                                    || path.starts_with("/api/cache/")
                                    || path.starts_with("/api/hierarchy/")
                                    || path.starts_with("/api/upstream/")
                                {
                                    return Ok::<_, Infallible>(api.handle_request(req).await);
                                }
                            }

                            let response = match path {
                                "/metrics" => {
                                    debug!("Exporting metrics...");
                                    let export_result =
                                        panic::catch_unwind(panic::AssertUnwindSafe(|| metrics.export()));

                                    match export_result {
                                        Ok(Ok(body)) => {
                                            debug!("Metrics exported successfully: {} bytes", body.len());
                                            Response::builder()
                                                .status(StatusCode::OK)
                                                .header("Content-Type", "text/plain; version=0.0.4")
                                                .header("Content-Length", body.len().to_string())
                                                .body(full(Bytes::from(body)))
                                                .unwrap_or_else(|e| {
                                                    error!("Failed to build metrics response: {}", e);
                                                    Response::new(full(Bytes::from_static(
                                                        b"500 Internal Server Error",
                                                    )))
                                                })
                                        }
                                        Ok(Err(e)) => {
                                            error!("Failed to export metrics: {}", e);
                                            Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(full(Bytes::from_static(
                                                    b"500 Internal Server Error",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(full(Bytes::from_static(
                                                        b"500 Internal Server Error",
                                                    )))
                                                })
                                        }
                                        Err(panic_info) => {
                                            error!("Metrics export panicked: {:?}", panic_info);
                                            Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(full(Bytes::from_static(
                                                    b"500 Panic in metrics export",
                                                )))
                                                .unwrap_or_else(|_| {
                                                    Response::new(full(Bytes::from_static(
                                                        b"500 Internal Server Error",
                                                    )))
                                                })
                                        }
                                    }
                                }
                                "/health" => {
                                    debug!("Health check OK");
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("Content-Type", "application/json")
                                        .body(full(Bytes::from_static(b"{\"status\":\"ok\"}")))
                                        .unwrap_or_else(|_| {
                                            Response::new(full(Bytes::from_static(
                                                b"{\"status\":\"ok\"}",
                                            )))
                                        })
                                }
                                "/ready" => {
                                    if draining.load(Ordering::Relaxed) {
                                        debug!("Readiness check: draining");
                                        Response::builder()
                                            .status(StatusCode::SERVICE_UNAVAILABLE)
                                            .header("Content-Type", "application/json")
                                            .body(full(Bytes::from_static(
                                                b"{\"status\":\"draining\"}",
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(full(Bytes::from_static(
                                                    b"{\"status\":\"draining\"}",
                                                )))
                                            })
                                    } else {
                                        debug!("Readiness check OK");
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("Content-Type", "application/json")
                                            .body(full(Bytes::from_static(
                                                b"{\"status\":\"ready\"}",
                                            )))
                                            .unwrap_or_else(|_| {
                                                Response::new(full(Bytes::from_static(
                                                    b"{\"status\":\"ready\"}",
                                                )))
                                            })
                                    }
                                }
                                _ => {
                                    warn!("Unknown metrics endpoint: {}", path);
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(full(Bytes::from_static(b"404 Not Found")))
                                        .unwrap_or_else(|_| {
                                            Response::new(full(Bytes::from_static(b"404 Not Found")))
                                        })
                                }
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });

                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        error!("Metrics server connection error from {}: {}", addr, e);
                    }
                });
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    info!("Metrics server stopping");
                    break;
                }
            }
        }
    }
}

pub async fn wait_shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to listen for Ctrl+C: {}", e);
        } else {
            info!("Received Ctrl+C");
        }
    };

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

async fn handle_connect_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    authority: String,
    service: Arc<ProxyService>,
    client_ip: String,
    request_start: Instant,
    proxy_user: Option<Arc<UserInfo>>,
) {
    let mut client_io = TokioIo::new(upgraded);

    match TcpStream::connect(&authority).await {
        Ok(mut upstream) => {
            service.metrics.upstream_connections_created.inc();
            service.metrics.upstream_connections_active.inc();

            match copy_bidirectional(&mut client_io, &mut upstream).await {
                Ok((bytes_c2u, bytes_u2c)) => {
                    service.metrics.upstream_connections_active.dec();
                    let duration_ms = request_start.elapsed().as_millis() as u64;
                    let domain = parse_authority(&authority).0;
                    let (user_id, username) = ProxyService::user_fields(proxy_user.as_deref());

                    if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                    {
                        let event_id = new_event_id();
                        let url = format!("https://{}", authority);
                        let corr = service.sessions().begin_request(
                            &client_ip,
                            username.as_deref(),
                            None,
                            &url,
                        );
                        let event = CacheEvent {
                            url,
                            method: "CONNECT".to_string(),
                            status: 200,
                            cache_key: service
                                .generate_cache_key("CONNECT", &authority)
                                .to_string(),
                            cache_status: "BYPASS".to_string(),
                            timestamp: timestamp.as_secs(),
                            headers: HashMap::new(),
                            user_id,
                            username,
                            client_ip,
                            domain,
                            response_size: bytes_u2c,
                            request_duration_ms: duration_ms,
                            content_type: None,
                            user_agent: None,
                            categories: vec![],
                            threat_sources: vec![],
                            acl_action: None,
                            session_id: corr.session_id,
                            parent_event_id: corr.parent_event_id,
                            redirect_url: None,
                            event_id,
                        };
                        service.send_cache_event(event);
                    }
                    debug!("CONNECT tunnel closed: {}↑ {}↓", bytes_c2u, bytes_u2c);
                }
                Err(e) => {
                    error!("CONNECT copy failed: {}", e);
                    service.metrics.upstream_connections_active.dec();
                }
            }
        }
        Err(e) => {
            error!("CONNECT upstream failed: {}", e);
            service
                .metrics
                .upstream_errors_total
                .with_label_values(&[&authority, "connect"])
                .inc();
        }
    }
}

async fn handle_connect_mitm(
    upgraded: hyper::upgrade::Upgraded,
    authority: String,
    service: Arc<ProxyService>,
    client_ip: String,
    proxy_user: Option<Arc<UserInfo>>,
) {
    let (domain, _port) = parse_authority(&authority);

    let server_config = match service.cert_cache.server_config_for_domain(&domain).await {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to build TLS config for {}: {}", domain, e);
            return;
        }
    };

    let tls_acceptor = TlsAcceptor::from(server_config);
    let tls_stream = match tls_acceptor.accept(TokioIo::new(upgraded)).await {
        Ok(stream) => {
            service
                .metrics
                .tls_handshakes_total
                .with_label_values(&["success"])
                .inc();
            stream
        }
        Err(e) => {
            service
                .metrics
                .tls_handshakes_total
                .with_label_values(&["error"])
                .inc();
            error!("TLS handshake failed for {}: {}", domain, e);
            return;
        }
    };

    info!("MITM session established for {}", authority);
    let authority_log = authority.clone();
    let io = TokioIo::new(tls_stream);
    let svc = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        let client_ip = client_ip.clone();
        let authority = authority.clone();
        let proxy_user = proxy_user.clone();

        async move {
            let req = match rewrite_mitm_request(req, &authority) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to rewrite MITM request for {}: {}", authority, e);
                    let mut resp = Response::new(full(Bytes::from_static(b"400 Bad Request")));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok::<_, Infallible>(resp);
                }
            };

            Ok::<_, Infallible>(service.handle_request(req, client_ip, proxy_user).await)
        }
    });

    if let Err(e) = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, svc)
        .await
    {
        debug!("MITM connection closed for {}: {}", authority_log, e);
    }
}

pub async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    service: Arc<ProxyService>,
    client_ip: String,
    tasks: TaskTracker,
) {
    tune_client_tcp(&stream, addr);
    let io = TokioIo::new(stream);
    let preserve_headers = service.http_preserve_header_case();
    let conn_auth_ttl = service
        .auth()
        .map(|auth| auth.conn_cache_ttl())
        .unwrap_or(Duration::ZERO);
    let conn_auth = Arc::new(ConnAuthCache::new(conn_auth_ttl));

    let svc = service_fn(move |req: Request<Incoming>| {
        let service = service.clone();
        let client_ip = client_ip.clone();
        let request_start = Instant::now();
        let tasks = tasks.clone();
        let conn_auth = conn_auth.clone();

        async move {
            if req.method() == Method::CONNECT {
                let authority = match req.uri().authority() {
                    Some(auth) => auth.as_str().to_string(),
                    None => {
                        error!("CONNECT without authority");
                        let mut resp = Response::new(full(Bytes::from_static(b"400 Bad Request")));
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                        return Ok::<_, Infallible>(resp);
                    }
                };

                let proxy_user = match service
                    .authenticate_proxy(&req, &client_ip, Some(&conn_auth))
                    .await
                {
                    Ok(user) => user,
                    Err(resp) => return Ok(resp),
                };

                let policy_username = proxy_user.as_deref().map(|u| u.username.as_str());
                let policy_groups: Vec<&str> = proxy_user
                    .as_deref()
                    .map(|u| u.groups.iter().map(String::as_str).collect())
                    .unwrap_or_default();
                if let Some(resp) =
                    service.check_rate_limit(&client_ip, policy_username, req.headers())
                {
                    return Ok::<_, Infallible>(resp);
                }

                let connect_url = format!("https://{}", authority);
                let connect_domain = parse_authority(&authority).0;
                let (policy_decision, _, _) = service
                    .check_policy(
                        &connect_url,
                        &connect_domain,
                        policy_username,
                        &policy_groups,
                        &client_ip,
                    )
                    .await;
                if let Some(decision) = policy_decision {
                    return Ok::<_, Infallible>(ProxyService::policy_response(&decision));
                }

                tasks.spawn({
                    let service = service.clone();
                    let client_ip = client_ip.clone();
                    let authority = authority.clone();
                    let proxy_user = proxy_user.clone();
                    async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                let (_, port) = parse_authority(&authority);
                                if service.mitm_enabled && should_mitm_port(port) {
                                    handle_connect_mitm(
                                        upgraded, authority, service, client_ip, proxy_user,
                                    )
                                    .await;
                                } else {
                                    handle_connect_tunnel(
                                        upgraded,
                                        authority,
                                        service,
                                        client_ip,
                                        request_start,
                                        proxy_user,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => error!("Upgrade failed: {}", e),
                        }
                    }
                });

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(empty())
                    .unwrap_or_else(|e| {
                        error!("Failed to build response: {}", e);
                        let mut resp = Response::new(empty());
                        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        resp
                    });
                return Ok::<_, Infallible>(response);
            }

            let proxy_user = match service
                .authenticate_proxy(&req, &client_ip, Some(&conn_auth))
                .await
            {
                Ok(user) => user,
                Err(resp) => return Ok(resp),
            };

            Ok::<_, Infallible>(service.handle_request(req, client_ip, proxy_user).await)
        }
    });

    let serve_result = if preserve_headers {
        http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, svc)
            .with_upgrades()
            .await
    } else {
        http1::Builder::new()
            .serve_connection(io, svc)
            .with_upgrades()
            .await
    };

    if let Err(e) = serve_result {
        error!("Connection error from {}: {}", addr, e);
    }
}
