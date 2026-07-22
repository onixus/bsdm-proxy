//! Optional gRPC control plane (Cargo feature `grpc`).
//!
//! Enable at build: `--features grpc`
//! Enable at runtime: `CONTROL_GRPC_ENABLED=true` (bind `CONTROL_GRPC_BIND`, default `127.0.0.1:50051`).

use std::sync::Arc;

use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::control_api::{ControlApiState, PurgeRequest as ApiPurgeRequest};

pub mod proto {
    tonic::include_proto!("bsdm.control.v1");
}

use proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use proto::*;

#[derive(Clone)]
struct ControlPlaneService {
    state: Arc<ControlApiState>,
}

fn bearer_from_metadata(meta: &MetadataMap) -> Option<&str> {
    meta.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
}

#[allow(clippy::result_large_err)]
fn require_auth(state: &ControlApiState, meta: &MetadataMap) -> Result<(), Status> {
    if !state.auth_required() {
        return Ok(());
    }
    if state.is_authorized_bearer(bearer_from_metadata(meta)) {
        Ok(())
    } else {
        Err(Status::unauthenticated("unauthorized"))
    }
}

#[tonic::async_trait]
impl ControlPlane for ControlPlaneService {
    async fn get_stats(&self, _req: Request<Empty>) -> Result<Response<StatsResponse>, Status> {
        let s = self.state.stats_payload();
        Ok(Response::new(StatsResponse {
            service: s.service.to_string(),
            uptime_secs: s.uptime_secs,
            requests_in_flight: s.requests_in_flight,
            cache: Some(CacheStats {
                hits: s.cache.hits,
                misses: s.cache.misses,
                bypasses: s.cache.bypasses,
                hit_ratio: s.cache.hit_ratio,
                entries: s.cache.entries as u64,
                capacity: s.cache.capacity as u64,
                shards: s.cache.shards as u64,
                tags: s.cache.tags as u64,
            }),
        }))
    }

    async fn purge_cache(
        &self,
        req: Request<PurgeRequest>,
    ) -> Result<Response<PurgeResponse>, Status> {
        require_auth(&self.state, req.metadata())?;
        let p = req.into_inner();
        let api_req = ApiPurgeRequest {
            all: p.all,
            url: if p.url.is_empty() { None } else { Some(p.url) },
            method: if p.method.is_empty() {
                None
            } else {
                Some(p.method)
            },
            tag: if p.tag.is_empty() { None } else { Some(p.tag) },
            tags: p.tags,
        };
        match self.state.purge_payload(api_req).await {
            Ok(r) => Ok(Response::new(PurgeResponse {
                status: r.status,
                scope: r.scope,
                removed: r.removed as u64,
                url: r.url.unwrap_or_default(),
                tags: r.tags,
            })),
            Err(e) => Err(Status::invalid_argument(e)),
        }
    }

    async fn list_hierarchy_peers(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<PeersListResponse>, Status> {
        let payload = self.state.hierarchy_peers_payload().await;
        Ok(Response::new(PeersListResponse {
            enabled: payload.enabled,
            peers: payload
                .peers
                .into_iter()
                .map(|p| PeerInfo {
                    id: p.id,
                    host: p.host,
                    port: p.port as u32,
                    peer_type: p.peer_type,
                    weight: p.weight,
                    icp_port: p.icp_port.unwrap_or(0) as u32,
                    healthy: p.healthy,
                    is_static: p.is_static,
                })
                .collect(),
        }))
    }

    async fn reload_hierarchy(
        &self,
        req: Request<Empty>,
    ) -> Result<Response<HierarchyReloadResponse>, Status> {
        require_auth(&self.state, req.metadata())?;
        match self.state.hierarchy_reload_payload().await {
            Ok(r) => Ok(Response::new(HierarchyReloadResponse {
                status: r.status.to_string(),
                source: r.source,
                added: r.added,
                removed: r.removed,
                preserved_discovery: r.preserved_discovery,
                error: String::new(),
            })),
            Err(e) if e.contains("hierarchy disabled") => Err(Status::failed_precondition(e)),
            Err(e) => Err(Status::invalid_argument(e)),
        }
    }

    async fn get_upstream_tls(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<UpstreamTlsSnapshot>, Status> {
        let s = self.state.upstream_tls_snapshot();
        Ok(Response::new(UpstreamTlsSnapshot {
            http2_enabled: s.http2_enabled,
            ca_cert_path: s.ca_cert_path.unwrap_or_default(),
            custom_ca: s.custom_ca,
            reloaded_at_unix: s.reloaded_at_unix,
        }))
    }

    async fn reload_upstream_tls(
        &self,
        req: Request<Empty>,
    ) -> Result<Response<UpstreamTlsReloadResponse>, Status> {
        require_auth(&self.state, req.metadata())?;
        match self.state.upstream_tls_reload_payload() {
            Ok(s) => Ok(Response::new(UpstreamTlsReloadResponse {
                status: "reloaded".into(),
                tls: Some(UpstreamTlsSnapshot {
                    http2_enabled: s.http2_enabled,
                    ca_cert_path: s.ca_cert_path.unwrap_or_default(),
                    custom_ca: s.custom_ca,
                    reloaded_at_unix: s.reloaded_at_unix,
                }),
                error: String::new(),
            })),
            Err(e) => Err(Status::invalid_argument(e)),
        }
    }
}

/// Bind and serve the control-plane gRPC API until the process exits.
pub async fn serve_control_grpc(state: Arc<ControlApiState>, bind: &str) -> Result<(), String> {
    let addr = bind
        .parse()
        .map_err(|e| format!("invalid CONTROL_GRPC_BIND {bind}: {e}"))?;
    info!("Control plane gRPC listening on {bind}");
    tonic::transport::Server::builder()
        .add_service(ControlPlaneServer::new(ControlPlaneService { state }))
        .serve(addr)
        .await
        .map_err(|e| format!("gRPC serve error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;
    use crate::sharded_cache::HttpL1Cache;
    use crate::upstream::{UpstreamClientHandle, UpstreamTlsConfig};
    use tokio::net::TcpListener;

    fn test_state() -> Arc<ControlApiState> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let upstream =
            UpstreamClientHandle::new(UpstreamTlsConfig::default()).expect("upstream client");
        Arc::new(ControlApiState::new(
            metrics,
            cache,
            None,
            None,
            None,
            false,
            upstream,
            #[cfg(feature = "wasm")]
            None,
            Arc::new(crate::casb::CasbEngine::new()),
            Arc::new(crate::dlp::DlpEngine::new()),
        ))
    }

    #[tokio::test]
    async fn grpc_get_stats_and_purge() {
        let state = test_state();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let svc_state = state.clone();
        let bind = addr.to_string();
        tokio::spawn(async move {
            let _ = serve_control_grpc(svc_state, &bind).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client =
            proto::control_plane_client::ControlPlaneClient::connect(format!("http://{addr}"))
                .await
                .expect("connect");

        let stats = client
            .get_stats(Request::new(Empty {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stats.service, "bsdm-proxy");
        assert!(stats.cache.as_ref().unwrap().capacity > 0);

        let purge = client
            .purge_cache(Request::new(PurgeRequest {
                all: true,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(purge.scope, "all");
    }

    #[tokio::test]
    async fn grpc_purge_requires_bearer_when_token_set() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let metrics = Arc::new(Metrics::new().unwrap());
        let cache = Arc::new(HttpL1Cache::new(100, 4));
        let upstream =
            UpstreamClientHandle::new(UpstreamTlsConfig::default()).expect("upstream client");
        let state = Arc::new(ControlApiState::new(
            metrics,
            cache,
            None,
            Some("secret".into()),
            None,
            false,
            upstream,
            #[cfg(feature = "wasm")]
            None,
            Arc::new(crate::casb::CasbEngine::new()),
            Arc::new(crate::dlp::DlpEngine::new()),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let svc_state = state.clone();
        let bind = addr.to_string();
        tokio::spawn(async move {
            let _ = serve_control_grpc(svc_state, &bind).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client =
            proto::control_plane_client::ControlPlaneClient::connect(format!("http://{addr}"))
                .await
                .unwrap();

        let err = client
            .purge_cache(Request::new(PurgeRequest {
                all: true,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let mut req = Request::new(PurgeRequest {
            all: true,
            ..Default::default()
        });
        req.metadata_mut()
            .insert("authorization", "Bearer secret".parse().unwrap());
        let ok = client.purge_cache(req).await.unwrap().into_inner();
        assert_eq!(ok.scope, "all");
    }
}
