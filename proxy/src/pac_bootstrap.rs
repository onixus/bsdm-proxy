//! Startup bridge for the built-in PAC listener.
//!
//! `proxy/src/main.rs` already spawns the exported `metrics_server` function.
//! Keeping the same signature lets PAC startup remain an isolated module rather
//! than adding more orchestration to the main request-path bootstrap.

use crate::acl_api::AclApiState;
use crate::control_api::ControlApiState;
use crate::metrics::Metrics;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::error;

pub async fn metrics_server(
    metrics: Arc<Metrics>,
    draining: Arc<AtomicBool>,
    shutdown_rx: watch::Receiver<bool>,
    metrics_port: u16,
    acl_api: Option<Arc<AclApiState>>,
    control_api: Option<Arc<ControlApiState>>,
) {
    if let Err(error) = crate::pac::start_pac_server(metrics.clone(), shutdown_rx.clone()).await {
        error!(error = %error, "PAC server failed to start");
    }

    crate::server::metrics_server(
        metrics,
        draining,
        shutdown_rx,
        metrics_port,
        acl_api,
        control_api,
    )
    .await;
}
