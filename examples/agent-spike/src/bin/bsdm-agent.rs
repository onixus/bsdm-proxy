//! Product binary. Real logic lives in the `agent_spike` library so that this
//! entry point and the `agent-spike` lab alias are two distinct source files —
//! pointing several [[bin]] targets at one file makes cargo build them
//! concurrently from the same source and breaks cold builds with E0463.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    agent_spike::run().await
}
