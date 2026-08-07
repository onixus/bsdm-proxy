//! Lab alias kept for existing docs/scripts; identical behaviour to
//! `bsdm-agent`. Separate file on purpose — see the note in bsdm-agent.rs.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    agent_spike::run().await
}
