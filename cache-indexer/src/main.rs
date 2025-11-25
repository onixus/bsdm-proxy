use opensearch::{
    http::transport::TransportBuilder,
    BulkParts, OpenSearch,
};
use rdkafka::{
    config::ClientConfig,
    consumer::{CommitMode, Consumer, StreamConsumer},
    message::Message,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{error, info, warn};

// ...оставшийся код без изменений...
