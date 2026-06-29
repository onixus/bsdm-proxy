//! Shared HTTP body type alias.

use bytes::Bytes;

pub type Body = http_body_util::Full<Bytes>;
