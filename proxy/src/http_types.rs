//! Shared HTTP body type alias.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::Error;
use std::convert::Infallible;

/// Response body: buffered (`Full`) or streaming (`TeeMissBody`, etc.).
pub type Body = BoxBody<Bytes, Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|e: Infallible| match e {})
        .boxed()
}

pub fn empty() -> Body {
    full(Bytes::new())
}
