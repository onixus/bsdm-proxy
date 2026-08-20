//! Feed fetching.
//!
//! The collector is metadata-only by construction: it issues `GET` requests
//! against configured feed endpoints, refuses redirects to non-HTTP schemes,
//! and never requests an indicator value it has collected.

use crate::source::{FeedError, FeedSource};
use std::time::Duration;

pub struct FeedHttpClient {
    client: reqwest::Client,
    max_body_bytes: usize,
}

impl FeedHttpClient {
    pub fn new(timeout: Duration, max_body_bytes: usize, user_agent: &str) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent.to_string())
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
        Ok(Self {
            client,
            max_body_bytes,
        })
    }

    pub async fn fetch(&self, source: &dyn FeedSource) -> Result<String, FeedError> {
        let url = source.url();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(FeedError::Parse(format!("feed URL must be http(s): {url}")));
        }

        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, source.accept())
            .send()
            .await
            .map_err(|e| FeedError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(FeedError::Status(status.as_u16()));
        }

        // Reject oversized feeds before buffering them when the server is honest
        // about the length, and again after reading when it is not.
        if let Some(len) = response.content_length() {
            if len as usize > self.max_body_bytes {
                return Err(FeedError::TooLarge {
                    limit: self.max_body_bytes,
                });
            }
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| FeedError::Transport(e.to_string()))?;
        if bytes.len() > self.max_body_bytes {
            return Err(FeedError::TooLarge {
                limit: self.max_body_bytes,
            });
        }

        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}
