use super::*;

impl ProxyService {
    #[allow(clippy::result_large_err)]
    pub(crate) async fn authenticate_proxy(
        &self,
        req: &Request<Incoming>,
        client_ip: &str,
        conn_auth: Option<&crate::auth::ConnAuthCache>,
    ) -> Result<Option<Arc<UserInfo>>, Response<Body>> {
        let Some(auth) = &self.auth else {
            return Ok(None);
        };
        if !auth.is_enabled() {
            return Ok(None);
        }

        match auth
            .handle_proxy_auth(client_ip, req, conn_auth, false)
            .await
        {
            ProxyAuthOutcome::Anonymous => Ok(None),
            ProxyAuthOutcome::Authenticated(user) => Ok(Some(Arc::new(user))),
            ProxyAuthOutcome::Challenge {
                authenticate_header,
            } => {
                if let Some(cache) = conn_auth {
                    cache.invalidate().await;
                }
                tracing::debug!("Proxy authentication challenge issued");
                Err(auth.create_auth_challenge_response(authenticate_header, false))
            }
        }
    }

    pub(crate) fn user_fields(user: Option<&UserInfo>) -> (Option<String>, Option<String>) {
        user.map(|u| {
            let name = u.username.clone();
            (Some(name.clone()), Some(name))
        })
        .unwrap_or((None, None))
    }

    pub(crate) fn check_rate_limit(
        &self,
        client_ip: &str,
        username: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> Option<Response<Body>> {
        // Disabled is the default: bail before touching headers or metrics so a
        // deployment that does not rate limit pays nothing per request.
        if !self.rate_limiter.is_enabled() {
            return None;
        }
        let api_key = extract_api_key_ref(headers, self.rate_limiter.config());
        if self.rate_limiter.is_distributed() {
            self.metrics.distributed_rate_limit_hits_total.inc();
        }
        let violation = self.rate_limiter.check(client_ip, username, api_key)?;
        let (limit_type, status, body) = match violation {
            RateLimitViolation::Ip => (
                "ip",
                StatusCode::TOO_MANY_REQUESTS,
                &b"429 Too Many Requests: rate limit exceeded"[..],
            ),
            RateLimitViolation::User => (
                "user",
                StatusCode::TOO_MANY_REQUESTS,
                &b"429 Too Many Requests: rate limit exceeded"[..],
            ),
            RateLimitViolation::ApiKey => (
                "api_key",
                StatusCode::TOO_MANY_REQUESTS,
                &b"429 Too Many Requests: API key rate limit exceeded"[..],
            ),
            RateLimitViolation::ApiKeyMissing => (
                "api_key_missing",
                StatusCode::UNAUTHORIZED,
                &b"401 Unauthorized: API key required"[..],
            ),
        };
        self.metrics
            .rate_limit_rejected_total
            .with_label_values(&[limit_type])
            .inc();
        let key_prefix = api_key.map(|k| &k[..k.len().min(4)]).unwrap_or("-");
        warn!(
            "Rate limit ({}) for client_ip={} user={} api_key_prefix={}",
            limit_type,
            client_ip,
            username.unwrap_or("-"),
            key_prefix
        );
        Some(Self::rate_limit_response(status, body))
    }

    fn rate_limit_response(status: StatusCode, body: &'static [u8]) -> Response<Body> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY");
        if status == StatusCode::TOO_MANY_REQUESTS {
            builder = builder.header("Retry-After", "1");
        }
        builder
            .body(full(Bytes::from_static(body)))
            .unwrap_or_else(|_| Response::new(full(Bytes::from_static(b"429 Too Many Requests"))))
    }
}
