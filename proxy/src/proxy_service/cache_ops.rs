use super::*;

impl ProxyService {
    pub(super) async fn try_l2_cache_get(&self, cache_key: &Arc<str>) -> Option<CachedResponse> {
        let l2 = self.l2_cache.as_ref()?;
        l2.get(cache_key.as_ref()).await
    }

    pub(super) fn store_in_l1_and_l2(&self, cache_key: Arc<str>, cached_response: CachedResponse) {
        self.http_cache
            .insert(cache_key.clone(), cached_response.clone());
        if let Some(registry) = &self.digest_registry {
            let key = cache_key.to_string();
            let reg = registry.clone();
            tokio::spawn(async move {
                reg.insert_cache_key(&key).await;
            });
        }
        if let Some(l2) = &self.l2_cache {
            let l2 = l2.clone();
            tokio::spawn(async move {
                l2.set(cache_key.as_ref(), &cached_response).await;
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn serve_l1_hit(
        &self,
        cached: &CachedResponse,
        cache_key: &Arc<str>,
        url: &str,
        method: &str,
        user_id: &Option<String>,
        username: &Option<String>,
        user_agent: Option<&str>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
        detailed_metrics: bool,
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
        cache_status_label: &'static str,
        x_cache_status: &str,
    ) -> Response<Body> {
        if detailed_metrics {
            if let Some(g) = guard.as_mut() {
                g.set_cache_status(cache_status_label);
            }
            self.metrics.cache_hits_total.inc();
            self.emit_cache_hit_event(
                url,
                method,
                cache_key,
                cache_status_label,
                cached,
                user_id,
                username,
                user_agent,
                client_ip,
                categories,
                threat_sources,
                request_start,
            );
        } else if let Some(scope) = fast_scope.take() {
            scope.finish_cache_hit();
        }

        let response = cached.to_response_with_cache_status(x_cache_status);
        let body_size = cached.response_body_len();
        if let Some(g) = guard.take() {
            g.finish(cached.status, 0, body_size);
        }
        response
    }

    fn build_conditional_request(
        req: &Request<Incoming>,
        cached: &CachedResponse,
    ) -> Option<Request<Body>> {
        // Revalidation goes to the origin, so it is subject to the same
        // hop-by-hop rule as the plain forward path above.
        let mut headers = req.headers().clone();
        strip_hop_by_hop_request_headers(&mut headers);
        let mut builder = Request::builder()
            .method(req.method())
            .uri(req.uri().clone());
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        if let Some(etag) = &cached.etag {
            builder = builder.header(IF_NONE_MATCH, etag.as_ref());
        }
        if let Some(lm) = &cached.last_modified {
            builder = builder.header(IF_MODIFIED_SINCE, lm.as_ref());
        }
        builder.body(empty()).ok()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn try_revalidate_stale(
        &self,
        cached: &CachedResponse,
        req: &Request<Incoming>,
        cache_key: &Arc<str>,
        url: &str,
        method: &str,
        user_id: &Option<String>,
        username: &Option<String>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
        detailed_metrics: bool,
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
    ) -> Option<Response<Body>> {
        if !self.cache_config.honor_cache_control || !cached.has_validators() {
            return None;
        }

        let cond_req = Self::build_conditional_request(req, cached)?;
        let domain = Self::extract_domain(url);
        let upstream_start = Instant::now();

        let response = match self.http_client.request(cond_req).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Revalidation upstream error for {}: {}", url, e);
                self.metrics
                    .record_upstream_error(domain.as_str(), "revalidate");
                return None;
            }
        };

        let upstream_duration = upstream_start.elapsed().as_secs_f64();
        let status = response.status();
        self.metrics
            .record_upstream_request(domain.as_str(), StatusLabel::new(status.as_u16()).as_str());
        self.metrics
            .record_upstream_duration(&domain, upstream_duration);

        if status == StatusCode::NOT_MODIFIED {
            let headers_map = Self::headers_map_from_response(&response);
            let Some(refreshed) = refresh_cache_response(
                cached,
                headers_map,
                method,
                &RequestCacheContext::from_headers(req.headers()),
                &self.cache_config,
            ) else {
                // An origin may withdraw permission to share a previously
                // cached representation. Do not serve it or leave it in L2.
                self.http_cache.remove(cache_key);
                if let Some(l2) = &self.l2_cache {
                    l2.delete(cache_key).await;
                }
                return None;
            };
            self.store_in_l1_and_l2(cache_key.clone(), refreshed.clone());
            debug!("Cache REVALIDATED (304): {} {}", method, url);
            let user_agent = Self::request_header(req, "user-agent");
            return Some(self.serve_l1_hit(
                &refreshed,
                cache_key,
                url,
                method,
                user_id,
                username,
                user_agent,
                client_ip,
                categories,
                threat_sources,
                request_start,
                detailed_metrics,
                guard,
                fast_scope,
                "REVALIDATED",
                "REVALIDATED",
            ));
        }

        // Changed response: consume body and fall through to normal miss handling upstream.
        let _ = http_body_util::BodyExt::collect(response.into_body()).await;
        None
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn try_serve_cache_before_policy(
        &self,
        req: &Request<Incoming>,
        cache_key: &Arc<str>,
        url: &str,
        method: &str,
        client_ip: &str,
        request_start: Instant,
        detailed_metrics: bool,
        guard: &mut Option<RequestMetricsGuard>,
        fast_scope: &mut Option<FastRequestScope>,
    ) -> Option<Response<Body>> {
        let no_user: Option<String> = None;
        let no_cats: Vec<String> = Vec::new();
        let no_threats: Vec<String> = Vec::new();
        // Borrowed: `req` outlives every use below, so the fast path does not
        // copy the User-Agent just to hand it to an event builder.
        let user_agent = Self::request_header(req, "user-agent");
        let cache_lookup_start = Instant::now();

        if let Some(cached) = self.http_cache.get(cache_key) {
            if detailed_metrics {
                self.metrics
                    .cache_lookup_duration_seconds
                    .observe(cache_lookup_start.elapsed().as_secs_f64());
            }
            if cached.can_serve_fresh() {
                let (label, x_status) = if cached.is_negative {
                    ("NEGATIVE_HIT", "NEGATIVE-HIT")
                } else {
                    ("HIT", "HIT")
                };
                debug!(
                    "Cache {} (fast path, skip policy): {} {}",
                    label, method, url
                );
                return Some(self.serve_l1_hit(
                    &cached,
                    cache_key,
                    url,
                    method,
                    &no_user,
                    &no_user,
                    user_agent,
                    client_ip,
                    &no_cats,
                    &no_threats,
                    request_start,
                    detailed_metrics,
                    guard,
                    fast_scope,
                    label,
                    x_status,
                ));
            }
            if let Some(resp) = self
                .try_revalidate_stale(
                    &cached,
                    req,
                    cache_key,
                    url,
                    method,
                    &no_user,
                    &no_user,
                    client_ip,
                    &no_cats,
                    &no_threats,
                    request_start,
                    detailed_metrics,
                    guard,
                    fast_scope,
                )
                .await
            {
                return Some(resp);
            }
        }

        if let Some(cached) = self.try_l2_cache_get(cache_key).await {
            debug!("Cache L2 HIT (fast path, skip policy): {} {}", method, url);
            self.http_cache.insert(cache_key.clone(), cached.clone());
            let hit_label = if cached.is_negative {
                "NEGATIVE_HIT"
            } else {
                "L2_HIT"
            };
            let x_status = if cached.is_negative {
                "NEGATIVE-HIT"
            } else {
                "L2-HIT"
            };
            if let Some(g) = guard.as_mut() {
                g.set_cache_status(hit_label);
                self.metrics.cache_hits_total.inc();
            }
            if detailed_metrics {
                self.emit_cache_hit_event(
                    url,
                    method,
                    cache_key,
                    hit_label,
                    &cached,
                    &no_user,
                    &no_user,
                    user_agent,
                    client_ip,
                    &no_cats,
                    &no_threats,
                    request_start,
                );
            }
            let response = cached.to_response_with_cache_status(x_status);
            let body_size = cached.response_body_len();
            if let Some(g) = guard.take() {
                g.finish(cached.status, 0, body_size);
            } else if let Some(scope) = fast_scope.take() {
                scope.finish_cache_hit();
            }
            return Some(response);
        }

        None
    }
}

/// Apply 304 metadata through the same privacy gate as a newly fetched body.
fn refresh_cache_response(
    cached: &CachedResponse,
    updated_headers: HashMap<String, String>,
    method: &str,
    request: &RequestCacheContext,
    config: &CacheConfig,
) -> Option<CachedResponse> {
    let mut headers: HashMap<String, String> = cached
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
        .collect();
    headers.extend(updated_headers);
    let decision = evaluate_store(
        method,
        cached.status,
        &headers,
        cached.response_body_len(),
        request,
        config,
    );
    if !decision.store {
        return None;
    }
    let mut refreshed = cached.refreshed_after_not_modified(decision.ttl);
    refreshed.headers = headers
        .into_iter()
        .map(|(name, value)| (Arc::from(name), Arc::from(value)))
        .collect();
    refreshed.must_revalidate = decision.must_revalidate;
    refreshed.etag = decision.etag;
    refreshed.last_modified = decision.last_modified;
    Some(refreshed)
}

#[cfg(test)]
mod revalidation_privacy_tests {
    use super::*;

    fn cached() -> CachedResponse {
        CachedResponse::from_upstream(
            200,
            vec![
                (Arc::from("cache-control"), Arc::from("public, max-age=60")),
                (Arc::from("etag"), Arc::from("v1")),
            ]
            .into(),
            Bytes::from_static(b"body"),
            Duration::from_secs(60),
            &crate::cache_compress::CompressionConfig::default(),
            usize::MAX,
            &std::env::temp_dir(),
            Some(Arc::from("v1")),
            None,
            false,
            false,
        )
    }

    #[test]
    fn revalidation_cannot_restore_private_or_varied_content() {
        for (name, value) in [
            ("cache-control", "private, max-age=60"),
            ("cache-control", "no-store, max-age=60"),
            ("vary", "Cookie, Accept-Encoding"),
            ("vary", "*"),
            ("set-cookie", "sid=1"),
        ] {
            let updated = HashMap::from([(name.to_string(), value.to_string())]);
            assert!(
                refresh_cache_response(
                    &cached(),
                    updated,
                    "GET",
                    &RequestCacheContext::default(),
                    &CacheConfig::default()
                )
                .is_none(),
                "{name}: {value}"
            );
        }
    }

    #[test]
    fn benign_revalidation_preserves_and_updates_policy_metadata() {
        let updated = HashMap::from([(
            "cache-control".to_string(),
            "public, no-cache, max-age=120".to_string(),
        )]);
        let refreshed = refresh_cache_response(
            &cached(),
            updated,
            "GET",
            &RequestCacheContext::default(),
            &CacheConfig::default(),
        )
        .unwrap();
        assert_eq!(refreshed.ttl, Duration::from_secs(120));
        assert!(refreshed.must_revalidate);
        assert_eq!(refreshed.etag.as_deref(), Some("v1"));
        let again = refresh_cache_response(
            &refreshed,
            HashMap::new(),
            "GET",
            &RequestCacheContext::default(),
            &CacheConfig::default(),
        )
        .unwrap();
        assert!(again.must_revalidate);
        assert_eq!(again.ttl, Duration::from_secs(120));
    }
}
