use super::*;

#[derive(Clone)]
pub(super) struct MissCompletionHandle {
    pub(super) http_cache: Arc<HttpL1Cache>,
    pub(super) cache_config: CacheConfig,
    pub(super) l2_cache: Option<RedisL2Cache>,
    pub(super) hierarchy: Option<Arc<HierarchyManager>>,
    pub(super) metrics: Arc<Metrics>,
    #[cfg(feature = "kafka")]
    pub(super) kafka_pipeline: Option<Arc<KafkaEventPipeline>>,
    pub(super) http_pipeline: Option<Arc<HttpEventPipeline>>,
    pub(super) perf: PerfConfig,
    pub(super) digest_registry: Option<Arc<DigestRegistry>>,
    pub(super) sessions: Arc<SessionCorrelator>,
    pub(super) ti_shadow: Arc<TiShadowMatcher>,
    pub(super) miss_flights: MissFlightMap,
    pub(super) semantic_config: SemanticCacheConfig,
    pub(super) semantic_index: SemanticIndex,
    pub(super) llm_mode: bool,
    pub(super) llm_normalized_body: Option<Bytes>,
}

impl MissCompletionHandle {
    fn store_in_l1_and_l2(&self, cache_key: Arc<str>, cached_response: CachedResponse) {
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

    #[inline]
    fn has_event_sink(&self) -> bool {
        #[cfg(feature = "kafka")]
        if self.kafka_pipeline.is_some() {
            return true;
        }
        self.http_pipeline.is_some()
    }

    fn send_cache_event(&self, mut event: CacheEvent) {
        crate::ti_shadow::annotate_shadow_match(&self.ti_shadow, &self.metrics, &mut event);
        if !self.perf.should_emit_kafka_event() {
            return;
        }
        dispatch_cache_event(
            #[cfg(feature = "kafka")]
            self.kafka_pipeline.as_deref(),
            self.http_pipeline.as_deref(),
            event,
            &self.metrics,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn complete_cache_miss(
        &self,
        cache_key: Arc<str>,
        url: &str,
        method: &str,
        domain: &str,
        status: u16,
        headers_map: &HashMap<String, String>,
        body_bytes: Bytes,
        store_decision: &crate::cache_freshness::CacheStoreDecision,
        stored: bool,
        user_id: Option<String>,
        username: Option<String>,
        user_agent: Option<String>,
        client_ip: &str,
        categories: &[String],
        threat_sources: &[String],
        request_start: Instant,
        request_body_size: usize,
        hierarchy_peer: Option<Arc<CachePeer>>,
        mut guard: Option<RequestMetricsGuard>,
        mut fast_scope: Option<FastRequestScope>,
    ) {
        let body_size = body_bytes.len();

        if let (Some(hierarchy), Some(peer)) = (self.hierarchy.clone(), hierarchy_peer) {
            let bytes = body_size as u64;
            tokio::spawn(async move {
                hierarchy.record_peer_hit(&peer, bytes).await;
            });
        }

        if stored && store_decision.store {
            let headers_arc: Arc<[(Arc<str>, Arc<str>)]> = headers_map
                .iter()
                .map(|(k, v)| (Arc::from(k.as_str()), Arc::from(v.as_str())))
                .collect();

            let cached_response = CachedResponse::from_upstream(
                status,
                headers_arc,
                body_bytes,
                store_decision.ttl,
                &self.cache_config.compression,
                self.cache_config.spill_threshold_bytes,
                &self.cache_config.spill_dir,
                store_decision.etag.clone(),
                store_decision.last_modified.clone(),
                store_decision.is_negative,
                store_decision.must_revalidate,
            );
            self.store_in_l1_and_l2(cache_key.clone(), cached_response.clone());
            if self.llm_mode {
                if let Some(norm) = &self.llm_normalized_body {
                    let index = self.semantic_index.clone();
                    let cfg = self.semantic_config.clone();
                    let metrics = self.metrics.clone();
                    let key = cache_key.clone();
                    let text = extract_embed_text(norm);
                    tokio::spawn(async move {
                        match cfg.embed(&text).await {
                            Ok(emb) => {
                                if let Err(e) = index.insert(emb, key).await {
                                    metrics.semantic_cache_vector_errors_total.inc();
                                    warn!("semantic index insert failed: {e}");
                                }
                            }
                            Err(e) => {
                                metrics.semantic_cache_vector_errors_total.inc();
                                warn!("semantic embed failed: {e}");
                            }
                        }
                    });
                }
            }
            self.miss_flights
                .complete(&cache_key, Some(cached_response));
            if let Some(g) = guard.as_mut() {
                g.set_cache_status(if store_decision.is_negative {
                    "NEGATIVE_MISS"
                } else if self.llm_mode {
                    "LLM_MISS"
                } else {
                    "MISS"
                });
            }
        } else {
            self.miss_flights.complete(&cache_key, None);
            self.metrics.cache_bypasses_total.inc();
            if let Some(g) = guard.as_mut() {
                g.set_cache_status("BYPASS");
            }
        }

        let cache_status = if stored && store_decision.store {
            if store_decision.is_negative {
                "NEGATIVE_MISS"
            } else if self.llm_mode {
                "LLM_MISS"
            } else {
                "MISS"
            }
        } else {
            "BYPASS"
        };

        if self.has_event_sink() {
            if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                let event_id = new_event_id();
                let redirect_url =
                    header_ci(headers_map, "location").map(|loc| resolve_location(url, loc));
                let corr = self.sessions.begin_request(
                    client_ip,
                    username.as_deref(),
                    user_agent.as_deref(),
                    url,
                );
                self.sessions.note_redirect(
                    client_ip,
                    &event_id,
                    status,
                    url,
                    redirect_url.as_deref(),
                );
                let event = CacheEvent {
                    url: url.to_string(),
                    method: method.to_string(),
                    status,
                    cache_key: cache_key.to_string(),
                    cache_status: cache_status.to_string(),
                    timestamp: timestamp.as_secs(),
                    headers: headers_map.clone(),
                    user_id,
                    username,
                    client_ip: client_ip.to_string(),
                    domain: domain.to_string(),
                    response_size: body_size as u64,
                    request_duration_ms: request_start.elapsed().as_millis() as u64,
                    content_type: headers_map
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone()),
                    user_agent,
                    categories: categories.to_vec(),
                    threat_sources: threat_sources.to_vec(),
                    acl_action: None,
                    acl_rule_id: None,
                    acl_reason: None,
                    session_id: corr.session_id,
                    parent_event_id: corr.parent_event_id,
                    redirect_url,
                    dlp_violation: None,
                    casb_alert: None,
                    decision_source: Some(request_decision_source(url).to_string()),
                    bypass_reason: None,
                    threat_shadow_match: None,
                    event_id,
                };
                self.send_cache_event(event);
            }
        }

        ProxyService::finish_request_metrics(
            &mut guard,
            &mut fast_scope,
            status,
            request_body_size,
            body_size,
        );
    }
}

impl ProxyService {
    pub(super) fn miss_completion_handle(&self) -> MissCompletionHandle {
        self.miss_completion_handle_inner(false, None)
    }

    pub(super) fn miss_completion_handle_llm(
        &self,
        normalized_body: Bytes,
    ) -> MissCompletionHandle {
        self.miss_completion_handle_inner(true, Some(normalized_body))
    }

    fn miss_completion_handle_inner(
        &self,
        llm_mode: bool,
        llm_normalized_body: Option<Bytes>,
    ) -> MissCompletionHandle {
        MissCompletionHandle {
            http_cache: self.http_cache.clone(),
            cache_config: self.cache_config.clone(),
            l2_cache: self.l2_cache.clone(),
            hierarchy: self.hierarchy.clone(),
            metrics: self.metrics.clone(),
            #[cfg(feature = "kafka")]
            kafka_pipeline: self.kafka_pipeline.clone(),
            http_pipeline: self.http_pipeline.clone(),
            perf: self.perf.clone(),
            digest_registry: self.digest_registry.clone(),
            sessions: self.sessions.clone(),
            ti_shadow: self.ti_shadow.clone(),
            miss_flights: self.miss_flights.clone(),
            semantic_config: self.semantic_config.clone(),
            semantic_index: self.semantic_index.clone(),
            llm_mode,
            llm_normalized_body,
        }
    }
}
