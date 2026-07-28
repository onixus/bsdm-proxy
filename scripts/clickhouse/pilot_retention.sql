-- Pilot profile: keep analytics data for no more than five days.
-- Mounted after the base DDL by docker-compose.pilot.yml on a fresh volume.

ALTER TABLE bsdm.http_cache
MODIFY TTL toDateTime(ts) + INTERVAL 5 DAY;

ALTER TABLE bsdm.entity_features
MODIFY TTL toDateTime(window_start) + INTERVAL 5 DAY;

ALTER TABLE bsdm.ml_scores
MODIFY TTL toDateTime(scored_at) + INTERVAL 5 DAY;

ALTER TABLE bsdm.domain_phishing_features
MODIFY TTL toDateTime(window_start) + INTERVAL 5 DAY;

ALTER TABLE bsdm.beacon_pair_features
MODIFY TTL toDateTime(window_start) + INTERVAL 5 DAY;
