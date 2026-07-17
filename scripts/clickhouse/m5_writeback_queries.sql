-- M5.5 threat score write-back — ad-hoc ClickHouse queries

-- Latest cached scores per entity (dedupe by max score)
SELECT
    entity_type,
    entity_id,
    max(score) AS max_score,
    argMax(severity, score) AS severity,
    argMax(model, score) AS model,
    max(scored_at) AS last_scored_at
FROM bsdm.threat_score_cache
WHERE expires_at > now()
GROUP BY entity_type, entity_id
ORDER BY max_score DESC
LIMIT 50;

-- Active high-severity domain scores
SELECT entity_id, score, severity, model, scored_at, expires_at
FROM bsdm.threat_score_cache
WHERE entity_type = 'domain'
  AND score >= 0.7
  AND expires_at > now()
ORDER BY score DESC
LIMIT 25;
