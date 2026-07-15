-- Migration: session correlation columns for existing ClickHouse volumes.
-- Safe to re-run (IF NOT EXISTS).

ALTER TABLE bsdm.http_cache
    ADD COLUMN IF NOT EXISTS session_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS parent_event_id Nullable(String),
    ADD COLUMN IF NOT EXISTS redirect_url Nullable(String);
