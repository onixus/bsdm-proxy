//! Transparent at-rest compression for cached HTTP response bodies.

use bytes::Bytes;
use std::sync::Arc;
use tracing::debug;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BodyEncoding {
    #[default]
    Raw,
    Zstd,
    Brotli,
}

impl BodyEncoding {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "zstd" => Some(Self::Zstd),
            "brotli" => Some(Self::Brotli),
            _ => None,
        }
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Zstd => "zstd",
            Self::Brotli => "brotli",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompressionConfig {
    pub codec: BodyEncoding,
    pub min_bytes: usize,
    pub zstd_level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            codec: BodyEncoding::Raw,
            min_bytes: 1024,
            zstd_level: 3,
        }
    }
}

impl CompressionConfig {
    pub fn from_env() -> Self {
        let codec = std::env::var("CACHE_COMPRESSION")
            .ok()
            .and_then(|v| match v.to_ascii_lowercase().as_str() {
                "zstd" => Some(BodyEncoding::Zstd),
                "brotli" => Some(BodyEncoding::Brotli),
                "off" | "false" | "0" | "" => Some(BodyEncoding::Raw),
                _ => None,
            })
            .unwrap_or(BodyEncoding::Raw);
        let min_bytes = std::env::var("CACHE_COMPRESS_MIN_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024);
        let zstd_level = std::env::var("CACHE_COMPRESS_ZSTD_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);

        Self {
            codec,
            min_bytes,
            zstd_level,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self.codec, BodyEncoding::Raw)
    }
}

pub fn decode_body(body: &Bytes, encoding: BodyEncoding) -> Result<Bytes, String> {
    match encoding {
        BodyEncoding::Raw => Ok(body.clone()),
        BodyEncoding::Zstd => zstd::decode_all(body.as_ref())
            .map(Bytes::from)
            .map_err(|e| format!("zstd decompress failed: {e}")),
        BodyEncoding::Brotli => {
            let mut reader = std::io::Cursor::new(body.as_ref());
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut reader, &mut out)
                .map_err(|e| format!("brotli decompress failed: {e:?}"))?;
            Ok(Bytes::from(out))
        }
    }
}

fn compress_zstd(body: &[u8], level: i32) -> Result<Vec<u8>, String> {
    zstd::encode_all(body, level).map_err(|e| format!("zstd compress failed: {e}"))
}

fn compress_brotli(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    brotli::BrotliCompress(
        &mut std::io::Cursor::new(body),
        &mut out,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .map_err(|e| format!("brotli compress failed: {e:?}"))?;
    Ok(out)
}

fn has_content_encoding(headers: &[(Arc<str>, Arc<str>)]) -> bool {
    headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
}

fn strip_length_headers(headers: &[(Arc<str>, Arc<str>)]) -> Arc<[(Arc<str>, Arc<str>)]> {
    headers
        .iter()
        .filter(|(k, _)| {
            !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("content-encoding")
        })
        .cloned()
        .collect()
}

#[derive(Clone, Debug)]
pub struct PreparedCacheBody {
    pub body: Bytes,
    pub headers: Arc<[(Arc<str>, Arc<str>)]>,
    pub encoding: BodyEncoding,
    pub uncompressed_len: usize,
}

/// Compress body for cache storage when configured.
pub fn prepare_body_for_cache(
    body: Bytes,
    headers: Arc<[(Arc<str>, Arc<str>)]>,
    config: &CompressionConfig,
) -> PreparedCacheBody {
    let uncompressed_len = body.len();

    if !config.is_enabled()
        || body.len() < config.min_bytes
        || has_content_encoding(headers.as_ref())
    {
        return PreparedCacheBody {
            body,
            headers,
            encoding: BodyEncoding::Raw,
            uncompressed_len,
        };
    }

    let compressed = match config.codec {
        BodyEncoding::Raw => {
            return PreparedCacheBody {
                body,
                headers,
                encoding: BodyEncoding::Raw,
                uncompressed_len,
            };
        }
        BodyEncoding::Zstd => match compress_zstd(body.as_ref(), config.zstd_level) {
            Ok(v) => v,
            Err(e) => {
                debug!("cache compression skipped: {e}");
                return PreparedCacheBody {
                    body,
                    headers,
                    encoding: BodyEncoding::Raw,
                    uncompressed_len,
                };
            }
        },
        BodyEncoding::Brotli => match compress_brotli(body.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                debug!("cache compression skipped: {e}");
                return PreparedCacheBody {
                    body,
                    headers,
                    encoding: BodyEncoding::Raw,
                    uncompressed_len,
                };
            }
        },
    };

    if compressed.len() >= body.len() {
        return PreparedCacheBody {
            body,
            headers,
            encoding: BodyEncoding::Raw,
            uncompressed_len,
        };
    }

    debug!(
        "cache body compressed {:?}: {} -> {} bytes",
        config.codec,
        body.len(),
        compressed.len()
    );

    PreparedCacheBody {
        body: Bytes::from(compressed),
        headers: strip_length_headers(headers.as_ref()),
        encoding: config.codec,
        uncompressed_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> Bytes {
        Bytes::from("x".repeat(2048))
    }

    #[test]
    fn compression_config_defaults_off() {
        std::env::remove_var("CACHE_COMPRESSION");
        let cfg = CompressionConfig::from_env();
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn compression_config_parses_zstd() {
        std::env::set_var("CACHE_COMPRESSION", "zstd");
        let cfg = CompressionConfig::from_env();
        assert_eq!(cfg.codec, BodyEncoding::Zstd);
        std::env::remove_var("CACHE_COMPRESSION");
    }

    #[test]
    fn zstd_roundtrip() {
        let body = sample_body();
        let headers: Arc<[(Arc<str>, Arc<str>)]> =
            Arc::from([(Arc::from("content-type"), Arc::from("text/plain"))]);
        let config = CompressionConfig {
            codec: BodyEncoding::Zstd,
            min_bytes: 512,
            zstd_level: 3,
        };
        let prepared = prepare_body_for_cache(body.clone(), headers, &config);
        assert_eq!(prepared.encoding, BodyEncoding::Zstd);
        assert!(prepared.body.len() < body.len());
        assert_eq!(prepared.uncompressed_len, body.len());
        let decoded = decode_body(&prepared.body, prepared.encoding).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn brotli_roundtrip() {
        let body = sample_body();
        let headers: Arc<[(Arc<str>, Arc<str>)]> = Arc::from([]);
        let config = CompressionConfig {
            codec: BodyEncoding::Brotli,
            min_bytes: 512,
            zstd_level: 3,
        };
        let prepared = prepare_body_for_cache(body.clone(), headers, &config);
        assert_eq!(prepared.encoding, BodyEncoding::Brotli);
        let decoded = decode_body(&prepared.body, prepared.encoding).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn skips_already_encoded_responses() {
        let body = sample_body();
        let headers: Arc<[(Arc<str>, Arc<str>)]> =
            Arc::from([(Arc::from("content-encoding"), Arc::from("gzip"))]);
        let config = CompressionConfig {
            codec: BodyEncoding::Zstd,
            min_bytes: 512,
            zstd_level: 3,
        };
        let prepared = prepare_body_for_cache(body, headers, &config);
        assert_eq!(prepared.encoding, BodyEncoding::Raw);
    }
}
