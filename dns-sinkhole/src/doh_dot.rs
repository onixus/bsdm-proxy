//! DoH (DNS-over-HTTPS, RFC 8484) and DoT (DNS-over-TLS, RFC 7858) helpers.
//!
//! Codec logic for DoH base64url decoding and DoT 2-byte length framing.
#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Decode a base64url query string parameter for DoH GET (`/dns-query?dns=...`).
#[allow(dead_code)]
pub fn decode_doh_base64url(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Empty dns parameter".to_string());
    }

    // Replace standard base64 url-safe chars if padding is present
    let clean = input.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(clean)
        .map_err(|e| format!("Invalid base64url encoding: {e}"))
}

/// Encode DoT 2-byte length-prefixed packet.
#[allow(dead_code)]
pub fn encode_dot_frame(packet: &[u8]) -> Vec<u8> {
    let len = packet.len() as u16;
    let mut frame = Vec::with_capacity(2 + packet.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

/// Decode a 2-byte length prefix from a TCP stream buffer.
#[allow(dead_code)]
pub fn parse_dot_length(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        None
    } else {
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_doh_base64url() {
        // Sample base64url DNS query
        let encoded = "q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAEC";
        let decoded = decode_doh_base64url(encoded).expect("decode base64url");
        assert!(!decoded.is_empty());
        assert_eq!(decoded[0], 0xab);
        assert_eq!(decoded[1], 0xcd);
    }

    #[test]
    fn test_dot_framing() {
        let packet = vec![1, 2, 3, 4, 5];
        let frame = encode_dot_frame(&packet);
        assert_eq!(frame.len(), 7);
        assert_eq!(frame[0], 0);
        assert_eq!(frame[1], 5);
        assert_eq!(parse_dot_length(&frame), Some(5));
    }
}
