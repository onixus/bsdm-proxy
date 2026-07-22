//! BSDM Proxy Wasm SDK
//!
//! Provides ergonomic Rust wrappers around the `bsdm` host ABI.

use std::ffi::{CStr, c_char};
use std::slice;

// -----------------------------------------------------------------------------
// Raw Host ABI
// -----------------------------------------------------------------------------

#[link(wasm_import_module = "bsdm")]
unsafe extern "C" {
    fn url_contains(ptr: *const u8, len: usize) -> i32;
    fn method_eq(ptr: *const u8, len: usize) -> i32;
    fn set_request_header(nptr: *const u8, nlen: usize, vptr: *const u8, vlen: usize);
    fn deny(ptr: *const u8, len: usize);
    fn get_request_header(nptr: *const u8, nlen: usize, optr: *mut u8, omaxlen: usize) -> i32;
    fn get_client_ip(optr: *mut u8, omaxlen: usize) -> i32;
    fn get_username(optr: *mut u8, omaxlen: usize) -> i32;
    fn set_response_header(nptr: *const u8, nlen: usize, vptr: *const u8, vlen: usize);
    fn get_response_status() -> i32;
}

// -----------------------------------------------------------------------------
// Ergonomic API
// -----------------------------------------------------------------------------

/// Returns true if the request URL contains the given substring.
pub fn request_url_contains(needle: &str) -> bool {
    unsafe { url_contains(needle.as_ptr(), needle.len()) == 1 }
}

/// Returns true if the request method equals the given string (case-insensitive).
pub fn request_method_eq(method: &str) -> bool {
    unsafe { method_eq(method.as_ptr(), method.len()) == 1 }
}

/// Queues a request header to be set (overwritten) if the request is allowed.
pub fn set_req_header(name: &str, value: &str) {
    unsafe {
        set_request_header(name.as_ptr(), name.len(), value.as_ptr(), value.len());
    }
}

/// Queues a response header to be set (overwritten) on the final response.
/// Only takes effect if called during the `on_response` hook.
pub fn set_res_header(name: &str, value: &str) {
    unsafe {
        set_response_header(name.as_ptr(), name.len(), value.as_ptr(), value.len());
    }
}

/// Denies the request with the specified reason.
pub fn deny_request(reason: &str) {
    unsafe {
        deny(reason.as_ptr(), reason.len());
    }
}

/// Helper to read a string from the host into a newly allocated String.
fn host_read_str<F>(reader: F) -> Option<String>
where
    F: FnOnce(*mut u8, usize) -> i32,
{
    let mut buf = vec![0u8; 1024]; // Maximum expected length
    let written = reader(buf.as_mut_ptr(), buf.len());
    if written < 0 {
        return None; // Not found or error
    }
    let len = written as usize;
    if len > buf.len() {
        return None; // Truncated (should handle dynamically, but 1024 is usually enough)
    }
    buf.truncate(len);
    String::from_utf8(buf).ok()
}

/// Retrieves the value of a specific request header by name.
pub fn get_req_header(name: &str) -> Option<String> {
    host_read_str(|out_ptr, max_len| unsafe {
        get_request_header(name.as_ptr(), name.len(), out_ptr, max_len)
    })
}

/// Retrieves the client IP address.
pub fn get_client_ip_addr() -> Option<String> {
    host_read_str(|out_ptr, max_len| unsafe { get_client_ip(out_ptr, max_len) })
}

/// Retrieves the username (if authenticated).
pub fn get_authenticated_username() -> Option<String> {
    host_read_str(|out_ptr, max_len| unsafe { get_username(out_ptr, max_len) })
}

/// Retrieves the HTTP response status code.
/// Only valid during the `on_response` hook.
pub fn get_res_status() -> Option<u16> {
    let status = unsafe { get_response_status() };
    if status > 0 {
        Some(status as u16)
    } else {
        None
    }
}
