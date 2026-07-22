//! Optional Wasmtime request hook host (Cargo feature `wasm`).
//!
//! Guest ABI (imports from module `bsdm`):
//! - `url_contains(ptr, len) -> i32` — 1 if request URL contains UTF-8 needle
//! - `method_eq(ptr, len) -> i32` — 1 if method equals needle (case-insensitive)
//! - `set_request_header(name_ptr, name_len, val_ptr, val_len)` — queue header rewrite
//! - `deny(reason_ptr, reason_len)` — mark request denied
//!
//! Guest must export `on_request` (no params / no results) and `memory`.
//!
//! Security: fuel-limited; no WASI FS/net. Fail-open/closed via `WASM_FAIL_OPEN`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

#[derive(Debug, Clone)]
pub struct WasmHookConfig {
    pub enabled: bool,
    pub module_path: Option<String>,
    pub fuel: u64,
    pub fail_open: bool,
}

impl WasmHookConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("WASM_ENABLED")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let module_path = std::env::var("WASM_MODULE_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let fuel = std::env::var("WASM_FUEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50_000);
        let fail_open = std::env::var("WASM_FAIL_OPEN")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);
        Self {
            enabled,
            module_path,
            fuel: fuel.max(1),
            fail_open,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WasmHookRequest {
    pub method: String,
    pub url: String,
    pub client_ip: String,
    pub username: Option<String>,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct WasmHookResponseContext {
    pub status: u16,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum WasmHookDecision {
    Allow {
        set_headers: HashMap<String, String>,
    },
    Deny {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub enum WasmHookResponseDecision {
    Continue {
        set_headers: HashMap<String, String>,
    },
}

struct HostState {
    request: WasmHookRequest,
    response: Option<WasmHookResponseContext>,
    denied: bool,
    deny_reason: String,
    set_headers: HashMap<String, String>,
    set_res_headers: HashMap<String, String>,
    limits: StoreLimits,
}

/// Compiled Wasm hook module + engine.
#[derive(Clone)]
pub struct WasmHookEngine {
    engine: Engine,
    module: Module,
    fuel: u64,
    fail_open: bool,
}

impl WasmHookEngine {
    pub fn from_config(cfg: &WasmHookConfig) -> Result<Option<Self>, String> {
        if !cfg.enabled {
            return Ok(None);
        }
        let path = cfg
            .module_path
            .as_deref()
            .ok_or_else(|| "WASM_MODULE_PATH required when WASM_ENABLED=true".to_string())?;
        Self::load_path(path, cfg.fuel, cfg.fail_open).map(Some)
    }

    pub fn load_path(path: &str, fuel: u64, fail_open: bool) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        Self::load_bytes(&bytes, Path::new(path), fuel, fail_open)
    }

    pub fn load_bytes(
        bytes: &[u8],
        label: &Path,
        fuel: u64,
        fail_open: bool,
    ) -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        let engine = Engine::new(&config).map_err(|e| format!("wasm engine: {e}"))?;
        let module =
            if label.extension().and_then(|e| e.to_str()) == Some("wat") || looks_like_wat(bytes) {
                Module::new(&engine, bytes).map_err(|e| format!("compile wat: {e}"))?
            } else {
                Module::new(&engine, bytes).map_err(|e| format!("compile wasm: {e}"))?
            };
        info!(
            "Wasm hook loaded from {} (fuel={fuel}, fail_open={fail_open})",
            label.display()
        );
        Ok(Self {
            engine,
            module,
            fuel: fuel.max(1),
            fail_open,
        })
    }

    pub fn evaluate(&self, request: WasmHookRequest) -> Result<WasmHookDecision, String> {
        let mut linker = Linker::new(&self.engine);
        register_host(&mut linker)?;

        let host = HostState {
            request,
            response: None,
            denied: false,
            deny_reason: String::new(),
            set_headers: HashMap::new(),
            set_res_headers: HashMap::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(16 << 20)
                .instances(1)
                .memories(1)
                .tables(2)
                .build(),
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.fuel)
            .map_err(|e| format!("set fuel: {e}"))?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| format!("instantiate: {e}"))?;
        let on_request = instance
            .get_typed_func::<(), ()>(&mut store, "on_request")
            .map_err(|e| format!("export on_request: {e}"))?;
        on_request
            .call(&mut store, ())
            .map_err(|e| format!("on_request trap: {e}"))?;

        let host = store.into_data();
        if host.denied {
            Ok(WasmHookDecision::Deny {
                reason: if host.deny_reason.is_empty() {
                    "wasm deny".into()
                } else {
                    host.deny_reason
                },
            })
        } else {
            Ok(WasmHookDecision::Allow {
                set_headers: host.set_headers,
            })
        }
    }

    pub fn evaluate_response(
        &self,
        request: WasmHookRequest,
        response: WasmHookResponseContext,
    ) -> Result<WasmHookResponseDecision, String> {
        let mut linker = Linker::new(&self.engine);
        register_host(&mut linker)?;

        let host = HostState {
            request,
            response: Some(response),
            denied: false,
            deny_reason: String::new(),
            set_headers: HashMap::new(),
            set_res_headers: HashMap::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(16 << 20)
                .instances(1)
                .memories(1)
                .tables(2)
                .build(),
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.fuel)
            .map_err(|e| format!("set fuel: {e}"))?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| format!("instantiate: {e}"))?;

        // If the module doesn't export on_response, just return
        if let Ok(on_response) = instance.get_typed_func::<(), ()>(&mut store, "on_response") {
            on_response
                .call(&mut store, ())
                .map_err(|e| format!("on_response trap: {e}"))?;
        }

        let host = store.into_data();
        Ok(WasmHookResponseDecision::Continue {
            set_headers: host.set_res_headers,
        })
    }

    pub fn reload(&mut self) -> Result<(), String> {
        // Read the module bytes again if there's a path
        if let Ok(cfg_path) = std::env::var("WASM_MODULE_PATH") {
            let path = cfg_path.trim();
            if !path.is_empty() {
                let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
                let mut config = Config::new();
                config.consume_fuel(true);
                config.cranelift_opt_level(wasmtime::OptLevel::Speed);
                let engine = Engine::new(&config).map_err(|e| format!("wasm engine: {e}"))?;
                let module = if Path::new(path).extension().and_then(|e| e.to_str()) == Some("wat")
                    || looks_like_wat(&bytes)
                {
                    Module::new(&engine, &bytes).map_err(|e| format!("compile wat: {e}"))?
                } else {
                    Module::new(&engine, &bytes).map_err(|e| format!("compile wasm: {e}"))?
                };
                self.engine = engine;
                self.module = module;
                info!("Wasm hook reloaded from {}", path);
            }
        }
        Ok(())
    }

    pub fn fail_open(&self) -> bool {
        self.fail_open
    }
}

fn looks_like_wat(bytes: &[u8]) -> bool {
    let s = String::from_utf8_lossy(bytes);
    let t = s.trim_start();
    t.starts_with("(module") || t.starts_with(";;")
}

fn read_guest_str(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<String, String> {
    if ptr < 0 || len < 0 {
        return Err("invalid ptr/len".into());
    }
    let mem = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| "missing memory export".to_string())?;
    let data = mem
        .data(caller)
        .get(ptr as usize..(ptr as usize + len as usize))
        .ok_or_else(|| "guest string OOB".to_string())?;
    String::from_utf8(data.to_vec()).map_err(|e| format!("utf8: {e}"))
}

fn write_guest_str(caller: &mut Caller<'_, HostState>, ptr: i32, max_len: i32, val: &str) -> i32 {
    if ptr < 0 || max_len < 0 {
        return -1;
    }
    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(m) => m,
        None => return -1,
    };
    let bytes = val.as_bytes();
    let to_write = bytes.len().min(max_len as usize);
    let data = match mem
        .data_mut(caller)
        .get_mut(ptr as usize..(ptr as usize + to_write))
    {
        Some(d) => d,
        None => return -1,
    };
    data.copy_from_slice(&bytes[..to_write]);
    to_write as i32
}

fn register_host(linker: &mut Linker<HostState>) -> Result<(), String> {
    linker
        .func_wrap(
            "bsdm",
            "url_contains",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                match read_guest_str(&mut caller, ptr, len) {
                    Ok(needle) => {
                        if caller.data().request.url.contains(&needle) {
                            1
                        } else {
                            0
                        }
                    }
                    Err(_) => 0,
                }
            },
        )
        .map_err(|e| format!("link url_contains: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "method_eq",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                match read_guest_str(&mut caller, ptr, len) {
                    Ok(needle) => {
                        if caller
                            .data()
                            .request
                            .method
                            .eq_ignore_ascii_case(needle.trim())
                        {
                            1
                        } else {
                            0
                        }
                    }
                    Err(_) => 0,
                }
            },
        )
        .map_err(|e| format!("link method_eq: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "set_request_header",
            |mut caller: Caller<'_, HostState>, np: i32, nl: i32, vp: i32, vl: i32| {
                let Ok(name) = read_guest_str(&mut caller, np, nl) else {
                    return;
                };
                let Ok(value) = read_guest_str(&mut caller, vp, vl) else {
                    return;
                };
                if !name.is_empty() {
                    caller
                        .data_mut()
                        .set_headers
                        .insert(name.to_ascii_lowercase(), value);
                }
            },
        )
        .map_err(|e| format!("link set_request_header: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "deny",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                let reason = read_guest_str(&mut caller, ptr, len).unwrap_or_default();
                let host = caller.data_mut();
                host.denied = true;
                host.deny_reason = reason;
            },
        )
        .map_err(|e| format!("link deny: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "get_request_header",
            |mut caller: Caller<'_, HostState>, np: i32, nl: i32, optr: i32, omax: i32| -> i32 {
                let Ok(name) = read_guest_str(&mut caller, np, nl) else {
                    return -1;
                };
                let val = caller
                    .data()
                    .request
                    .headers
                    .get(&name.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_default();
                write_guest_str(&mut caller, optr, omax, &val)
            },
        )
        .map_err(|e| format!("link get_request_header: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "get_client_ip",
            |mut caller: Caller<'_, HostState>, optr: i32, omax: i32| -> i32 {
                let val = caller.data().request.client_ip.clone();
                write_guest_str(&mut caller, optr, omax, &val)
            },
        )
        .map_err(|e| format!("link get_client_ip: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "get_username",
            |mut caller: Caller<'_, HostState>, optr: i32, omax: i32| -> i32 {
                let val = caller.data().request.username.clone().unwrap_or_default();
                write_guest_str(&mut caller, optr, omax, &val)
            },
        )
        .map_err(|e| format!("link get_username: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "set_response_header",
            |mut caller: Caller<'_, HostState>, np: i32, nl: i32, vp: i32, vl: i32| {
                let Ok(name) = read_guest_str(&mut caller, np, nl) else {
                    return;
                };
                let Ok(value) = read_guest_str(&mut caller, vp, vl) else {
                    return;
                };
                if !name.is_empty() {
                    caller
                        .data_mut()
                        .set_res_headers
                        .insert(name.to_ascii_lowercase(), value);
                }
            },
        )
        .map_err(|e| format!("link set_response_header: {e}"))?;

    linker
        .func_wrap(
            "bsdm",
            "get_response_status",
            |caller: Caller<'_, HostState>| -> i32 {
                caller
                    .data()
                    .response
                    .as_ref()
                    .map(|r| r.status as i32)
                    .unwrap_or(-1)
            },
        )
        .map_err(|e| format!("link get_response_status: {e}"))?;

    Ok(())
}

/// PoC guest: deny URLs containing `.blocked.test`; else allow and set `x-wasm-hook: allow`.
pub const POC_DENY_SUFFIX_WAT: &str = r#"(module
  (import "bsdm" "url_contains" (func $url_contains (param i32 i32) (result i32)))
  (import "bsdm" "set_request_header" (func $set_header (param i32 i32 i32 i32)))
  (import "bsdm" "deny" (func $deny (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) ".blocked.test")
  (data (i32.const 16) "blocked by wasm PoC")
  (data (i32.const 48) "x-wasm-hook")
  (data (i32.const 64) "allow")
  (func (export "on_request")
    (if (i32.eqz (call $url_contains (i32.const 0) (i32.const 13)))
      (then
        (call $set_header (i32.const 48) (i32.const 11) (i32.const 64) (i32.const 5))
      )
      (else
        (call $deny (i32.const 16) (i32.const 19))
      )
    )
  )
)
"#;

/// Build engine from in-memory WAT (tests / embedded PoC).
pub fn engine_from_wat(wat: &str, fuel: u64, fail_open: bool) -> Result<WasmHookEngine, String> {
    WasmHookEngine::load_bytes(wat.as_bytes(), Path::new("inline.wat"), fuel, fail_open)
}

pub fn try_load_from_env() -> Option<Arc<std::sync::RwLock<WasmHookEngine>>> {
    let cfg = WasmHookConfig::from_env();
    match WasmHookEngine::from_config(&cfg) {
        Ok(Some(eng)) => Some(Arc::new(std::sync::RwLock::new(eng))),
        Ok(None) => None,
        Err(e) => {
            warn!("Wasm hook disabled: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poc_allows_and_sets_header() {
        let eng = engine_from_wat(POC_DENY_SUFFIX_WAT, 100_000, false).unwrap();
        let d = eng
            .evaluate(WasmHookRequest {
                method: "GET".into(),
                url: "https://example.com/ok".into(),
                client_ip: "127.0.0.1".into(),
                username: None,
                headers: HashMap::new(),
            })
            .unwrap();
        match d {
            WasmHookDecision::Allow { set_headers } => {
                assert_eq!(
                    set_headers.get("x-wasm-hook").map(String::as_str),
                    Some("allow")
                );
            }
            WasmHookDecision::Deny { reason } => panic!("unexpected deny: {reason}"),
        }
    }

    #[test]
    fn poc_denies_blocked_suffix() {
        let eng = engine_from_wat(POC_DENY_SUFFIX_WAT, 100_000, false).unwrap();
        let d = eng
            .evaluate(WasmHookRequest {
                method: "GET".into(),
                url: "https://evil.blocked.test/phish".into(),
                client_ip: "10.0.0.1".into(),
                username: Some("alice".into()),
                headers: HashMap::new(),
            })
            .unwrap();
        match d {
            WasmHookDecision::Deny { reason } => {
                assert!(reason.contains("blocked"));
            }
            WasmHookDecision::Allow { .. } => panic!("expected deny"),
        }
    }

    #[test]
    fn fuel_exhaustion_errors() {
        let eng = engine_from_wat(POC_DENY_SUFFIX_WAT, 1, false).unwrap();
        let err = eng
            .evaluate(WasmHookRequest {
                method: "GET".into(),
                url: "https://example.com/".into(),
                client_ip: "127.0.0.1".into(),
                username: None,
                headers: HashMap::new(),
            })
            .unwrap_err();
        assert!(
            err.contains("fuel") || err.contains("trap") || err.contains("on_request"),
            "err={err}"
        );
    }
}
