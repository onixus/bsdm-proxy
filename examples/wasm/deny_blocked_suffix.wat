;; BSDM-Proxy Wasm PoC (#188) — deny URLs containing ".blocked.test"
;; Host imports: bsdm.url_contains / set_request_header / deny
;; Export: on_request, memory
;;
;; Build/run:
;;   cargo build -p bsdm-proxy --features wasm --bin proxy
;;   WASM_ENABLED=true WASM_MODULE_PATH=examples/wasm/deny_blocked_suffix.wat \
;;     cargo run -p bsdm-proxy --features wasm --bin proxy

(module
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
