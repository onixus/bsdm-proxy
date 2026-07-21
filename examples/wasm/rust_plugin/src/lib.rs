use bsdm_wasm_sdk::{
    deny_request, get_req_header, get_res_status, set_req_header, set_res_header,
};

#[no_mangle]
pub extern "C" fn on_request() -> i32 {
    // Example: Block specific user-agent
    if let Some(ua) = get_req_header("user-agent") {
        if ua.contains("BadBot") {
            deny_request("Blocked by BadBot WASM filter");
            return 0; // 0 = denied
        }
    }

    // Example: Add a custom header to the outgoing request
    set_req_header("X-Wasm-Processed", "true");
    
    1 // 1 = allowed
}

#[no_mangle]
pub extern "C" fn on_response() -> i32 {
    let status = get_res_status().unwrap_or(0);
    
    // Example: Set custom header unconditionally
    set_res_header("X-Wasm-Response-Hook", "active");

    if status == 404 {
        set_res_header("X-Wasm-Oops", "not-found");
    }
    
    1 // Return value ignored by host for on_response currently
}
