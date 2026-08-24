use crate::pac::generate_pac;
use crate::router::{RouteRule, RouteTable};
use crate::tunnel::{tunnel_down, tunnel_status, tunnel_up};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct UiServerState {
    pub routes: Arc<RwLock<RouteTable>>,
    pub routes_path: PathBuf,
    pub conf_path: PathBuf,
    pub control_url: String,
    pub proxy_authority: String,
    pub tunnel_active: Arc<RwLock<bool>>,
    pub device_id: String,
}

pub async fn run_ui_server(
    bind_addr: SocketAddr,
    state: Arc<UiServerState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "🌐 BSDM Agent Web/Mobile UI & PAC server listening");

    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("UI server accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let req_str = String::from_utf8_lossy(&buf[..n]);
            let (method, path) = parse_request_line(&req_str);

            let body_offset = req_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
            let body_bytes = &buf[body_offset..n];

            let response = handle_request(&method, &path, body_bytes, &state).await;

            let _ = socket.write_all(&response).await;
            let _ = socket.flush().await;
        });
    }
}

fn parse_request_line(req: &str) -> (String, String) {
    if let Some(first_line) = req.lines().next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            return (parts[0].to_uppercase(), parts[1].to_string());
        }
    }
    ("GET".to_string(), "/".to_string())
}

async fn handle_request(
    method: &str,
    path: &str,
    body: &[u8],
    state: &Arc<UiServerState>,
) -> Vec<u8> {
    let clean_path = path.split('?').next().unwrap_or(path);

    match (method, clean_path) {
        ("GET", "/") | ("GET", "/index.html") => {
            let html = render_agent_ui_html();
            http_response(200, "text/html; charset=utf-8", html.as_bytes())
        }
        ("GET", "/proxy.pac") => {
            let routes = state.routes.read().await;
            let pac = generate_pac(&routes, &state.proxy_authority, None);
            http_response(200, "application/x-ns-proxy-autoconfig", pac.as_bytes())
        }
        ("GET", "/api/status") => {
            let tunnel_is_active = *state.tunnel_active.read().await;
            let telemetry = tunnel_status("awg0");
            let routes = state.routes.read().await;
            let payload = serde_json::json!({
                "status": "ok",
                "device_id": state.device_id,
                "control_url": state.control_url,
                "proxy_authority": state.proxy_authority,
                "tunnel_active": tunnel_is_active || telemetry.active,
                "telemetry": telemetry,
                "route_count": routes.rules.len(),
                "default_target": routes.default_target,
            });
            json_response(200, &payload.to_string())
        }
        ("POST", "/api/tunnel/toggle") => {
            let mut active_lock = state.tunnel_active.write().await;
            let current = *active_lock;
            let res = if current {
                match tunnel_down(&state.conf_path, false) {
                    Ok(msg) => {
                        *active_lock = false;
                        serde_json::json!({"active": false, "message": msg})
                    }
                    Err(e) => serde_json::json!({"error": e}),
                }
            } else {
                match tunnel_up(&state.conf_path, false) {
                    Ok(msg) => {
                        *active_lock = true;
                        serde_json::json!({"active": true, "message": msg})
                    }
                    Err(e) => serde_json::json!({"error": e}),
                }
            };
            json_response(200, &res.to_string())
        }
        ("GET", "/api/routes") => {
            let routes = state.routes.read().await;
            let payload = serde_json::to_string(&*routes).unwrap_or_else(|_| "{}".to_string());
            json_response(200, &payload)
        }
        ("POST", "/api/routes") => match serde_json::from_slice::<RouteRule>(body) {
            Ok(rule) => {
                let mut routes = state.routes.write().await;
                routes.upsert_rule(rule);
                let _ = routes.save(&state.routes_path);
                json_response(200, r#"{"status":"saved"}"#)
            }
            Err(e) => json_response(400, &format!(r#"{{"error":"{e}"}}"#)),
        },
        ("DELETE", p) if p.starts_with("/api/routes/") => {
            let id = p.trim_start_matches("/api/routes/");
            let mut routes = state.routes.write().await;
            let removed = routes.remove_rule(id);
            if removed {
                let _ = routes.save(&state.routes_path);
                json_response(200, r#"{"status":"deleted"}"#)
            } else {
                json_response(404, r#"{"error":"rule not found"}"#)
            }
        }
        ("POST", "/api/system-proxy/toggle") => {
            #[derive(serde::Deserialize)]
            struct ProxyToggleReq {
                mode: String, // "pac", "global", "off"
            }
            if let Ok(req) = serde_json::from_slice::<ProxyToggleReq>(body) {
                let msg = match req.mode.as_str() {
                    "pac" => {
                        let pac_url = "http://127.0.0.1:8765/proxy.pac";
                        crate::system_proxy::set_auto_proxy(pac_url, false)
                    }
                    "global" => {
                        let ep = crate::system_proxy::ProxyEndpoint::from_env();
                        crate::system_proxy::set_system_proxy(&ep, false)
                    }
                    _ => crate::system_proxy::clear_system_proxy(false),
                };
                match msg {
                    Ok(m) => json_response(
                        200,
                        &serde_json::json!({"status": "ok", "message": m}).to_string(),
                    ),
                    Err(e) => json_response(500, &serde_json::json!({"error": e}).to_string()),
                }
            } else {
                json_response(400, r#"{"error":"invalid request"}"#)
            }
        }
        _ => http_response(404, "text/plain", b"Not Found"),
    }
}

fn http_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn json_response(status: u16, json: &str) -> Vec<u8> {
    http_response(status, "application/json", json.as_bytes())
}

/// Render lightweight responsive Single-Page Application HTML (macOS and Android adaptive)
pub fn render_agent_ui_html() -> String {
    r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
<title>BSDM Connect — Управление туннелем и маршрутами</title>
<style>
:root {
  --bg: #0d1117;
  --card-bg: rgba(22, 27, 34, 0.85);
  --border: #30363d;
  --text: #f0f6fc;
  --text-muted: #8b949e;
  --primary: #2f81f7;
  --primary-glow: rgba(47, 129, 247, 0.25);
  --success: #238636;
  --success-glow: rgba(35, 134, 54, 0.3);
  --danger: #da3633;
  --warning: #d29922;
  --radius: 16px;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
body { background: var(--bg); color: var(--text); padding-bottom: 70px; -webkit-font-smoothing: antialiased; }
.container { max-width: 680px; margin: 0 auto; padding: 16px; }

/* Header */
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; padding-top: 8px; }
.header h1 { font-size: 20px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
.badge { background: #21262d; border: 1px solid var(--border); padding: 4px 8px; border-radius: 20px; font-size: 12px; color: var(--text-muted); }

/* Glass Cards */
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 16px; backdrop-filter: blur(12px); box-shadow: 0 4px 20px rgba(0,0,0,0.3); }

/* Connection Status Card */
.connection-hero { text-align: center; padding: 32px 16px; }
.toggle-btn { width: 100px; height: 100px; border-radius: 50%; border: 3px solid var(--border); background: #21262d; color: var(--text); cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); display: inline-flex; align-items: center; justify-content: center; font-size: 32px; box-shadow: 0 0 0 0 var(--success-glow); }
.toggle-btn.connected { background: var(--success); border-color: #3fb950; box-shadow: 0 0 25px var(--success-glow); }
.status-title { font-size: 18px; font-weight: 600; margin-top: 16px; }
.status-subtitle { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

/* Metrics Row */
.metrics-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 16px; }
.metric-box { background: #161b22; border: 1px solid var(--border); border-radius: 12px; padding: 12px; text-align: center; }
.metric-val { font-size: 16px; font-weight: 700; color: var(--text); }
.metric-lbl { font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-top: 2px; }

/* Steering Mode Switcher */
.mode-tabs { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; background: #161b22; padding: 4px; border-radius: 12px; border: 1px solid var(--border); margin-top: 12px; }
.mode-tab { padding: 8px 4px; text-align: center; font-size: 12px; font-weight: 600; border-radius: 8px; cursor: pointer; border: none; background: transparent; color: var(--text-muted); transition: 0.2s; }
.mode-tab.active { background: var(--primary); color: #fff; box-shadow: 0 2px 8px var(--primary-glow); }

/* Routing Rules List */
.rules-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.rules-title { font-size: 15px; font-weight: 600; }
.btn-sm { background: #21262d; border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 8px; font-size: 12px; cursor: pointer; }
.btn-sm:hover { background: #30363d; }
.rule-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid var(--border); }
.rule-item:last-child { border-bottom: none; }
.rule-pattern { font-family: monospace; font-size: 13px; font-weight: 600; color: var(--text); }
.rule-comment { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
.target-tag { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 3px 8px; border-radius: 6px; }
.target-direct { background: rgba(139, 148, 158, 0.2); color: #8b949e; }
.target-proxy { background: rgba(47, 129, 247, 0.2); color: #58a6ff; }
.target-tunnel { background: rgba(35, 134, 54, 0.2); color: #3fb950; }
.target-block { background: rgba(218, 54, 51, 0.2); color: #f85149; }

/* Modal */
.modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); align-items: center; justify-content: center; z-index: 100; }
.modal-content { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; width: 90%; max-width: 440px; }
.form-group { margin-bottom: 14px; }
.form-label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
.form-input, .form-select { width: 100%; background: #161b22; border: 1px solid var(--border); border-radius: 8px; padding: 10px; color: var(--text); font-size: 14px; }
.form-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; }
.btn-primary { background: var(--primary); color: #fff; border: none; padding: 10px 16px; border-radius: 8px; font-weight: 600; cursor: pointer; }

/* Mobile Bottom Navigation */
.bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; height: 60px; background: rgba(22, 27, 34, 0.95); border-top: 1px solid var(--border); display: flex; justify-content: space-around; align-items: center; backdrop-filter: blur(16px); }
.nav-tab { color: var(--text-muted); text-decoration: none; font-size: 11px; text-align: center; flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px; }
.nav-tab.active { color: var(--primary); }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ BSDM Connect</h1>
    <span id="deviceBadge" class="badge">dev-loading</span>
  </div>

  <!-- Hero Connection Card -->
  <div class="card connection-hero">
    <button id="toggleBtn" class="toggle-btn" onclick="toggleTunnel()">⚡</button>
    <div id="statusTitle" class="status-title">Проверка состояния...</div>
    <div id="statusSubtitle" class="status-subtitle">AmneziaWG Obfuscated Tunnel</div>

    <div class="metrics-row">
      <div class="metric-box">
        <div id="rxVal" class="metric-val">0 KB</div>
        <div class="metric-lbl">Принято (RX)</div>
      </div>
      <div class="metric-box">
        <div id="txVal" class="metric-val">0 KB</div>
        <div class="metric-lbl">Отправлено (TX)</div>
      </div>
      <div class="metric-box">
        <div id="handshakeVal" class="metric-val">—</div>
        <div class="metric-lbl">Handshake</div>
      </div>
    </div>
  </div>

  <!-- Steering / Split Routing Mode -->
  <div class="card">
    <div class="rules-header">
      <span class="rules-title">Режим маршрутизации трафика</span>
      <span class="badge" id="pacLink"><a href="/proxy.pac" target="_blank" style="color:var(--primary);text-decoration:none;">PAC файл</a></span>
    </div>
    <div class="mode-tabs">
      <button id="modePac" class="mode-tab active" onclick="setMode('pac')">Smart (PAC)</button>
      <button id="modeGlobal" class="mode-tab" onclick="setMode('global')">Global Proxy</button>
      <button id="modeOff" class="mode-tab" onclick="setMode('off')">Прямой доступ</button>
    </div>
  </div>

  <!-- Domain Routes List -->
  <div class="card">
    <div class="rules-header">
      <span class="rules-title">Правила маршрутизации по доменам</span>
      <button class="btn-sm" onclick="openAddRuleModal()">+ Добавить</button>
    </div>
    <div id="rulesList">
      <div style="text-align:center;padding:16px;color:var(--text-muted);">Загрузка правил...</div>
    </div>
  </div>
</div>

<!-- Add/Edit Rule Modal -->
<div id="ruleModal" class="modal">
  <div class="modal-content">
    <h3 style="font-size:16px;margin-bottom:16px;">Добавить правило для домена</h3>
    <div class="form-group">
      <label class="form-label">Шаблон домена (wildcard, через точку с запятой):</label>
      <input id="rulePattern" class="form-input" placeholder="*.corp.com; internal.net"/>
    </div>
    <div class="form-group">
      <label class="form-label">Маршрут / Действие:</label>
      <select id="ruleTarget" class="form-select">
        <option value="direct">Direct (Напрямую)</option>
        <option value="proxy" selected>BSDM Proxy (Корпоративный прокси)</option>
        <option value="tunnel">Amnezia Tunnel (VPN шифрование)</option>
        <option value="block">Block (Локальная блокировка)</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Примечание (опционально):</label>
      <input id="ruleComment" class="form-input" placeholder="Корпоративный интранет"/>
    </div>
    <div class="form-actions">
      <button class="btn-sm" onclick="closeModal()">Отмена</button>
      <button class="btn-primary" onclick="saveRule()">Сохранить</button>
    </div>
  </div>
</div>

<script>
let currentStatus = null;
let currentRoutes = [];

async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    currentStatus = data;
    
    document.getElementById('deviceBadge').textContent = data.device_id || 'online';
    const btn = document.getElementById('toggleBtn');
    const title = document.getElementById('statusTitle');
    const sub = document.getElementById('statusSubtitle');
    
    if (data.tunnel_active) {
      btn.className = 'toggle-btn connected';
      title.textContent = 'Подключено';
      title.style.color = '#3fb950';
      sub.textContent = data.telemetry?.endpoint ? `Endpoint: ${data.telemetry.endpoint}` : 'AmneziaWG Active';
    } else {
      btn.className = 'toggle-btn';
      title.textContent = 'Отключено';
      title.style.color = 'var(--text)';
      sub.textContent = 'AmneziaWG Standby';
    }
    
    const rx = data.telemetry?.rx_bytes || 0;
    const tx = data.telemetry?.tx_bytes || 0;
    document.getElementById('rxVal').textContent = formatBytes(rx);
    document.getElementById('txVal').textContent = formatBytes(tx);
    
    const hs = data.telemetry?.latest_handshake_secs || 0;
    if (hs > 0) {
      const now = Math.floor(Date.now() / 1000);
      document.getElementById('handshakeVal').textContent = (now - hs) + 's';
    } else {
      document.getElementById('handshakeVal').textContent = '—';
    }
  } catch(e) {
    console.error(e);
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function toggleTunnel() {
  try {
    const res = await fetch('/api/tunnel/toggle', { method: 'POST' });
    await refreshStatus();
  } catch(e) {
    alert('Ошибка переключения: ' + e);
  }
}

async function setMode(mode) {
  document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
  if (mode === 'pac') document.getElementById('modePac').classList.add('active');
  if (mode === 'global') document.getElementById('modeGlobal').classList.add('active');
  if (mode === 'off') document.getElementById('modeOff').classList.add('active');
  
  await fetch('/api/system-proxy/toggle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode })
  });
}

async function loadRoutes() {
  try {
    const res = await fetch('/api/routes');
    const data = await res.json();
    currentRoutes = data.rules || [];
    renderRoutes();
  } catch(e) {
    console.error(e);
  }
}

function renderRoutes() {
  const container = document.getElementById('rulesList');
  if (currentRoutes.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-muted);">Нет настроенных правил</div>';
    return;
  }
  
  container.innerHTML = currentRoutes.map(r => `
    <div class="rule-item">
      <div>
        <div class="rule-pattern">${escapeHtml(r.pattern)}</div>
        <div class="rule-comment">${escapeHtml(r.comment || 'Правило маршрутизации')}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <span class="target-tag target-${r.target}">${r.target}</span>
        <button class="btn-sm" style="color:var(--danger);border-color:transparent;" onclick="deleteRule('${r.id}')">✕</button>
      </div>
    </div>
  `).join('');
}

function openAddRuleModal() {
  document.getElementById('rulePattern').value = '';
  document.getElementById('ruleComment').value = '';
  document.getElementById('ruleModal').style.display = 'flex';
}

function closeModal() {
  document.getElementById('ruleModal').style.display = 'none';
}

async function saveRule() {
  const pattern = document.getElementById('rulePattern').value.trim();
  const target = document.getElementById('ruleTarget').value;
  const comment = document.getElementById('ruleComment').value.trim();
  if (!pattern) return alert('Укажите шаблон домена');
  
  const id = 'rule-' + Math.random().toString(36).substring(2, 9);
  await fetch('/api/routes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, pattern, target, enabled: true, comment: comment || null })
  });
  
  closeModal();
  await loadRoutes();
}

async function deleteRule(id) {
  if (!confirm('Удалить правило?')) return;
  await fetch('/api/routes/' + id, { method: 'DELETE' });
  await loadRoutes();
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

refreshStatus();
loadRoutes();
setInterval(refreshStatus, 3000);
</script>
</body>
</html>
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::RouteTarget;

    #[tokio::test]
    async fn test_ui_server_status_and_routes_api() {
        let routes = Arc::new(RwLock::new(RouteTable::default_corporate()));
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state = Arc::new(UiServerState {
            routes: routes.clone(),
            routes_path: tmp.path().to_path_buf(),
            conf_path: tmp.path().to_path_buf(),
            control_url: "http://127.0.0.1:9090".to_string(),
            proxy_authority: "127.0.0.1:3128".to_string(),
            tunnel_active: Arc::new(RwLock::new(false)),
            device_id: "test-dev-01".to_string(),
        });

        // Test GET /
        let res_html = handle_request("GET", "/", b"", &state).await;
        assert!(String::from_utf8_lossy(&res_html).contains("BSDM Connect"));

        // Test GET /proxy.pac
        let res_pac = handle_request("GET", "/proxy.pac", b"", &state).await;
        assert!(String::from_utf8_lossy(&res_pac).contains("FindProxyForURL"));

        // Test GET /api/status
        let res_status = handle_request("GET", "/api/status", b"", &state).await;
        assert!(String::from_utf8_lossy(&res_status).contains("test-dev-01"));

        // Test POST /api/routes
        let new_rule = serde_json::json!({
            "id": "test-rule-custom",
            "pattern": "*.testdomain.internal",
            "target": "proxy",
            "enabled": true,
            "comment": "Custom test rule"
        });
        let res_post = handle_request(
            "POST",
            "/api/routes",
            new_rule.to_string().as_bytes(),
            &state,
        )
        .await;
        assert!(String::from_utf8_lossy(&res_post).contains("saved"));

        let current_routes = routes.read().await;
        assert_eq!(
            current_routes.evaluate("sub.testdomain.internal"),
            RouteTarget::Proxy
        );
    }
}
