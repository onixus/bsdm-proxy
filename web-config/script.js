// BSDM-Proxy web config generator

function el(id) {
    return document.getElementById(id);
}

function val(id, fallback = '') {
    const node = el(id);
    return node ? node.value : fallback;
}

function checked(id) {
    const node = el(id);
    return node ? node.checked : false;
}

function setChecked(id, on) {
    const node = el(id);
    if (node) node.checked = !!on;
}

function setVal(id, value) {
    const node = el(id);
    if (node) node.value = value;
}

function truthyEnv(v) {
    return ['1', 'true', 'yes', 'on'].includes(String(v).trim().toLowerCase());
}

function toggleSection(checkboxId, sectionId) {
    const cb = el(checkboxId);
    const section = el(sectionId);
    if (!cb || !section) return;
    const update = () => {
        section.style.display = cb.checked ? 'block' : 'none';
    };
    cb.addEventListener('change', update);
    update();
}

function initTabs() {
    document.querySelectorAll('.tab').forEach((tab) => {
        tab.addEventListener('click', () => {
            const target = tab.getAttribute('data-tab');
            document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach((tc) => tc.classList.remove('active'));
            tab.classList.add('active');
            const panel = el(target);
            if (panel) panel.classList.add('active');
        });
    });
}

function updateCacheStats() {
    const stats = el('cache_stats');
    const cap = parseInt(val('cache_capacity', '10000'), 10) || 10000;
    const memoryMB = ((cap * 120) / 1024 / 1024).toFixed(2);
    if (stats) {
        stats.textContent = `${cap.toLocaleString()} entries ≈ ${memoryMB} MB metadata`;
    }
}

function updateAuthBackendPanels() {
    const backend = val('auth_backend', 'basic');
    const ldap = el('ldap_settings');
    const ntlm = el('ntlm_settings');
    if (ldap) ldap.style.display = backend === 'ldap' ? 'block' : 'none';
    if (ntlm) ntlm.style.display = backend === 'ntlm' ? 'block' : 'none';
}

function collectConfig() {
    const maxBodyMb = parseInt(val('max_body_size', '10'), 10) || 10;
    const spillKb = parseInt(val('spill_threshold', '256'), 10) || 0;

    const config = {
        HTTP_PORT: val('http_port', '1488'),
        METRICS_PORT: val('metrics_port', '9090'),
        RUST_LOG: val('log_level', 'info,bsdm_proxy=info'),
        SHUTDOWN_TIMEOUT_SECONDS: val('shutdown_timeout', '30'),
        MAX_CACHE_BODY_SIZE: String(maxBodyMb * 1024 * 1024),
        MITM_ENABLED: String(checked('mitm_enabled')),

        CACHE_CAPACITY: val('cache_capacity', '10000'),
        CACHE_TTL_SECONDS: val('cache_ttl', '3600'),
        CACHE_SHARDS: val('cache_shards', '16'),
        CACHE_HONOR_CACHE_CONTROL: String(checked('cache_honor_cache_control')),
        NEGATIVE_CACHE_ENABLED: String(checked('negative_cache_enabled')),
        NEGATIVE_CACHE_TTL_SECONDS: val('negative_cache_ttl', '120'),
        CACHE_SPILL_THRESHOLD_BYTES: String(spillKb * 1024),

        WORKER_COUNT: val('worker_count', '1'),
        PERF_FAST_CACHE_HIT: String(checked('perf_fast_cache_hit')),
        STREAMING_MISS_ENABLED: String(checked('streaming_miss_enabled')),
        KAFKA_SAMPLE_RATE: val('kafka_sample_rate', '0'),
        METRICS_SAMPLE_RATE: val('metrics_sample_rate', '0'),
        KAFKA_QUEUE_CAPACITY: val('kafka_queue_capacity', '8192'),

        KAFKA_BROKERS: val('kafka_brokers', 'kafka:9092'),
        KAFKA_TOPIC: val('kafka_topic', 'cache-events'),
        KAFKA_ACKS: val('kafka_acks', '1'),
        KAFKA_BATCH_SIZE: val('kafka_batch_size', '100'),
        KAFKA_BATCH_TIMEOUT: val('kafka_batch_timeout', '5000'),

        AUTH_ENABLED: String(checked('auth_enabled')),
        AUTH_BACKEND: val('auth_backend', 'basic'),
        AUTH_REALM: val('auth_realm', 'BSDM-Proxy'),
        AUTH_CACHE_TTL: val('auth_cache_ttl', '300'),

        ACL_ENABLED: String(checked('acl_enabled')),
        ACL_DEFAULT_ACTION: val('acl_default_action', 'allow'),
        ACL_RULES_PATH: val('acl_rules_path', '/etc/bsdm-proxy/acl-rules.json'),
        ACL_AUTO_RELOAD: String(checked('acl_auto_reload')),
        ACL_RELOAD_INTERVAL: val('acl_reload_interval', '60'),

        CATEGORIZATION_ENABLED: String(checked('categorization_enabled')),
        CATEGORIZATION_CACHE_TTL: val('categorization_cache_ttl', '3600'),
        UT1_ENABLED: String(checked('ut1_enabled')),
        UT1_PATH: val('ut1_path', '/var/lib/ut1-blacklists'),
        URLHAUS_ENABLED: String(checked('urlhaus_enabled')),
        URLHAUS_API: val('urlhaus_api', ''),
        PHISHTANK_ENABLED: String(checked('phishtank_enabled')),
        PHISHTANK_API: val('phishtank_api', ''),
        PHISHTANK_API_KEY: val('phishtank_api_key', ''),
        CUSTOM_DB_ENABLED: String(checked('custom_db_enabled')),
        CUSTOM_DB_PATH: val('custom_db_path', ''),

        CLICKHOUSE_URL: val('clickhouse_url', 'http://clickhouse:8123'),
        CLICKHOUSE_DATABASE: val('clickhouse_database', 'bsdm'),
        CLICKHOUSE_TABLE: val('clickhouse_table', 'http_cache'),

        PROMETHEUS_ENABLED: String(checked('prometheus_enabled')),
        GRAFANA_ENABLED: String(checked('grafana_enabled')),
    };

    if (checked('auth_enabled') && val('auth_backend') === 'ldap') {
        Object.assign(config, {
            LDAP_SERVERS: val('ldap_servers'),
            LDAP_BASE_DN: val('ldap_base_dn'),
            LDAP_BIND_DN: val('ldap_bind_dn'),
            LDAP_BIND_PASSWORD: val('ldap_bind_password'),
            LDAP_USER_FILTER: val('ldap_user_filter'),
            LDAP_USE_TLS: String(checked('ldap_use_tls')),
        });
    }

    if (checked('auth_enabled') && val('auth_backend') === 'ntlm') {
        Object.assign(config, {
            NTLM_DOMAIN: val('ntlm_domain'),
            NTLM_WORKSTATION: val('ntlm_workstation'),
        });
    }

    if (checked('redis_l2_enabled')) {
        Object.assign(config, {
            REDIS_L2_ENABLED: 'true',
            REDIS_URL: val('redis_url', 'redis://redis:6379'),
            REDIS_KEY_PREFIX: val('redis_key_prefix', 'bsdm:http:'),
        });
    }

    const apiToken = val('acl_api_token');
    if (apiToken) config.ACL_API_TOKEN = apiToken;

    const searchToken = val('search_api_token');
    if (searchToken) config.SEARCH_API_TOKEN = searchToken;

    return config;
}

function generateAclRules() {
    if (!checked('acl_enabled')) return null;

    const rules = [];
    let priority = 100;

    const addCategory = (id, name, category, enabled) => {
        if (!enabled) return;
        rules.push({
            id,
            name,
            enabled: true,
            priority: priority++,
            action: 'deny',
            rule_type: { Category: category },
            redirect_url: null,
            comment: null,
        });
    };

    addCategory('block-malware', 'Block malware URLs', 'malware', checked('acl_block_malware'));
    addCategory('block-phishing', 'Block phishing URLs', 'phishing', checked('acl_block_phishing'));
    addCategory('block-adult', 'Block adult content', 'adult', checked('acl_block_adult'));
    addCategory('block-gambling', 'Block gambling sites', 'gambling', checked('acl_block_gambling'));

    return {
        default_action: val('acl_default_action', 'allow'),
        rules,
    };
}

function formatEnv(config) {
    const lines = [
        '# Generated by BSDM-Proxy web-config',
        '# See packaging/config/bsdm-proxy.env.example for full reference',
        '',
    ];

    const order = [
        'HTTP_PORT', 'METRICS_PORT', 'MITM_ENABLED', 'SHUTDOWN_TIMEOUT_SECONDS', 'RUST_LOG',
        'CACHE_CAPACITY', 'CACHE_TTL_SECONDS', 'MAX_CACHE_BODY_SIZE', 'CACHE_SHARDS',
        'CACHE_HONOR_CACHE_CONTROL', 'NEGATIVE_CACHE_ENABLED', 'NEGATIVE_CACHE_TTL_SECONDS',
        'CACHE_SPILL_THRESHOLD_BYTES',
        'REDIS_L2_ENABLED', 'REDIS_URL', 'REDIS_KEY_PREFIX',
        'WORKER_COUNT', 'PERF_FAST_CACHE_HIT', 'STREAMING_MISS_ENABLED',
        'KAFKA_SAMPLE_RATE', 'METRICS_SAMPLE_RATE', 'KAFKA_QUEUE_CAPACITY',
        'KAFKA_BROKERS', 'KAFKA_TOPIC', 'KAFKA_ACKS',
        'AUTH_ENABLED', 'AUTH_BACKEND', 'AUTH_REALM', 'AUTH_CACHE_TTL',
        'LDAP_SERVERS', 'LDAP_BASE_DN', 'LDAP_BIND_DN', 'LDAP_BIND_PASSWORD',
        'LDAP_USER_FILTER', 'LDAP_USE_TLS',
        'NTLM_DOMAIN', 'NTLM_WORKSTATION',
        'ACL_ENABLED', 'ACL_DEFAULT_ACTION', 'ACL_RULES_PATH', 'ACL_AUTO_RELOAD',
        'ACL_RELOAD_INTERVAL', 'ACL_API_TOKEN',
        'CATEGORIZATION_ENABLED', 'CATEGORIZATION_CACHE_TTL',
        'UT1_ENABLED', 'UT1_PATH', 'URLHAUS_ENABLED', 'URLHAUS_API',
        'PHISHTANK_ENABLED', 'PHISHTANK_API', 'PHISHTANK_API_KEY', 'CUSTOM_DB_ENABLED', 'CUSTOM_DB_PATH',
    ];

    const written = new Set();
    for (const key of order) {
        if (config[key] !== undefined && config[key] !== '') {
            lines.push(`${key}=${config[key]}`);
            written.add(key);
        }
    }
    for (const [key, value] of Object.entries(config)) {
        if (!written.has(key) && value !== '') {
            lines.push(`${key}=${value}`);
        }
    }

    return lines.join('\n') + '\n';
}

function proxyEnvBlock(config) {
    const keys = [
        'HTTP_PORT', 'METRICS_PORT', 'RUST_LOG', 'MITM_ENABLED', 'SHUTDOWN_TIMEOUT_SECONDS',
        'CACHE_CAPACITY', 'CACHE_TTL_SECONDS', 'MAX_CACHE_BODY_SIZE', 'CACHE_SHARDS',
        'CACHE_HONOR_CACHE_CONTROL', 'NEGATIVE_CACHE_ENABLED', 'NEGATIVE_CACHE_TTL_SECONDS',
        'CACHE_SPILL_THRESHOLD_BYTES', 'REDIS_L2_ENABLED', 'REDIS_URL', 'REDIS_KEY_PREFIX',
        'WORKER_COUNT', 'PERF_FAST_CACHE_HIT', 'STREAMING_MISS_ENABLED',
        'KAFKA_SAMPLE_RATE', 'METRICS_SAMPLE_RATE', 'KAFKA_QUEUE_CAPACITY',
        'KAFKA_BROKERS', 'KAFKA_TOPIC', 'KAFKA_ACKS',
        'AUTH_ENABLED', 'AUTH_BACKEND', 'AUTH_REALM', 'AUTH_CACHE_TTL',
        'LDAP_SERVERS', 'LDAP_BASE_DN', 'LDAP_BIND_DN', 'LDAP_BIND_PASSWORD',
        'LDAP_USER_FILTER', 'LDAP_USE_TLS', 'NTLM_DOMAIN', 'NTLM_WORKSTATION',
        'ACL_ENABLED', 'ACL_DEFAULT_ACTION', 'ACL_RULES_PATH', 'ACL_AUTO_RELOAD',
        'ACL_RELOAD_INTERVAL', 'ACL_API_TOKEN',
        'CATEGORIZATION_ENABLED', 'CATEGORIZATION_CACHE_TTL', 'UT1_ENABLED', 'UT1_PATH',
        'URLHAUS_ENABLED', 'URLHAUS_API', 'PHISHTANK_ENABLED', 'PHISHTANK_API', 'PHISHTANK_API_KEY',
        'CUSTOM_DB_ENABLED', 'CUSTOM_DB_PATH',
    ];
    return keys
        .filter((k) => config[k] !== undefined && config[k] !== '')
        .map((k) => `      - ${k}=${config[k]}`)
        .join('\n');
}

function generateDockerCompose(config) {
    const prom = config.PROMETHEUS_ENABLED === 'true';
    const graf = config.GRAFANA_ENABLED === 'true';

    return `services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.9.8
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    networks: [bsdm-net]
    restart: unless-stopped

  kafka:
    image: confluentinc/cp-kafka:7.9.8
    depends_on: [zookeeper]
    ports: ["9092:9092"]
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
    networks: [bsdm-net]
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "kafka-broker-api-versions --bootstrap-server localhost:9092 >/dev/null 2>&1"]
      interval: 10s
      timeout: 10s
      retries: 12
      start_period: 30s

  clickhouse:
    image: clickhouse/clickhouse-server:24.12
    ports: ["8123:8123", "9000:9000"]
    environment:
      CLICKHOUSE_DB: ${config.CLICKHOUSE_DATABASE}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
    volumes:
      - clickhouse-data:/var/lib/clickhouse
      - ./scripts/clickhouse/http_cache.sql:/docker-entrypoint-initdb.d/01-http_cache.sql:ro
    networks: [bsdm-net]
    restart: unless-stopped
${prom ? `
  prometheus:
    image: prom/prometheus:v2.55.1
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    ports: ["9091:9090"]
    networks: [bsdm-net]
    restart: unless-stopped
` : ''}${graf ? `
  grafana:
    image: grafana/grafana:11.4.0
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_AUTH_ANONYMOUS_ENABLED: "false"
    volumes:
      - ./grafana/datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml:ro
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    ports: ["3000:3000"]
    depends_on: [prometheus]
    networks: [bsdm-net]
    restart: unless-stopped
` : ''}
  proxy:
    build:
      context: .
      dockerfile: Dockerfile
      target: proxy
    ports:
      - "${config.HTTP_PORT}:${config.HTTP_PORT}"
      - "${config.METRICS_PORT}:${config.METRICS_PORT}"
    environment:
${proxyEnvBlock(config)}
    volumes:
      - ./certs:/certs:ro
${config.ACL_ENABLED === 'true' ? `      - ./acl-rules.json:${config.ACL_RULES_PATH}:ro\n` : ''}${config.UT1_ENABLED === 'true' ? `      - ${config.UT1_PATH}:${config.UT1_PATH}:ro\n` : ''}${config.CUSTOM_DB_ENABLED === 'true' ? `      - ./custom-categories.json:${config.CUSTOM_DB_PATH}:ro\n` : ''}    depends_on:
      kafka:
        condition: service_healthy
    networks: [bsdm-net]
    restart: unless-stopped

  cache-indexer:
    build:
      context: .
      dockerfile: Dockerfile
      target: cache-indexer
    environment:
      - KAFKA_BROKERS=${config.KAFKA_BROKERS}
      - KAFKA_TOPIC=${config.KAFKA_TOPIC}
      - KAFKA_BATCH_SIZE=${config.KAFKA_BATCH_SIZE}
      - KAFKA_BATCH_TIMEOUT=${config.KAFKA_BATCH_TIMEOUT}
      - CLICKHOUSE_URL=${config.CLICKHOUSE_URL}
      - CLICKHOUSE_DATABASE=${config.CLICKHOUSE_DATABASE}
      - CLICKHOUSE_TABLE=${config.CLICKHOUSE_TABLE}
${config.SEARCH_API_TOKEN ? `      - SEARCH_API_TOKEN=${config.SEARCH_API_TOKEN}\n` : ''}    depends_on: [kafka, clickhouse]
    networks: [bsdm-net]
    restart: unless-stopped

volumes:
  clickhouse-data:

networks:
  bsdm-net:
    driver: bridge
`;
}

function generateConfig() {
    showModal('bsdm-proxy.env', formatEnv(collectConfig()));
}

function exportEnv() {
    downloadFile('bsdm-proxy.env', formatEnv(collectConfig()));
}

function exportDockerCompose() {
    downloadFile('docker-compose.yml', generateDockerCompose(collectConfig()));
}

function exportAclRules() {
    const rules = generateAclRules();
    if (!rules) {
        alert('Enable ACL first');
        return;
    }
    downloadFile('acl-rules.json', JSON.stringify(rules, null, 2) + '\n');
}

function importEnvFile(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => applyEnvText(String(reader.result || ''));
    reader.readAsText(file);
    event.target.value = '';
}

function applyEnvText(text) {
    const map = {};
    for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq < 1) continue;
        map[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
    }

    if (map.HTTP_PORT) setVal('http_port', map.HTTP_PORT);
    if (map.METRICS_PORT) setVal('metrics_port', map.METRICS_PORT);
    if (map.RUST_LOG) setVal('log_level', map.RUST_LOG);
    if (map.SHUTDOWN_TIMEOUT_SECONDS) setVal('shutdown_timeout', map.SHUTDOWN_TIMEOUT_SECONDS);
    if (map.MAX_CACHE_BODY_SIZE) {
        setVal('max_body_size', String(Math.round(parseInt(map.MAX_CACHE_BODY_SIZE, 10) / 1024 / 1024)));
    }
    setChecked('mitm_enabled', truthyEnv(map.MITM_ENABLED));

    if (map.CACHE_CAPACITY) setVal('cache_capacity', map.CACHE_CAPACITY);
    if (map.CACHE_TTL_SECONDS) setVal('cache_ttl', map.CACHE_TTL_SECONDS);
    if (map.CACHE_SHARDS) setVal('cache_shards', map.CACHE_SHARDS);
    setChecked('cache_honor_cache_control', map.CACHE_HONOR_CACHE_CONTROL !== 'false');
    setChecked('negative_cache_enabled', truthyEnv(map.NEGATIVE_CACHE_ENABLED));
    if (map.NEGATIVE_CACHE_TTL_SECONDS) setVal('negative_cache_ttl', map.NEGATIVE_CACHE_TTL_SECONDS);
    if (map.CACHE_SPILL_THRESHOLD_BYTES) {
        setVal('spill_threshold', String(Math.round(parseInt(map.CACHE_SPILL_THRESHOLD_BYTES, 10) / 1024)));
    }
    setChecked('redis_l2_enabled', truthyEnv(map.REDIS_L2_ENABLED));
    if (map.REDIS_URL) setVal('redis_url', map.REDIS_URL);
    if (map.REDIS_KEY_PREFIX) setVal('redis_key_prefix', map.REDIS_KEY_PREFIX);

    if (map.WORKER_COUNT) setVal('worker_count', map.WORKER_COUNT);
    setChecked('perf_fast_cache_hit', truthyEnv(map.PERF_FAST_CACHE_HIT));
    setChecked('streaming_miss_enabled', map.STREAMING_MISS_ENABLED !== 'false');
    if (map.KAFKA_SAMPLE_RATE) setVal('kafka_sample_rate', map.KAFKA_SAMPLE_RATE);
    if (map.METRICS_SAMPLE_RATE) setVal('metrics_sample_rate', map.METRICS_SAMPLE_RATE);
    if (map.KAFKA_QUEUE_CAPACITY) setVal('kafka_queue_capacity', map.KAFKA_QUEUE_CAPACITY);

    if (map.KAFKA_BROKERS) setVal('kafka_brokers', map.KAFKA_BROKERS);
    if (map.KAFKA_TOPIC) setVal('kafka_topic', map.KAFKA_TOPIC);
    if (map.KAFKA_ACKS) setVal('kafka_acks', map.KAFKA_ACKS);
    if (map.KAFKA_BATCH_SIZE) setVal('kafka_batch_size', map.KAFKA_BATCH_SIZE);
    if (map.KAFKA_BATCH_TIMEOUT) setVal('kafka_batch_timeout', map.KAFKA_BATCH_TIMEOUT);

    setChecked('auth_enabled', truthyEnv(map.AUTH_ENABLED));
    if (map.AUTH_BACKEND) setVal('auth_backend', map.AUTH_BACKEND);
    if (map.AUTH_REALM) setVal('auth_realm', map.AUTH_REALM);
    if (map.AUTH_CACHE_TTL) setVal('auth_cache_ttl', map.AUTH_CACHE_TTL);
    if (map.LDAP_SERVERS) setVal('ldap_servers', map.LDAP_SERVERS);
    if (map.LDAP_BASE_DN) setVal('ldap_base_dn', map.LDAP_BASE_DN);
    if (map.LDAP_BIND_DN) setVal('ldap_bind_dn', map.LDAP_BIND_DN);
    if (map.LDAP_BIND_PASSWORD) setVal('ldap_bind_password', map.LDAP_BIND_PASSWORD);
    if (map.LDAP_USER_FILTER) setVal('ldap_user_filter', map.LDAP_USER_FILTER);
    setChecked('ldap_use_tls', map.LDAP_USE_TLS !== 'false');
    if (map.NTLM_DOMAIN) setVal('ntlm_domain', map.NTLM_DOMAIN);
    if (map.NTLM_WORKSTATION) setVal('ntlm_workstation', map.NTLM_WORKSTATION);

    setChecked('acl_enabled', truthyEnv(map.ACL_ENABLED));
    if (map.ACL_DEFAULT_ACTION) setVal('acl_default_action', map.ACL_DEFAULT_ACTION);
    if (map.ACL_RULES_PATH) setVal('acl_rules_path', map.ACL_RULES_PATH);
    setChecked('acl_auto_reload', truthyEnv(map.ACL_AUTO_RELOAD));
    if (map.ACL_RELOAD_INTERVAL) setVal('acl_reload_interval', map.ACL_RELOAD_INTERVAL);
    if (map.ACL_API_TOKEN) setVal('acl_api_token', map.ACL_API_TOKEN);

    setChecked('categorization_enabled', truthyEnv(map.CATEGORIZATION_ENABLED));
    if (map.CATEGORIZATION_CACHE_TTL) setVal('categorization_cache_ttl', map.CATEGORIZATION_CACHE_TTL);
    setChecked('ut1_enabled', truthyEnv(map.UT1_ENABLED));
    if (map.UT1_PATH) setVal('ut1_path', map.UT1_PATH);
    setChecked('urlhaus_enabled', truthyEnv(map.URLHAUS_ENABLED));
    if (map.URLHAUS_API) setVal('urlhaus_api', map.URLHAUS_API);
    setChecked('phishtank_enabled', truthyEnv(map.PHISHTANK_ENABLED));
    if (map.PHISHTANK_API) setVal('phishtank_api', map.PHISHTANK_API);
    if (map.PHISHTANK_API_KEY) setVal('phishtank_api_key', map.PHISHTANK_API_KEY);
    setChecked('custom_db_enabled', truthyEnv(map.CUSTOM_DB_ENABLED));
    if (map.CUSTOM_DB_PATH) setVal('custom_db_path', map.CUSTOM_DB_PATH);

    if (map.CLICKHOUSE_URL) setVal('clickhouse_url', map.CLICKHOUSE_URL);
    if (map.CLICKHOUSE_DATABASE) setVal('clickhouse_database', map.CLICKHOUSE_DATABASE);
    if (map.CLICKHOUSE_TABLE) setVal('clickhouse_table', map.CLICKHOUSE_TABLE);
    if (map.SEARCH_API_TOKEN) setVal('search_api_token', map.SEARCH_API_TOKEN);

    updateCacheStats();
    updateAuthBackendPanels();
    el('auth_options').style.display = checked('auth_enabled') ? 'block' : 'none';
    el('acl_options').style.display = checked('acl_enabled') ? 'block' : 'none';
    el('categorization_options').style.display = checked('categorization_enabled') ? 'block' : 'none';
    el('redis_l2_options').style.display = checked('redis_l2_enabled') ? 'block' : 'none';

    alert('Imported ' + Object.keys(map).length + ' variables');
}

function showModal(title, content) {
    el('modal-title').textContent = title;
    el('modal-output').textContent = content;
    el('output-modal').style.display = 'block';
}

function closeModal() {
    el('output-modal').style.display = 'none';
}

function copyToClipboard() {
    const output = el('modal-output').textContent;
    navigator.clipboard.writeText(output).then(() => alert('Copied'));
}

function downloadFile(filename, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

window.onclick = function (event) {
    const modal = el('output-modal');
    if (event.target === modal) closeModal();
};

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    toggleSection('auth_enabled', 'auth_options');
    toggleSection('acl_enabled', 'acl_options');
    toggleSection('categorization_enabled', 'categorization_options');
    toggleSection('redis_l2_enabled', 'redis_l2_options');

    const authBackend = el('auth_backend');
    if (authBackend) {
        authBackend.addEventListener('change', updateAuthBackendPanels);
        updateAuthBackendPanels();
    }

    const cacheCap = el('cache_capacity');
    if (cacheCap) {
        cacheCap.addEventListener('input', updateCacheStats);
        updateCacheStats();
    }
});
