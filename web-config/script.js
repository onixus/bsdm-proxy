// Tab switching
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const target = tab.getAttribute('data-tab');
        
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(tc => tc.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(target).classList.add('active');
    });
});

// Authentication toggle
const authEnabled = document.getElementById('auth_enabled');
const authOptions = document.getElementById('auth_options');
const authBackend = document.getElementById('auth_backend');
const ldapSettings = document.getElementById('ldap_settings');
const ntlmSettings = document.getElementById('ntlm_settings');

authEnabled.addEventListener('change', () => {
    authOptions.style.display = authEnabled.checked ? 'block' : 'none';
});

authBackend.addEventListener('change', () => {
    ldapSettings.style.display = authBackend.value === 'ldap' ? 'block' : 'none';
    ntlmSettings.style.display = authBackend.value === 'ntlm' ? 'block' : 'none';
});

// Cache statistics
const cacheCapacity = document.getElementById('cache_capacity');
const cacheStats = document.getElementById('cache_stats');

cacheCapacity.addEventListener('input', () => {
    const entries = parseInt(cacheCapacity.value) || 10000;
    const memoryMB = (entries * 120 / 1024 / 1024).toFixed(2);
    cacheStats.textContent = `${entries.toLocaleString()} entries ≈ ${memoryMB} MB memory`;
});

// Generate configuration
function generateConfig() {
    const config = collectConfig();
    const output = formatConfig(config);
    showModal('Environment Variables', output);
}

// Collect configuration from form
function collectConfig() {
    return {
        // General
        HTTP_PORT: document.getElementById('http_port').value,
        METRICS_PORT: document.getElementById('metrics_port').value,
        RUST_LOG: document.getElementById('log_level').value,
        MAX_CACHE_BODY_SIZE: (parseInt(document.getElementById('max_body_size').value) * 1024 * 1024).toString(),
        
        // Cache
        CACHE_CAPACITY: document.getElementById('cache_capacity').value,
        CACHE_TTL_SECONDS: document.getElementById('cache_ttl').value,
        
        // Kafka
        KAFKA_BROKERS: document.getElementById('kafka_brokers').value,
        KAFKA_TOPIC: document.getElementById('kafka_topic').value,
        KAFKA_BATCH_SIZE: document.getElementById('kafka_batch_size').value,
        KAFKA_BATCH_TIMEOUT: document.getElementById('kafka_batch_timeout').value,
        
        // Authentication
        AUTH_ENABLED: document.getElementById('auth_enabled').checked.toString(),
        AUTH_BACKEND: document.getElementById('auth_backend').value,
        AUTH_REALM: document.getElementById('auth_realm').value,
        AUTH_CACHE_TTL: document.getElementById('auth_cache_ttl').value,
        
        // LDAP (if enabled)
        ...(document.getElementById('auth_backend').value === 'ldap' && document.getElementById('auth_enabled').checked ? {
            LDAP_SERVERS: document.getElementById('ldap_servers').value,
            LDAP_BASE_DN: document.getElementById('ldap_base_dn').value,
            LDAP_BIND_DN: document.getElementById('ldap_bind_dn').value,
            LDAP_BIND_PASSWORD: document.getElementById('ldap_bind_password').value,
            LDAP_USER_FILTER: document.getElementById('ldap_user_filter').value,
            LDAP_USE_TLS: document.getElementById('ldap_use_tls').checked.toString(),
        } : {}),
        
        // NTLM (if enabled)
        ...(document.getElementById('auth_backend').value === 'ntlm' && document.getElementById('auth_enabled').checked ? {
            NTLM_DOMAIN: document.getElementById('ntlm_domain').value,
            NTLM_WORKSTATION: document.getElementById('ntlm_workstation').value,
        } : {}),
        
        // Monitoring
        PROMETHEUS_ENABLED: document.getElementById('prometheus_enabled').checked.toString(),
        GRAFANA_ENABLED: document.getElementById('grafana_enabled').checked.toString(),
        OPENSEARCH_URL: document.getElementById('opensearch_url').value,
    };
}

// Format configuration as environment variables
function formatConfig(config) {
    return Object.entries(config)
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');
}

// Export .env file
function exportEnv() {
    const config = collectConfig();
    const content = formatConfig(config);
    downloadFile('.env', content);
}

// Export docker-compose.yml
function exportDockerCompose() {
    const config = collectConfig();
    const compose = generateDockerCompose(config);
    downloadFile('docker-compose.yml', compose);
}

// Generate docker-compose.yml content
function generateDockerCompose(config) {
    return `version: '3.8'

services:
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    networks:
      - bsdm-network

  kafka:
    image: confluentinc/cp-kafka:latest
    depends_on:
      - zookeeper
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    networks:
      - bsdm-network

  opensearch:
    image: opensearchproject/opensearch:2.3.0
    environment:
      - discovery.type=single-node
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
      - DISABLE_SECURITY_PLUGIN=true
    ports:
      - "9200:9200"
    networks:
      - bsdm-network

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9091:9090"
    networks:
      - bsdm-network

  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=false
    volumes:
      - ./grafana/datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    networks:
      - bsdm-network

  proxy:
    build: ./proxy
    ports:
      - "${config.HTTP_PORT}:${config.HTTP_PORT}"
      - "${config.METRICS_PORT}:${config.METRICS_PORT}"
    environment:
      - HTTP_PORT=${config.HTTP_PORT}
      - METRICS_PORT=${config.METRICS_PORT}
      - RUST_LOG=${config.RUST_LOG}
      - CACHE_CAPACITY=${config.CACHE_CAPACITY}
      - CACHE_TTL_SECONDS=${config.CACHE_TTL_SECONDS}
      - MAX_CACHE_BODY_SIZE=${config.MAX_CACHE_BODY_SIZE}
      - KAFKA_BROKERS=${config.KAFKA_BROKERS}
      - AUTH_ENABLED=${config.AUTH_ENABLED}
${config.AUTH_ENABLED === 'true' ? `      - AUTH_BACKEND=${config.AUTH_BACKEND}
      - AUTH_REALM=${config.AUTH_REALM}
      - AUTH_CACHE_TTL=${config.AUTH_CACHE_TTL}` : ''}
${config.LDAP_SERVERS ? `      - LDAP_SERVERS=${config.LDAP_SERVERS}
      - LDAP_BASE_DN=${config.LDAP_BASE_DN}
      - LDAP_BIND_DN=${config.LDAP_BIND_DN}
      - LDAP_BIND_PASSWORD=${config.LDAP_BIND_PASSWORD}
      - LDAP_USER_FILTER=${config.LDAP_USER_FILTER}
      - LDAP_USE_TLS=${config.LDAP_USE_TLS}` : ''}
${config.NTLM_DOMAIN ? `      - NTLM_DOMAIN=${config.NTLM_DOMAIN}
      - NTLM_WORKSTATION=${config.NTLM_WORKSTATION}` : ''}
    depends_on:
      - kafka
    networks:
      - bsdm-network

  cache-indexer:
    build: ./cache-indexer
    environment:
      - KAFKA_BROKERS=${config.KAFKA_BROKERS}
      - KAFKA_TOPIC=${config.KAFKA_TOPIC}
      - OPENSEARCH_URL=${config.OPENSEARCH_URL}
      - KAFKA_BATCH_SIZE=${config.KAFKA_BATCH_SIZE}
      - KAFKA_BATCH_TIMEOUT=${config.KAFKA_BATCH_TIMEOUT}
    depends_on:
      - kafka
      - opensearch
    networks:
      - bsdm-network

networks:
  bsdm-network:
    driver: bridge
`;
}

// Modal functions
function showModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-output').textContent = content;
    document.getElementById('output-modal').style.display = 'block';
}

function closeModal() {
    document.getElementById('output-modal').style.display = 'none';
}

function copyToClipboard() {
    const output = document.getElementById('modal-output').textContent;
    navigator.clipboard.writeText(output).then(() => {
        alert('Copied to clipboard!');
    });
}

// Download file
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

// Close modal on outside click
window.onclick = function(event) {
    const modal = document.getElementById('output-modal');
    if (event.target === modal) {
        closeModal();
    }
};
