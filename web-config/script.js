// Tab switching
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const target = tab.getAttribute('data-tab');
        
        // Stop monitoring if leaving status tab
        if (document.querySelector('.tab.active')?.getAttribute('data-tab') === 'status') {
            if (typeof stopMonitoring === 'function') {
                stopMonitoring();
            }
        }
        
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(tc => tc.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(target).classList.add('active');
        
        // Start monitoring if entering status tab
        if (target === 'status') {
            if (typeof startMonitoring === 'function') {
                startMonitoring();
            }
        }
    });
});

// Check API health on load
window.addEventListener('DOMContentLoaded', async () => {
    await checkApiHealth();
    await loadConfigFromServer();
    loadConfigFromLocalStorage(); // Fallback
    
    // Update visibility of conditional sections
    authEnabled.dispatchEvent(new Event('change'));
    authBackend.dispatchEvent(new Event('change'));
    aclEnabled.dispatchEvent(new Event('change'));
    categorizationEnabled.dispatchEvent(new Event('change'));
    cacheCapacity.dispatchEvent(new Event('input'));
});

// API Health Check
async function checkApiHealth() {
    try {
        const response = await fetch('/api/health');
        const data = await response.json();
        console.log('✅ API Health:', data);
        if (!data.docker_available) {
            console.warn('⚠️ Docker not available - container restart disabled');
        }
    } catch (error) {
        console.error('❌ API not available:', error);
        showToast('⚠️ API unavailable - using local mode', 'error');
    }
}

// Auto-save on any input change
const allInputs = document.querySelectorAll('input, select');
allInputs.forEach(input => {
    input.addEventListener('change', () => {
        saveConfigToLocalStorage();
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

// ACL toggle
const aclEnabled = document.getElementById('acl_enabled');
const aclOptions = document.getElementById('acl_options');

aclEnabled.addEventListener('change', () => {
    aclOptions.style.display = aclEnabled.checked ? 'block' : 'none';
});

// Categorization toggle
const categorizationEnabled = document.getElementById('categorization_enabled');
const categorizationOptions = document.getElementById('categorization_options');

categorizationEnabled.addEventListener('change', () => {
    categorizationOptions.style.display = categorizationEnabled.checked ? 'block' : 'none';
});

// Cache statistics
const cacheCapacity = document.getElementById('cache_capacity');
const cacheStats = document.getElementById('cache_stats');

cacheCapacity.addEventListener('input', () => {
    const entries = parseInt(cacheCapacity.value) || 10000;
    const memoryMB = (entries * 120 / 1024 / 1024).toFixed(2);
    cacheStats.textContent = `${entries.toLocaleString()} entries ≈ ${memoryMB} MB memory`;
});

// Save configuration to localStorage (fallback)
function saveConfigToLocalStorage() {
    const config = collectFormData();
    localStorage.setItem('bsdm-proxy-config', JSON.stringify(config));
}

// Load configuration from localStorage (fallback)
function loadConfigFromLocalStorage() {
    const saved = localStorage.getItem('bsdm-proxy-config');
    if (saved) {
        try {
            const config = JSON.parse(saved);
            applyConfigToForm(config);
            console.log('✅ Configuration loaded from localStorage');
        } catch (e) {
            console.error('❌ Failed to load config:', e);
        }
    }
}

// Load configuration from server
async function loadConfigFromServer() {
    try {
        const response = await fetch('/api/config/env');
        const data = await response.json();
        
        if (data.exists && data.content) {
            // Parse .env format
            const config = {};
            data.content.split('\n').forEach(line => {
                const match = line.match(/^([^=]+)=(.*)$/);
                if (match) {
                    config[match[1].trim()] = match[2].trim();
                }
            });
            
            // Map env vars to form fields
            mapEnvToForm(config);
            console.log('✅ Configuration loaded from server');
        }
    } catch (error) {
        console.warn('⚠️ Could not load from server:', error);
    }
}

// Map environment variables to form fields
function mapEnvToForm(envConfig) {
    const mapping = {
        'HTTP_PORT': 'http_port',
        'METRICS_PORT': 'metrics_port',
        'RUST_LOG': 'log_level',
        'CACHE_CAPACITY': 'cache_capacity',
        'CACHE_TTL_SECONDS': 'cache_ttl',
        'KAFKA_BROKERS': 'kafka_brokers',
        'KAFKA_TOPIC': 'kafka_topic',
        'KAFKA_BATCH_SIZE': 'kafka_batch_size',
        'KAFKA_BATCH_TIMEOUT': 'kafka_batch_timeout',
        'AUTH_ENABLED': 'auth_enabled',
        'AUTH_BACKEND': 'auth_backend',
        'AUTH_REALM': 'auth_realm',
        'AUTH_CACHE_TTL': 'auth_cache_ttl',
        'ACL_ENABLED': 'acl_enabled',
        'ACL_DEFAULT_ACTION': 'acl_default_action',
        'ACL_RULES_PATH': 'acl_rules_path',
        'OPENSEARCH_URL': 'opensearch_url',
    };
    
    Object.entries(envConfig).forEach(([envKey, value]) => {
        const fieldId = mapping[envKey];
        if (fieldId) {
            const element = document.getElementById(fieldId);
            if (element) {
                if (element.type === 'checkbox') {
                    element.checked = value === 'true';
                } else {
                    element.value = value;
                }
            }
        }
    });
}

// Collect all form data
function collectFormData() {
    const data = {};
    const inputs = document.querySelectorAll('input, select');
    
    inputs.forEach(input => {
        if (input.type === 'checkbox') {
            data[input.id] = input.checked;
        } else {
            data[input.id] = input.value;
        }
    });
    
    return data;
}

// Apply configuration to form
function applyConfigToForm(config) {
    Object.entries(config).forEach(([key, value]) => {
        const element = document.getElementById(key);
        if (element) {
            if (element.type === 'checkbox') {
                element.checked = value === true || value === 'true';
            } else {
                element.value = value;
            }
        }
    });
}

// Collect configuration from form
function collectConfig() {
    const config = {
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
        
        // ACL
        ACL_ENABLED: document.getElementById('acl_enabled').checked.toString(),
        ...(document.getElementById('acl_enabled').checked ? {
            ACL_DEFAULT_ACTION: document.getElementById('acl_default_action').value,
            ACL_RULES_PATH: document.getElementById('acl_rules_path').value,
        } : {}),
        
        // Categorization
        CATEGORIZATION_ENABLED: document.getElementById('categorization_enabled').checked.toString(),
        ...(document.getElementById('categorization_enabled').checked ? {
            CATEGORIZATION_CACHE_TTL: document.getElementById('categorization_cache_ttl').value,
            SHALLALIST_ENABLED: document.getElementById('shallalist_enabled').checked.toString(),
            SHALLALIST_PATH: document.getElementById('shallalist_path').value,
            URLHAUS_ENABLED: document.getElementById('urlhaus_enabled').checked.toString(),
            URLHAUS_API: document.getElementById('urlhaus_api').value,
            PHISHTANK_ENABLED: document.getElementById('phishtank_enabled').checked.toString(),
            PHISHTANK_API: document.getElementById('phishtank_api').value,
            CUSTOM_DB_ENABLED: document.getElementById('custom_db_enabled').checked.toString(),
            CUSTOM_DB_PATH: document.getElementById('custom_db_path').value,
        } : {}),
        
        // Monitoring
        PROMETHEUS_ENABLED: document.getElementById('prometheus_enabled').checked.toString(),
        GRAFANA_ENABLED: document.getElementById('grafana_enabled').checked.toString(),
        OPENSEARCH_URL: document.getElementById('opensearch_url').value,
    };
    
    return config;
}

// Save configuration to server (NEW)
async function saveConfigToServer() {
    try {
        showToast('💾 Saving configuration...', 'success');
        const config = collectConfig();
        
        const response = await fetch('/api/config/env', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(config)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const result = await response.json();
        console.log('✅ Config saved to server:', result);
        
        // Also save ACL rules if enabled
        if (document.getElementById('acl_enabled').checked) {
            await saveAclRulesToServer();
        }
        
        saveConfigToLocalStorage();
        return true;
    } catch (error) {
        console.error('❌ Failed to save to server:', error);
        showToast('❌ Failed to save configuration', 'error');
        return false;
    }
}

// Save ACL rules to server
async function saveAclRulesToServer() {
    const rules = generateAclRules();
    if (!rules) return;
    
    try {
        const response = await fetch('/api/config/acl-rules', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(rules)
        });
        
        if (response.ok) {
            console.log('✅ ACL rules saved');
        }
    } catch (error) {
        console.error('❌ Failed to save ACL rules:', error);
    }
}

// Apply configuration (save + restart)
async function applyConfig() {
    if (!confirm('🔄 Save configuration and restart containers?')) {
        return;
    }
    
    const saved = await saveConfigToServer();
    if (!saved) {
        return;
    }
    
    showToast('🔄 Restarting containers...', 'success');
    
    try {
        const response = await fetch('/api/docker/restart-all', {
            method: 'POST',
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const result = await response.json();
        console.log('✅ Containers restarted:', result);
        showToast(`✅ ${result.message}`, 'success');
    } catch (error) {
        console.error('❌ Failed to restart containers:', error);
        showToast('❌ Failed to restart containers', 'error');
    }
}

// Save configuration (to server)
async function saveConfig() {
    const saved = await saveConfigToServer();
    if (saved) {
        showToast('✅ Configuration saved to server', 'success');
    }
}

// Load configuration from file
function loadConfig() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = (e) => {
        const file = e.target.files[0];
        const reader = new FileReader();
        
        reader.onload = (event) => {
            try {
                const config = JSON.parse(event.target.result);
                applyConfigToForm(config);
                saveConfigToLocalStorage();
                
                // Update visibility
                authEnabled.dispatchEvent(new Event('change'));
                authBackend.dispatchEvent(new Event('change'));
                aclEnabled.dispatchEvent(new Event('change'));
                categorizationEnabled.dispatchEvent(new Event('change'));
                cacheCapacity.dispatchEvent(new Event('input'));
                
                showToast('✅ Configuration loaded from file');
            } catch (err) {
                showToast('❌ Invalid configuration file', 'error');
                console.error('Load error:', err);
            }
        };
        
        reader.readAsText(file);
    };
    
    input.click();
}

// Reset configuration to defaults
function resetConfig() {
    if (confirm('⚠️ Reset all settings to defaults?')) {
        localStorage.removeItem('bsdm-proxy-config');
        location.reload();
    }
}

// Generate configuration
function generateConfig() {
    const config = collectConfig();
    const output = formatConfig(config);
    showModal('Environment Variables', output);
}

// Generate ACL rules JSON
function generateAclRules() {
    if (!document.getElementById('acl_enabled').checked) {
        return null;
    }
    
    const rules = [];
    let priority = 100;
    
    if (document.getElementById('acl_block_malware').checked) {
        rules.push({
            id: 'block-malware',
            name: 'Block malware URLs',
            enabled: true,
            priority: priority++,
            action: 'deny',
            rule_type: { Category: 'malware' }
        });
    }
    
    if (document.getElementById('acl_block_phishing').checked) {
        rules.push({
            id: 'block-phishing',
            name: 'Block phishing URLs',
            enabled: true,
            priority: priority++,
            action: 'deny',
            rule_type: { Category: 'phishing' }
        });
    }
    
    if (document.getElementById('acl_block_adult').checked) {
        rules.push({
            id: 'block-adult',
            name: 'Block adult content',
            enabled: true,
            priority: priority++,
            action: 'deny',
            rule_type: { Category: 'adult' }
        });
    }
    
    if (document.getElementById('acl_block_gambling').checked) {
        rules.push({
            id: 'block-gambling',
            name: 'Block gambling sites',
            enabled: true,
            priority: priority++,
            action: 'deny',
            rule_type: { Category: 'gambling' }
        });
    }
    
    return {
        default_action: document.getElementById('acl_default_action').value,
        rules: rules
    };
}

// Format configuration as environment variables
function formatConfig(config) {
    let output = Object.entries(config)
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');
    
    // Add ACL rules if enabled
    const aclRules = generateAclRules();
    if (aclRules) {
        output += '\n\n# ACL Rules (save to ' + config.ACL_RULES_PATH + '):\n';
        output += '# ' + JSON.stringify(aclRules, null, 2).split('\n').join('\n# ');
    }
    
    return output;
}

// Export .env file (download)
function exportEnv() {
    const config = collectConfig();
    const content = formatConfig(config);
    downloadFile('.env', content);
    showToast('✅ .env file exported');
}

// Export docker-compose.yml (download)
function exportDockerCompose() {
    const config = collectConfig();
    const compose = generateDockerCompose(config);
    downloadFile('docker-compose.yml', compose);
    showToast('✅ docker-compose.yml exported');
}

// Generate docker-compose.yml content (simplified, just returns empty for now)
function generateDockerCompose(config) {
    return `version: '3.8'\n\nservices:\n  # Generated from config\n`;
}

// Toast notification
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 2000);
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
        showToast('✅ Copied to clipboard!');
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
