// Monitoring page functionality
let monitoringInterval = null;
let lastNetSent = 0;
let lastNetRecv = 0;

// Start monitoring when tab is activated
function startMonitoring() {
    if (monitoringInterval) return;
    
    updateMonitoringStats();
    monitoringInterval = setInterval(updateMonitoringStats, 5000);
    console.log('✅ Monitoring started');
}

// Stop monitoring when tab is deactivated
function stopMonitoring() {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
        console.log('⏸️ Monitoring stopped');
    }
}

// Fetch and update monitoring stats
async function updateMonitoringStats() {
    try {
        const response = await fetch('/api/monitoring/stats');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        updateSystemStats(data.system);
        updateContainersTable(data.containers);
        
        // Update last update time
        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    } catch (error) {
        console.error('❌ Failed to fetch monitoring stats:', error);
        showToast('❌ Failed to fetch monitoring data', 'error');
    }
}

// Update system stats
function updateSystemStats(system) {
    // System info
    document.getElementById('sys-hostname').textContent = system.system.hostname;
    document.getElementById('sys-platform').textContent = system.system.platform;
    document.getElementById('sys-uptime').textContent = formatUptime(system.system.uptime);
    document.getElementById('sys-cpu-count').textContent = system.cpu.count;
    
    // CPU
    const cpuPercent = system.cpu.percent;
    document.getElementById('cpu-percent').textContent = `${cpuPercent}%`;
    document.getElementById('cpu-bar').style.width = `${cpuPercent}%`;
    updateBarColor('cpu-bar', cpuPercent);
    
    // Memory
    const memPercent = system.memory.percent;
    const memUsedGB = (system.memory.used / 1024 / 1024 / 1024).toFixed(1);
    const memTotalGB = (system.memory.total / 1024 / 1024 / 1024).toFixed(1);
    document.getElementById('mem-percent').textContent = `${memPercent}%`;
    document.getElementById('mem-bar').style.width = `${memPercent}%`;
    document.getElementById('mem-detail').textContent = `${memUsedGB} / ${memTotalGB} GB`;
    updateBarColor('mem-bar', memPercent);
    
    // Disk
    const diskPercent = system.disk.percent;
    const diskUsedGB = (system.disk.used / 1024 / 1024 / 1024).toFixed(1);
    const diskTotalGB = (system.disk.total / 1024 / 1024 / 1024).toFixed(1);
    document.getElementById('disk-percent').textContent = `${diskPercent}%`;
    document.getElementById('disk-bar').style.width = `${diskPercent}%`;
    document.getElementById('disk-detail').textContent = `${diskUsedGB} / ${diskTotalGB} GB`;
    updateBarColor('disk-bar', diskPercent);
    
    // Network
    const netSent = system.network.bytes_sent;
    const netRecv = system.network.bytes_recv;
    document.getElementById('net-sent').textContent = formatBytes(netSent);
    document.getElementById('net-recv').textContent = formatBytes(netRecv);
}

// Update containers table
function updateContainersTable(containers) {
    const tbody = document.getElementById('containers-tbody');
    
    if (containers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No containers found</td></tr>';
        return;
    }
    
    tbody.innerHTML = containers.map(container => {
        const statusClass = container.status === 'running' ? 'status-running' : 'status-stopped';
        const statusIcon = container.status === 'running' ? '🟢' : '🔴';
        const memUsedMB = (container.memory_usage / 1024 / 1024).toFixed(0);
        const memLimitMB = (container.memory_limit / 1024 / 1024).toFixed(0);
        
        return `
            <tr>
                <td><strong>${container.name}</strong></td>
                <td><span class="status-badge ${statusClass}">${statusIcon} ${container.status}</span></td>
                <td><code>${container.image}</code></td>
                <td>${container.cpu_percent}%</td>
                <td>${memUsedMB} / ${memLimitMB} MB</td>
                <td>
                    <div class="mini-bar">
                        <div class="mini-bar-fill" style="width: ${container.memory_percent}%"></div>
                    </div>
                    ${container.memory_percent}%
                </td>
            </tr>
        `;
    }).join('');
}

// Update bar color based on percentage
function updateBarColor(barId, percent) {
    const bar = document.getElementById(barId);
    bar.className = 'metric-bar-fill';
    
    if (percent >= 90) {
        bar.classList.add('bar-critical');
    } else if (percent >= 75) {
        bar.classList.add('bar-warning');
    } else {
        bar.classList.add('bar-normal');
    }
}

// Format bytes to human readable
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format uptime to human readable
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    
    return parts.join(' ') || '< 1m';
}

// Export functions
window.startMonitoring = startMonitoring;
window.stopMonitoring = stopMonitoring;
