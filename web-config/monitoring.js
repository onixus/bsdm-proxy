// Monitoring state
let monitoringInterval = null;
let isMonitoring = false;

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
    
    if (days > 0) {
        return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

// Update progress bar color based on percentage
function getBarColor(percent) {
    if (percent < 60) return 'bar-normal';
    if (percent < 80) return 'bar-warning';
    return 'bar-danger';
}

// Update monitoring stats
async function updateMonitoringStats() {
    if (!isMonitoring) return;
    
    try {
        const response = await fetch('/api/monitoring/stats');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        // Update system stats
        updateSystemStats(data.system);
        
        // Update container stats
        updateContainerStats(data.containers);
        
        // Update last update time
        const now = new Date();
        const timeStr = now.toLocaleTimeString();
        const lastUpdate = document.getElementById('last-update');
        if (lastUpdate) {
            lastUpdate.textContent = timeStr;
        }
    } catch (error) {
        console.error('❌ Failed to fetch monitoring stats:', error);
        
        // Show error in UI
        const tbody = document.getElementById('containers-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="6" class="error">Failed to load stats</td></tr>';
        }
    }
}

// Update system statistics
function updateSystemStats(system) {
    // CPU
    const cpuPercent = document.getElementById('cpu-percent');
    const cpuBar = document.getElementById('cpu-bar');
    if (cpuPercent && cpuBar) {
        cpuPercent.textContent = `${system.cpu.percent}%`;
        cpuBar.style.width = `${system.cpu.percent}%`;
        cpuBar.className = `metric-bar-fill ${getBarColor(system.cpu.percent)}`;
    }
    
    // Memory
    const memPercent = document.getElementById('mem-percent');
    const memBar = document.getElementById('mem-bar');
    const memDetail = document.getElementById('mem-detail');
    if (memPercent && memBar && memDetail) {
        memPercent.textContent = `${system.memory.percent}%`;
        memBar.style.width = `${system.memory.percent}%`;
        memBar.className = `metric-bar-fill ${getBarColor(system.memory.percent)}`;
        
        const usedGB = (system.memory.used / 1024 / 1024 / 1024).toFixed(1);
        const totalGB = (system.memory.total / 1024 / 1024 / 1024).toFixed(1);
        memDetail.textContent = `${usedGB} / ${totalGB} GB`;
    }
    
    // Disk
    const diskPercent = document.getElementById('disk-percent');
    const diskBar = document.getElementById('disk-bar');
    const diskDetail = document.getElementById('disk-detail');
    if (diskPercent && diskBar && diskDetail) {
        diskPercent.textContent = `${system.disk.percent}%`;
        diskBar.style.width = `${system.disk.percent}%`;
        diskBar.className = `metric-bar-fill ${getBarColor(system.disk.percent)}`;
        
        const usedGB = (system.disk.used / 1024 / 1024 / 1024).toFixed(1);
        const totalGB = (system.disk.total / 1024 / 1024 / 1024).toFixed(1);
        diskDetail.textContent = `${usedGB} / ${totalGB} GB`;
    }
    
    // Network
    const netSent = document.getElementById('net-sent');
    const netRecv = document.getElementById('net-recv');
    if (netSent && netRecv) {
        netSent.textContent = formatBytes(system.network.bytes_sent);
        netRecv.textContent = formatBytes(system.network.bytes_recv);
    }
    
    // System info
    const sysHostname = document.getElementById('sys-hostname');
    const sysPlatform = document.getElementById('sys-platform');
    const sysUptime = document.getElementById('sys-uptime');
    const sysCpuCount = document.getElementById('sys-cpu-count');
    
    if (sysHostname) sysHostname.textContent = system.system.hostname;
    if (sysPlatform) sysPlatform.textContent = system.system.platform;
    if (sysUptime) sysUptime.textContent = formatUptime(system.system.uptime);
    if (sysCpuCount) sysCpuCount.textContent = system.cpu.count;
}

// Update container statistics
function updateContainerStats(containers) {
    const tbody = document.getElementById('containers-tbody');
    if (!tbody) return;
    
    if (containers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No containers found</td></tr>';
        return;
    }
    
    tbody.innerHTML = containers.map(container => {
        const statusClass = container.status === 'running' ? 'status-running' : 'status-stopped';
        const cpuClass = container.cpu_percent > 80 ? 'high-usage' : '';
        const memClass = container.memory_percent > 80 ? 'high-usage' : '';
        
        return `
            <tr>
                <td><strong>${container.name}</strong></td>
                <td><span class="status-badge ${statusClass}">${container.status}</span></td>
                <td><code>${container.image}</code></td>
                <td class="${cpuClass}">${container.cpu_percent.toFixed(1)}%</td>
                <td>${formatBytes(container.memory_usage)}</td>
                <td class="${memClass}">${container.memory_percent.toFixed(1)}%</td>
            </tr>
        `;
    }).join('');
}

// Start monitoring
function startMonitoring() {
    if (isMonitoring) return;
    
    console.log('🚀 Starting monitoring...');
    isMonitoring = true;
    
    // Initial update
    updateMonitoringStats();
    
    // Update every 5 seconds
    monitoringInterval = setInterval(updateMonitoringStats, 5000);
}

// Stop monitoring
function stopMonitoring() {
    if (!isMonitoring) return;
    
    console.log('⏹️ Stopping monitoring...');
    isMonitoring = false;
    
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
    }
}

// Export functions globally
window.startMonitoring = startMonitoring;
window.stopMonitoring = stopMonitoring;

// Auto-start if on status tab
if (window.location.hash === '#status') {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startMonitoring);
    } else {
        startMonitoring();
    }
}
