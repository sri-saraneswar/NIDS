/**
 * =========================================================
 * Network Intrusion Detection System (NIDS)
 * Module : Dashboard JavaScript
 * Logic  : Data fetching, DOM updating, Chart.js rendering
 * =========================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // Global State
    let protocolChartInstance = null;
    let lastActiveAttacks = 0;

    // Formatting utilities
    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };
    
    const formatNumber = (num) => {
        return new Intl.NumberFormat().format(num);
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        const d = new Date(dateString);
        return d.toLocaleTimeString();
    };

    // Chart.js Default Config for Dark Theme
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    const initProtocolChart = (labels, data) => {
        const ctx = document.getElementById('protocolChart').getContext('2d');
        
        protocolChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#38bdf8', // TCP
                        '#a78bfa', // UDP
                        '#fbbf24', // ICMP
                        '#34d399', // ARP
                        '#f472b6', // DNS
                        '#fb923c'  // Other
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#f8fafc',
                            padding: 20,
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    }
                }
            }
        });
    };

    const updateProtocolChart = (protocolCounts) => {
        if (Object.keys(protocolCounts).length === 0) return;
        
        // Sort protocols by count
        const sorted = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);
        
        // Take top 5, sum the rest into "Other"
        const labels = [];
        const data = [];
        let otherCount = 0;
        
        sorted.forEach((item, index) => {
            if (index < 5) {
                labels.push(item[0]);
                data.push(item[1]);
            } else {
                otherCount += item[1];
            }
        });
        
        if (otherCount > 0) {
            labels.push('Other');
            data.push(otherCount);
        }

        if (!protocolChartInstance) {
            initProtocolChart(labels, data);
        } else {
            protocolChartInstance.data.labels = labels;
            protocolChartInstance.data.datasets[0].data = data;
            protocolChartInstance.update();
        }
    };

    // Update Status API
    const fetchStatus = async () => {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            
            // Update Metrics
            document.getElementById('val-packets').textContent = formatNumber(data.packets);
            document.getElementById('val-bytes').textContent = formatBytes(data.total_bytes);
            document.getElementById('val-alerts').textContent = formatNumber(data.alerts);
            document.getElementById('val-warnings').textContent = formatNumber(data.warnings);
            
            // Update Risk Badge
            const riskBadge = document.getElementById('risk-badge');
            const riskLevel = document.getElementById('risk-level');
            
            riskLevel.textContent = data.risk;
            riskBadge.className = `risk-badge risk-${data.risk}`;
            
            // Update Chart
            updateProtocolChart(data.protocol_counts);
            
        } catch (error) {
            console.error("Error fetching status:", error);
            document.getElementById('session-status').textContent = "Disconnected";
            document.querySelector('.status-dot').style.backgroundColor = "#ef4444";
        }
    };

    // Update Hosts API
    const fetchHosts = async () => {
        try {
            const res = await fetch('/api/hosts');
            const data = await res.json();
            
            const tbody = document.querySelector('#hosts-table tbody');
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="2" class="text-center dim-text">No traffic detected yet.</td></tr>';
                return;
            }
            
            let html = '';
            data.forEach(host => {
                html += `
                    <tr>
                        <td style="font-family: monospace;">${host.ip}</td>
                        <td class="text-right">${formatNumber(host.packets)}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
            
        } catch (error) {
            console.error("Error fetching hosts:", error);
        }
    };

    // Update Attacks API
    const fetchAttacks = async () => {
        try {
            const res = await fetch('/api/attacks');
            const data = await res.json();
            
            // 1. Update Active Attacks
            const activeList = document.getElementById('active-attacks-list');
            const activeBadge = document.getElementById('badge-active');
            
            activeBadge.textContent = data.active.length;
            
            if (data.active.length === 0) {
                activeList.innerHTML = '<div class="empty-state">No active threats detected.</div>';
            } else {
                let activeHtml = '';
                data.active.forEach(attack => {
                    activeHtml += `
                        <div class="active-attack-card">
                            <div class="attack-info">
                                <h4><span class="pulse-icon">●</span>${attack.attack_type}</h4>
                                <div class="attack-meta">${attack.source_ip} &rarr; ${attack.destination_ip}</div>
                                <div class="sev-badge sev-${attack.severity}" style="display:inline-block; margin-top:0.5rem;">${attack.severity}</div>
                            </div>
                            <div class="attack-stats">
                                <div class="dim-text">Packets</div>
                                <div class="attack-packets">${formatNumber(attack.packet_count)}</div>
                            </div>
                        </div>
                    `;
                });
                activeList.innerHTML = activeHtml;
            }
            
            // 2. Update Attack History
            const historyBody = document.querySelector('#attacks-table tbody');
            
            if (data.history.length === 0) {
                historyBody.innerHTML = '<tr><td colspan="5" class="text-center dim-text">No attacks recorded yet.</td></tr>';
            } else {
                let histHtml = '';
                // Show newest first
                const reversedHistory = [...data.history].reverse();
                
                reversedHistory.forEach(attack => {
                    histHtml += `
                        <tr>
                            <td class="dim-text">${attack.alert_id || '?'}</td>
                            <td><strong>${attack.attack_type}</strong></td>
                            <td><span class="sev-badge sev-${attack.severity}">${attack.severity}</span></td>
                            <td style="font-family: monospace;" class="dim-text">${attack.destination_ip}</td>
                            <td>${formatNumber(attack.packet_count || attack.packets)}</td>
                        </tr>
                    `;
                });
                historyBody.innerHTML = histHtml;
            }
            
        } catch (error) {
            console.error("Error fetching attacks:", error);
        }
    };

    // Data Polling Loop
    const pollData = () => {
        fetchStatus();
        fetchHosts();
        fetchAttacks();
    };

    // Initial fetch
    pollData();
    
    // Poll every 2 seconds
    setInterval(pollData, 2000);
});
