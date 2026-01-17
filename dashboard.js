/**
 * Healthcare Cyber-Resilience Platform
 * Dashboard JavaScript - Layer 5 Visualization
 */

async function fetchStats() {
    try {
        const response = await fetch('/api/v1/dashboard/stats');
        const data = await response.json();

        // Update Total Requests
        document.getElementById('total-reqs').innerText = data.total_requests;
        document.getElementById('active-alerts').innerText = data.active_alerts;
        document.getElementById('alert-count').innerText = `${data.active_alerts} alerts`;

        // Update Risk Rate Gauge
        const riskPct = Math.round(data.risk_rate * 100);
        document.getElementById('risk-rate').innerText = riskPct + '%';
        document.getElementById('risk-fill').style.width = riskPct + '%';

        // Update Layer Breakdown Bars
        const l1 = Math.round(data.layer1_rules_risk * 100);
        const l2 = Math.round(data.layer2_autoencoder_risk * 100);
        const l3 = Math.round(data.layer3_graph_risk * 100);

        document.getElementById('layer1-fill').style.width = l1 + '%';
        document.getElementById('layer2-fill').style.width = l2 + '%';
        document.getElementById('layer3-fill').style.width = l3 + '%';

        document.getElementById('layer1-value').innerText = l1 + '%';
        document.getElementById('layer2-value').innerText = l2 + '%';
        document.getElementById('layer3-value').innerText = l3 + '%';

        // Color the layer fills based on risk level
        setLayerFillColor('layer1-fill', l1);
        setLayerFillColor('layer2-fill', l2);
        setLayerFillColor('layer3-fill', l3);

        // Update System Status Badge
        const statusEl = document.getElementById('system-status');
        if (data.risk_rate >= 0.7) {
            statusEl.innerText = 'HIGH RISK';
            statusEl.className = 'status-badge HIGH';
        } else if (data.risk_rate >= 0.3) {
            statusEl.innerText = 'MEDIUM RISK';
            statusEl.className = 'status-badge MEDIUM';
        } else {
            statusEl.innerText = 'LOW RISK';
            statusEl.className = 'status-badge LOW';
        }

        // Update AI Confidence
        const aiConfEl = document.getElementById('ai-confidence');
        if (aiConfEl) {
            if (data.ai_status === 'ACTIVE') {
                aiConfEl.innerText = data.ai_confidence + '%';
                aiConfEl.style.color = data.ai_confidence > 80 ? '#45a29e' :
                    data.ai_confidence > 50 ? '#ffcc00' : '#ff0033';
            } else if (data.ai_status === 'CALIBRATING') {
                aiConfEl.innerText = 'CAL...';
                aiConfEl.style.color = '#ffcc00';
            } else {
                aiConfEl.innerText = 'OFF';
                aiConfEl.style.color = '#ff0033';
            }
        }

        // Update Layer 2 status dot in sidebar
        const layer2Dot = document.getElementById('layer2-dot');
        if (layer2Dot) {
            if (data.ai_status === 'ACTIVE') {
                layer2Dot.className = 'layer-dot active';
            } else if (data.ai_status === 'CALIBRATING') {
                layer2Dot.className = 'layer-dot warning';
            } else {
                layer2Dot.className = 'layer-dot';
            }
        }

        // Update Graph Stats
        const graphNodesEl = document.getElementById('graph-nodes');
        if (graphNodesEl) graphNodesEl.innerText = data.graph_nodes || 0;

    } catch (e) {
        console.error("Failed to fetch stats", e);
    }
}

function setLayerFillColor(elementId, percentage) {
    const el = document.getElementById(elementId);
    if (!el) return;

    if (percentage >= 70) {
        el.style.background = '#ff0033';
    } else if (percentage >= 30) {
        el.style.background = '#ffcc00';
    } else {
        el.style.background = '#45a29e';
    }
}

async function fetchAlerts() {
    try {
        const response = await fetch('/api/v1/dashboard/alerts');
        const alerts = await response.json();

        const container = document.getElementById('alert-feed');
        container.innerHTML = '';

        if (alerts.length === 0) {
            container.innerHTML = '<div class="log-entry safe">✅ No active threats detected. System secure.</div>';
            return;
        }

        // Show most recent first
        alerts.reverse().slice(0, 20).forEach(alert => {
            const div = document.createElement('div');
            div.className = 'log-entry alert';

            const severity = alert.severity || 'MEDIUM';
            const severityColor = severity === 'HIGH' ? '#ff0033' :
                severity === 'MEDIUM' ? '#ffcc00' : '#888';

            const attackType = alert.attack_type || '⚠️ Unknown';
            const attackDesc = alert.attack_description || alert.reason;
            const riskScore = alert.risk_score ? Math.round(alert.risk_score * 100) : 0;
            const time = alert.timestamp ? alert.timestamp.split('T')[1].split('.')[0] : '--:--:--';

            div.innerHTML = `
                <div class="alert-header">
                    <span class="alert-time">${time}</span>
                    <span class="alert-attack-type" style="color: ${severityColor};">${attackType}</span>
                    <span class="alert-severity severity-${severity.toLowerCase()}">${severity}</span>
                </div>
                <div class="alert-body">
                    <span class="alert-ip">📍 ${alert.ip}</span>
                    <span class="alert-confidence">🎯 Risk: ${riskScore}%</span>
                </div>
                <div class="alert-description">${attackDesc}</div>
            `;
            container.appendChild(div);
        });

    } catch (e) {
        console.error("Failed to fetch alerts", e);
    }
}

// Initial Load
fetchStats();
fetchAlerts();

// Poll every 2 seconds
setInterval(() => {
    fetchStats();
    fetchAlerts();
}, 2000);

console.log('🛡️ Sentinel Dashboard v6 Loaded');
