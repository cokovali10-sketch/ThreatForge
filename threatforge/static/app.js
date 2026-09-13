/**
 * ThreatForge SOC Platform - Frontend Application
 */

(function() {
    'use strict';

    // State
    const state = {
        currentPage: 'dashboard',
        wsEvents: null,
        wsAlerts: null,
        charts: {},
        stats: {},
        alerts: [],
        events: [],
        incidents: [],
        logs: [],
        iocs: [],
        feeds: [],
        connections: [],
        playbooks: [],
    };

    // API Client
    const api = {
        async get(url) {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        },
        async post(url, data) {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        },
        async put(url, data) {
            const response = await fetch(url, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        },
        async delete(url) {
            const response = await fetch(url, { method: 'DELETE' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        },
    };

    // WebSocket Manager
    const ws = {
        connect() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const base = `${protocol}//${location.host}`;

            state.wsEvents = new WebSocket(`${base}/ws/events`);
            state.wsAlerts = new WebSocket(`${base}/ws/alerts`);

            state.wsEvents.onopen = () => this.updateStatus(true);
            state.wsEvents.onclose = () => this.updateStatus(false);
            state.wsEvents.onerror = () => this.updateStatus(false);

            state.wsAlerts.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleAlertMessage(data);
            };

            state.wsEvents.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleEventMessage(data);
            };
        },
        updateStatus(connected) {
            const el = document.getElementById('wsStatus');
            if (el) {
                el.querySelector('.status-dot').classList.toggle('connected', connected);
                el.querySelector('span:last-child').textContent = connected ? 'Connected' : 'Disconnected';
            }
        },
        handleAlertMessage(data) {
            if (data.type === 'new_alert' || data.type === 'acknowledged' || data.type === 'resolved') {
                if (state.currentPage === 'alerts') loadAlerts();
                if (state.currentPage === 'dashboard') loadDashboard();
                showToast(`Alert ${data.type.replace('_', ' ')}`, 'info');
            }
            if (data.type === 'new_ioc') {
                if (state.currentPage === 'threats') loadThreats();
            }
            if (data.type === 'new_incident') {
                if (state.currentPage === 'incidents') loadIncidents();
            }
        },
        handleEventMessage(data) {
            if (data.type === 'new_event' && state.currentPage === 'events') {
                loadEvents();
            }
        },
        disconnect() {
            if (state.wsEvents) state.wsEvents.close();
            if (state.wsAlerts) state.wsAlerts.close();
        }
    };

    // Router
    function initRouter() {
        window.addEventListener('hashchange', handleRoute);
        handleRoute();
    }

    function handleRoute() {
        const hash = window.location.hash.slice(1) || '/';
        const page = hash.split('/')[1] || 'dashboard';
        navigateTo(page);
    }

    function navigateTo(page) {
        state.currentPage = page;
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === page);
        });
        const titles = {
            dashboard: 'Dashboard', alerts: 'Alerts', events: 'Events',
            incidents: 'Incidents', network: 'Network', threats: 'Threats',
            forensics: 'Forensics', logs: 'Logs', settings: 'Settings'
        };
        document.getElementById('pageTitle').textContent = titles[page] || 'Dashboard';
        renderPage(page);
    }

    function renderPage(page) {
        const content = document.getElementById('contentArea');
        content.innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';
        switch (page) {
            case 'dashboard': loadDashboard(); break;
            case 'alerts': loadAlerts(); break;
            case 'events': loadEvents(); break;
            case 'incidents': loadIncidents(); break;
            case 'network': loadNetwork(); break;
            case 'threats': loadThreats(); break;
            case 'forensics': loadForensics(); break;
            case 'logs': loadLogs(); break;
            case 'settings': loadSettings(); break;
            default: loadDashboard();
        }
    }

    // Dashboard
    async function loadDashboard() {
        try {
            const stats = await api.get('/api/stats');
            state.stats = stats;
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <div class="stat-label">Active Alerts</div>
                        <div class="stat-value">${stats.active_alerts || 0}</div>
                        <div class="stat-change negative">+3 last hour</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-label">Critical Alerts</div>
                        <div class="stat-value">${stats.critical_alerts || 0}</div>
                        <div class="stat-change negative">Requires attention</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-label">Total Events</div>
                        <div class="stat-value">${stats.total_events || 0}</div>
                        <div class="stat-change positive">Monitoring active</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-label">Open Incidents</div>
                        <div class="stat-value">${stats.open_incidents || 0}</div>
                        <div class="stat-change">${stats.total_incidents || 0} total</div>
                    </div>
                    <div class="stat-card info">
                        <div class="stat-label">Active Connections</div>
                        <div class="stat-value">${stats.active_connections || 0}</div>
                        <div class="stat-change">Network monitored</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-label">Total IOCs</div>
                        <div class="stat-value">${stats.total_iocs || 0}</div>
                        <div class="stat-change">Threat indicators</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-label">Total Logs</div>
                        <div class="stat-value">${stats.total_logs || 0}</div>
                        <div class="stat-change">System logs</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-label">System Health</div>
                        <div class="stat-value">OK</div>
                        <div class="stat-change positive">All systems operational</div>
                    </div>
                </div>
                <div class="charts-grid">
                    <div class="chart-card">
                        <div class="chart-header">
                            <span class="chart-title">Alerts Over Time</span>
                        </div>
                        <div class="chart-container"><canvas id="alertsChart"></canvas></div>
                    </div>
                    <div class="chart-card">
                        <div class="chart-header">
                            <span class="chart-title">Top Threat Types</span>
                        </div>
                        <div class="chart-container"><canvas id="threatsChart"></canvas></div>
                    </div>
                    <div class="chart-card">
                        <div class="chart-header">
                            <span class="chart-title">Severity Distribution</span>
                        </div>
                        <div class="chart-container"><canvas id="severityChart"></canvas></div>
                    </div>
                    <div class="chart-card">
                        <div class="chart-header">
                            <span class="chart-title">Network Traffic</span>
                        </div>
                        <div class="chart-container"><canvas id="networkChart"></canvas></div>
                    </div>
                </div>
                <div class="table-container">
                    <div class="table-header">
                        <span class="table-title">Recent Alerts</span>
                        <a href="#/alerts" class="btn btn-secondary btn-sm">View All</a>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Alert</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Source</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="recentAlerts"></tbody>
                    </table>
                </div>
            `;
            initCharts();
            loadRecentAlerts();
        } catch (error) {
            showToast('Failed to load dashboard', 'error');
        }
    }

    function initCharts() {
        const chartDefaults = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666' } }
            }
        };

        const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        const alertsCtx = document.getElementById('alertsChart');
        if (alertsCtx) {
            new Chart(alertsCtx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [{
                        label: 'Alerts',
                        data: [12, 19, 8, 15, 22, 14, 10],
                        borderColor: '#ff2d55',
                        backgroundColor: 'rgba(255,45,85,0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointBackgroundColor: '#ff2d55',
                    }]
                },
                options: chartDefaults
            });
        }

        const threatsCtx = document.getElementById('threatsChart');
        if (threatsCtx) {
            new Chart(threatsCtx, {
                type: 'bar',
                data: {
                    labels: ['Malware', 'Phishing', 'Brute Force', 'DDoS', 'SQLi', 'XSS'],
                    datasets: [{
                        data: [45, 32, 28, 21, 18, 12],
                        backgroundColor: ['#ff2d55', '#ff6b35', '#ffc107', '#5ac8fa', '#6c5ce7', '#34c759'],
                        borderRadius: 4,
                    }]
                },
                options: chartDefaults
            });
        }

        const severityCtx = document.getElementById('severityChart');
        if (severityCtx) {
            new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [8, 15, 32, 25, 20],
                        backgroundColor: ['#ff2d55', '#ff6b35', '#ffc107', '#34c759', '#5ac8fa'],
                        borderWidth: 0,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#a0a0a0', padding: 12, font: { size: 12 } }
                        }
                    }
                }
            });
        }

        const networkCtx = document.getElementById('networkChart');
        if (networkCtx) {
            new Chart(networkCtx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Inbound',
                            data: [65, 78, 52, 91, 68, 45, 72],
                            borderColor: '#4a90d9',
                            backgroundColor: 'rgba(74,144,217,0.1)',
                            fill: true,
                            tension: 0.4,
                        },
                        {
                            label: 'Outbound',
                            data: [42, 55, 38, 65, 48, 32, 50],
                            borderColor: '#6c5ce7',
                            backgroundColor: 'rgba(108,92,231,0.1)',
                            fill: true,
                            tension: 0.4,
                        }
                    ]
                },
                options: {
                    ...chartDefaults,
                    plugins: { legend: { display: true, labels: { color: '#a0a0a0' } } }
                }
            });
        }
    }

    async function loadRecentAlerts() {
        try {
            const data = await api.get('/api/alerts?limit=5');
            const tbody = document.getElementById('recentAlerts');
            if (!tbody) return;
            tbody.innerHTML = data.alerts.map(alert => `
                <tr>
                    <td>${escapeHtml(alert.title)}</td>
                    <td><span class="severity-badge ${alert.severity}">${alert.severity}</span></td>
                    <td><span class="status-badge ${alert.status}">${alert.status}</span></td>
                    <td>${escapeHtml(alert.source || '-')}</td>
                    <td>${formatTime(alert.created_at)}</td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('Failed to load recent alerts:', error);
        }
    }

    // Alerts
    async function loadAlerts() {
        try {
            const params = new URLSearchParams();
            const statusFilter = document.getElementById('alertStatusFilter')?.value;
            const sevFilter = document.getElementById('alertSevFilter')?.value;
            if (statusFilter) params.set('status', statusFilter);
            if (sevFilter) params.set('severity', sevFilter);
            params.set('limit', '50');
            const data = await api.get(`/api/alerts?${params}`);
            state.alerts = data.alerts;
            document.getElementById('alertBadge').textContent = data.total;
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="filter-bar">
                    <select id="alertStatusFilter" onchange="window.ThreatForge.loadAlerts()">
                        <option value="">All Status</option>
                        <option value="active" ${statusFilter === 'active' ? 'selected' : ''}>Active</option>
                        <option value="acknowledged" ${statusFilter === 'acknowledged' ? 'selected' : ''}>Acknowledged</option>
                        <option value="resolved" ${statusFilter === 'resolved' ? 'selected' : ''}>Resolved</option>
                    </select>
                    <select id="alertSevFilter" onchange="window.ThreatForge.loadAlerts()">
                        <option value="">All Severity</option>
                        <option value="critical" ${sevFilter === 'critical' ? 'selected' : ''}>Critical</option>
                        <option value="high" ${sevFilter === 'high' ? 'selected' : ''}>High</option>
                        <option value="medium" ${sevFilter === 'medium' ? 'selected' : ''}>Medium</option>
                        <option value="low" ${sevFilter === 'low' ? 'selected' : ''}>Low</option>
                        <option value="info" ${sevFilter === 'info' ? 'selected' : ''}>Info</option>
                    </select>
                </div>
                <div class="table-container">
                    <div class="table-header">
                        <span class="table-title">Alerts (${data.total} total)</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Alert</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Source</th>
                                <th>Time</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.alerts.map(alert => `
                                <tr>
                                    <td>${escapeHtml(alert.title)}</td>
                                    <td><span class="severity-badge ${alert.severity}">${alert.severity}</span></td>
                                    <td><span class="status-badge ${alert.status}">${alert.status}</span></td>
                                    <td>${escapeHtml(alert.source || '-')}</td>
                                    <td>${formatTime(alert.created_at)}</td>
                                    <td class="action-btns">
                                        ${alert.status === 'active' ? `
                                            <button class="action-btn ack" onclick="window.ThreatForge.ackAlert('${alert.id}')">Ack</button>
                                            <button class="action-btn resolve" onclick="window.ThreatForge.resolveAlert('${alert.id}')">Resolve</button>
                                        ` : ''}
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (error) {
            showToast('Failed to load alerts', 'error');
        }
    }

    async function ackAlert(id) {
        try {
            await api.post(`/api/alerts/${id}/acknowledge`);
            showToast('Alert acknowledged', 'success');
            loadAlerts();
        } catch (error) {
            showToast('Failed to acknowledge alert', 'error');
        }
    }

    async function resolveAlert(id) {
        try {
            await api.post(`/api/alerts/${id}/resolve`);
            showToast('Alert resolved', 'success');
            loadAlerts();
        } catch (error) {
            showToast('Failed to resolve alert', 'error');
        }
    }

    // Events
    async function loadEvents() {
        try {
            const data = await api.get('/api/events?limit=50');
            state.events = data.events;
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="table-container">
                    <div class="table-header">
                        <span class="table-title">Events (${data.total} total)</span>
                        <div>
                            <input type="text" placeholder="Search events..." id="eventSearch"
                                   style="background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:var(--radius-sm);padding:6px 12px;color:var(--text-primary);font-size:13px;"
                                   onkeyup="window.ThreatForge.searchEvents(this.value)">
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Source IP</th>
                                <th>Destination IP</th>
                                <th>Protocol</th>
                                <th>Severity</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.events.map(ev => `
                                <tr>
                                    <td>${escapeHtml(ev.event_type)}</td>
                                    <td>${escapeHtml(ev.source_ip || '-')}</td>
                                    <td>${escapeHtml(ev.destination_ip || '-')}</td>
                                    <td>${escapeHtml(ev.protocol || '-')}</td>
                                    <td><span class="severity-badge ${ev.severity}">${ev.severity}</span></td>
                                    <td>${formatTime(ev.timestamp)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (error) {
            showToast('Failed to load events', 'error');
        }
    }

    async function searchEvents(query) {
        if (!query) return loadEvents();
        try {
            const data = await api.get(`/api/events/search?q=${encodeURIComponent(query)}`);
            const tbody = document.querySelector('#contentArea tbody');
            if (tbody) {
                tbody.innerHTML = data.events.map(ev => `
                    <tr>
                        <td>${escapeHtml(ev.event_type)}</td>
                        <td>${escapeHtml(ev.source_ip || '-')}</td>
                        <td>${escapeHtml(ev.destination_ip || '-')}</td>
                        <td>${escapeHtml(ev.protocol || '-')}</td>
                        <td><span class="severity-badge ${ev.severity}">${ev.severity}</span></td>
                        <td>${formatTime(ev.timestamp)}</td>
                    </tr>
                `).join('');
            }
        } catch (error) {
            console.error('Search failed:', error);
        }
    }

    // Incidents
    async function loadIncidents() {
        try {
            const data = await api.get('/api/incidents?limit=50');
            state.incidents = data.incidents;
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="filter-bar">
                    <button class="btn btn-primary" onclick="window.ThreatForge.showCreateIncident()">New Incident</button>
                </div>
                <div class="table-container">
                    <div class="table-header">
                        <span class="table-title">Incidents (${data.incidents.length} total)</span>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Assigned To</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.incidents.map(inc => `
                                <tr>
                                    <td>${escapeHtml(inc.title)}</td>
                                    <td><span class="severity-badge ${inc.severity}">${inc.severity}</span></td>
                                    <td><span class="status-badge ${inc.status}">${inc.status}</span></td>
                                    <td>${escapeHtml(inc.assigned_to || '-')}</td>
                                    <td>${formatTime(inc.created_at)}</td>
                                    <td class="action-btns">
                                        <button class="action-btn view" onclick="window.ThreatForge.viewIncident('${inc.id}')">View</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (error) {
            showToast('Failed to load incidents', 'error');
        }
    }

    function showCreateIncident() {
        showModal('Create Incident', `
            <div class="form-group">
                <label>Title</label>
                <input type="text" id="incidentTitle" placeholder="Incident title">
            </div>
            <div class="form-group">
                <label>Description</label>
                <textarea id="incidentDesc" placeholder="Describe the incident..."></textarea>
            </div>
            <div class="form-group">
                <label>Severity</label>
                <select id="incidentSeverity">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium" selected>Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="form-group">
                <label>Assign To</label>
                <input type="text" id="incidentAssignee" placeholder="Analyst name">
            </div>
            <div class="form-actions">
                <button class="btn btn-secondary" onclick="window.ThreatForge.closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="window.ThreatForge.createIncident()">Create</button>
            </div>
        `);
    }

    async function createIncident() {
        const title = document.getElementById('incidentTitle')?.value;
        const description = document.getElementById('incidentDesc')?.value;
        const severity = document.getElementById('incidentSeverity')?.value;
        const assigned_to = document.getElementById('incidentAssignee')?.value;
        if (!title) return showToast('Title is required', 'error');
        try {
            await api.post('/api/incidents', { title, description, severity, assigned_to });
            showToast('Incident created', 'success');
            closeModal();
            loadIncidents();
        } catch (error) {
            showToast('Failed to create incident', 'error');
        }
    }

    async function viewIncident(id) {
        try {
            const [incident, timeline] = await Promise.all([
                api.get(`/api/incidents/${id}`),
                api.get(`/api/incidents/${id}/timeline`),
            ]);
            const tags = JSON.parse(incident.tags || '[]');
            showModal(incident.title, `
                <div style="margin-bottom:16px;">
                    <span class="severity-badge ${incident.severity}">${incident.severity}</span>
                    <span class="status-badge ${incident.status}" style="margin-left:8px;">${incident.status}</span>
                </div>
                <p style="color:var(--text-secondary);margin-bottom:16px;">${escapeHtml(incident.description || 'No description')}</p>
                <p style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">
                    Assigned to: ${escapeHtml(incident.assigned_to || 'Unassigned')}
                </p>
                <div style="margin-bottom:16px;">
                    ${tags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('')}
                </div>
                <h3 style="font-size:14px;margin-bottom:12px;">Timeline</h3>
                <div class="timeline">
                    ${timeline.timeline.map(item => `
                        <div class="timeline-item">
                            <div class="timeline-time">${formatTime(item.timestamp)}</div>
                            <div class="timeline-event">${escapeHtml(item.event)}</div>
                        </div>
                    `).join('')}
                </div>
            `);
        } catch (error) {
            showToast('Failed to load incident', 'error');
        }
    }

    // Network
    async function loadNetwork() {
        try {
            const [stats, connections, topTalkers] = await Promise.all([
                api.get('/api/network/stats'),
                api.get('/api/network/connections?limit=20'),
                api.get('/api/network/top-talkers?limit=10'),
            ]);
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-card info">
                        <div class="stat-label">Active Connections</div>
                        <div class="stat-value">${stats.active_connections || 0}</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-label">Total Bytes Sent</div>
                        <div class="stat-value">${formatBytes(stats.total_bytes_sent || 0)}</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-label">Total Bytes Received</div>
                        <div class="stat-value">${formatBytes(stats.total_bytes_received || 0)}</div>
                    </div>
                </div>
                <div class="charts-grid">
                    <div class="chart-card">
                        <div class="chart-header"><span class="chart-title">Top Talkers</span></div>
                        <table>
                            <thead><tr><th>IP Address</th><th>Total Bytes</th></tr></thead>
                            <tbody>
                                ${topTalkers.top_talkers.map(t => `
                                    <tr><td>${escapeHtml(t.ip)}</td><td>${formatBytes(t.total_bytes)}</td></tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                    <div class="chart-card">
                        <div class="chart-header"><span class="chart-title">Active Connections</span></div>
                        <table>
                            <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th></tr></thead>
                            <tbody>
                                ${connections.connections.map(c => `
                                    <tr>
                                        <td>${escapeHtml(c.source_ip)}</td>
                                        <td>${escapeHtml(c.destination_ip)}</td>
                                        <td>${escapeHtml(c.protocol || '-')}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } catch (error) {
            showToast('Failed to load network data', 'error');
        }
    }

    // Threats
    async function loadThreats() {
        try {
            const [iocData, feedData] = await Promise.all([
                api.get('/api/threats/ioc'),
                api.get('/api/threats/feeds'),
            ]);
            state.iocs = iocData.iocs;
            state.feeds = feedData.feeds;
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="filter-bar">
                    <button class="btn btn-primary" onclick="window.ThreatForge.showAddIOC()">Add IOC</button>
                    <button class="btn btn-secondary" onclick="window.ThreatForge.showAddFeed()">Add Feed</button>
                </div>
                <div class="charts-grid">
                    <div class="table-container">
                        <div class="table-header">
                            <span class="table-title">Indicators of Compromise (${state.iocs.length})</span>
                        </div>
                        <table>
                            <thead>
                                <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Severity</th><th>Actions</th></tr>
                            </thead>
                            <tbody>
                                ${state.iocs.map(ioc => `
                                    <tr>
                                        <td><span class="tag">${escapeHtml(ioc.type)}</span></td>
                                        <td style="font-family:monospace;font-size:12px;">${escapeHtml(ioc.value)}</td>
                                        <td>${ioc.confidence}%</td>
                                        <td><span class="severity-badge ${ioc.severity}">${ioc.severity}</span></td>
                                        <td>
                                            <button class="action-btn ack" onclick="window.ThreatForge.removeIOC('${ioc.id}')">Remove</button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                    <div class="table-container">
                        <div class="table-header">
                            <span class="table-title">Threat Feeds (${state.feeds.length})</span>
                        </div>
                        <table>
                            <thead>
                                <tr><th>Name</th><th>Type</th><th>Status</th><th>Indicators</th></tr>
                            </thead>
                            <tbody>
                                ${state.feeds.map(f => `
                                    <tr>
                                        <td>${escapeHtml(f.name)}</td>
                                        <td><span class="tag">${escapeHtml(f.feed_type)}</span></td>
                                        <td><span class="status-badge ${f.status}">${f.status}</span></td>
                                        <td>${f.indicators_count}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } catch (error) {
            showToast('Failed to load threats', 'error');
        }
    }

    function showAddIOC() {
        showModal('Add IOC', `
            <div class="form-group">
                <label>Type</label>
                <select id="iocType">
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="hash">Hash</option>
                    <option value="url">URL</option>
                    <option value="email">Email</option>
                </select>
            </div>
            <div class="form-group">
                <label>Value</label>
                <input type="text" id="iocValue" placeholder="IOC value">
            </div>
            <div class="form-group">
                <label>Confidence (0-100)</label>
                <input type="number" id="iocConfidence" value="75" min="0" max="100">
            </div>
            <div class="form-group">
                <label>Severity</label>
                <select id="iocSeverity">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium" selected>Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="form-group">
                <label>Description</label>
                <textarea id="iocDescription" placeholder="Description..."></textarea>
            </div>
            <div class="form-actions">
                <button class="btn btn-secondary" onclick="window.ThreatForge.closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="window.ThreatForge.addIOC()">Add</button>
            </div>
        `);
    }

    async function addIOC() {
        const type = document.getElementById('iocType')?.value;
        const value = document.getElementById('iocValue')?.value;
        const confidence = parseInt(document.getElementById('iocConfidence')?.value || '75');
        const severity = document.getElementById('iocSeverity')?.value;
        const description = document.getElementById('iocDescription')?.value;
        if (!value) return showToast('Value is required', 'error');
        try {
            await api.post('/api/threats/ioc', { type, value, confidence, severity, description });
            showToast('IOC added', 'success');
            closeModal();
            loadThreats();
        } catch (error) {
            showToast('Failed to add IOC', 'error');
        }
    }

    async function removeIOC(id) {
        try {
            await api.delete(`/api/threats/ioc/${id}`);
            showToast('IOC removed', 'success');
            loadThreats();
        } catch (error) {
            showToast('Failed to remove IOC', 'error');
        }
    }

    function showAddFeed() {
        showModal('Add Threat Feed', `
            <div class="form-group">
                <label>Name</label>
                <input type="text" id="feedName" placeholder="Feed name">
            </div>
            <div class="form-group">
                <label>URL</label>
                <input type="url" id="feedUrl" placeholder="https://...">
            </div>
            <div class="form-group">
                <label>Type</label>
                <select id="feedType">
                    <option value="stix">STIX</option>
                    <option value="csv">CSV</option>
                    <option value="json">JSON</option>
                    <option value="text">Plain Text</option>
                </select>
            </div>
            <div class="form-actions">
                <button class="btn btn-secondary" onclick="window.ThreatForge.closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="window.ThreatForge.addFeed()">Add</button>
            </div>
        `);
    }

    async function addFeed() {
        const name = document.getElementById('feedName')?.value;
        const url = document.getElementById('feedUrl')?.value;
        const feed_type = document.getElementById('feedType')?.value;
        if (!name || !url) return showToast('Name and URL are required', 'error');
        try {
            await api.post('/api/threats/feeds', { name, url, feed_type });
            showToast('Feed added', 'success');
            closeModal();
            loadThreats();
        } catch (error) {
            showToast('Failed to add feed', 'error');
        }
    }

    // Forensics
    function loadForensics() {
        const content = document.getElementById('contentArea');
        content.innerHTML = `
            <div class="chart-card">
                <div class="chart-header"><span class="chart-title">Artifact Analysis</span></div>
                <div class="form-group">
                    <label>Artifact Name</label>
                    <input type="text" id="forensicName" placeholder="filename.exe">
                </div>
                <div class="form-group">
                    <label>Type</label>
                    <select id="forensicType">
                        <option value="executable">Executable</option>
                        <option value="document">Document</option>
                        <option value="script">Script</option>
                        <option value="network">Network Capture</option>
                        <option value="memory">Memory Dump</option>
                    </select>
                </div>
                <button class="btn btn-primary" onclick="window.ThreatForge.analyzeArtifact()">Analyze</button>
                <div id="forensicResult" style="margin-top:20px;"></div>
            </div>
        `;
    }

    async function analyzeArtifact() {
        const name = document.getElementById('forensicName')?.value || 'unknown';
        const type = document.getElementById('forensicType')?.value || 'unknown';
        try {
            const result = await api.get(`/api/forensics/analyze?name=${encodeURIComponent(name)}&type=${type}`);
            document.getElementById('forensicResult').innerHTML = `
                <div class="info-card" style="margin-top:12px;">
                    <h3>Analysis Result</h3>
                    <p><strong>Artifact:</strong> ${escapeHtml(result.artifact)}</p>
                    <p><strong>Type:</strong> ${escapeHtml(result.type)}</p>
                    <p><strong>Threat Level:</strong> ${result.analysis.threat_level}</p>
                    <p style="margin-top:8px;color:var(--text-muted);font-size:12px;">
                        Analyzed at ${formatTime(result.timestamp)}
                    </p>
                </div>
            `;
        } catch (error) {
            showToast('Analysis failed', 'error');
        }
    }

    // Logs
    async function loadLogs() {
        try {
            const data = await api.get('/api/logs?limit=100');
            state.logs = data.logs;
            const content = document.getElementById('contentArea');
            content.innerHTML = `
                <div class="filter-bar">
                    <select id="logLevelFilter" onchange="window.ThreatForge.filterLogs()">
                        <option value="">All Levels</option>
                        <option value="INFO">INFO</option>
                        <option value="WARNING">WARNING</option>
                        <option value="ERROR">ERROR</option>
                        <option value="DEBUG">DEBUG</option>
                    </select>
                    <input type="text" id="logSearch" placeholder="Search logs..."
                           onkeyup="window.ThreatForge.searchLogs(this.value)">
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr>
                        </thead>
                        <tbody>
                            ${data.logs.map(log => `
                                <tr>
                                    <td style="white-space:nowrap;">${formatTime(log.timestamp)}</td>
                                    <td><span class="severity-badge ${log.level.toLowerCase()}">${log.level}</span></td>
                                    <td>${escapeHtml(log.source || '-')}</td>
                                    <td style="font-family:monospace;font-size:12px;">${escapeHtml(log.message)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (error) {
            showToast('Failed to load logs', 'error');
        }
    }

    async function filterLogs() {
        const level = document.getElementById('logLevelFilter')?.value;
        try {
            const params = level ? `?level=${level}` : '';
            const data = await api.get(`/api/logs${params}&limit=100`);
            const tbody = document.querySelector('#contentArea tbody');
            if (tbody) {
                tbody.innerHTML = data.logs.map(log => `
                    <tr>
                        <td style="white-space:nowrap;">${formatTime(log.timestamp)}</td>
                        <td><span class="severity-badge ${log.level.toLowerCase()}">${log.level}</span></td>
                        <td>${escapeHtml(log.source || '-')}</td>
                        <td style="font-family:monospace;font-size:12px;">${escapeHtml(log.message)}</td>
                    </tr>
                `).join('');
            }
        } catch (error) {
            console.error('Filter failed:', error);
        }
    }

    async function searchLogs(query) {
        if (!query) return filterLogs();
        try {
            const data = await api.get(`/api/logs?q=${encodeURIComponent(query)}&limit=100`);
            const tbody = document.querySelector('#contentArea tbody');
            if (tbody) {
                tbody.innerHTML = data.logs.map(log => `
                    <tr>
                        <td style="white-space:nowrap;">${formatTime(log.timestamp)}</td>
                        <td><span class="severity-badge ${log.level.toLowerCase()}">${log.level}</span></td>
                        <td>${escapeHtml(log.source || '-')}</td>
                        <td style="font-family:monospace;font-size:12px;">${escapeHtml(log.message)}</td>
                    </tr>
                `).join('');
            }
        } catch (error) {
            console.error('Search failed:', error);
        }
    }

    // Settings
    function loadSettings() {
        const content = document.getElementById('contentArea');
        content.innerHTML = `
            <div class="settings-section">
                <h2>Server Configuration</h2>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">Server Port</div>
                        <div class="setting-description">Port for the API server</div>
                    </div>
                    <input type="number" value="8443" style="background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:var(--radius-sm);padding:6px 12px;color:var(--text-primary);width:100px;">
                </div>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">Debug Mode</div>
                        <div class="setting-description">Enable verbose logging</div>
                    </div>
                    <div class="toggle" onclick="this.classList.toggle('active')"></div>
                </div>
            </div>
            <div class="settings-section">
                <h2>Alert Notifications</h2>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">Email Notifications</div>
                        <div class="setting-description">Send alerts via email</div>
                    </div>
                    <div class="toggle" onclick="this.classList.toggle('active')"></div>
                </div>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">Webhook Integration</div>
                        <div class="setting-description">Send alerts to webhook URL</div>
                    </div>
                    <div class="toggle" onclick="this.classList.toggle('active')"></div>
                </div>
            </div>
            <div class="settings-section">
                <h2>Threat Intelligence</h2>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">Auto-Update Feeds</div>
                        <div class="setting-description">Automatically update threat feeds</div>
                    </div>
                    <div class="toggle active" onclick="this.classList.toggle('active')"></div>
                </div>
                <div class="setting-row">
                    <div>
                        <div class="setting-label">Feed Update Interval</div>
                        <div class="setting-description">How often to check for updates</div>
                    </div>
                    <select style="background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:var(--radius-sm);padding:6px 12px;color:var(--text-primary);">
                        <option>15 minutes</option>
                        <option selected>1 hour</option>
                        <option>6 hours</option>
                        <option>24 hours</option>
                    </select>
                </div>
            </div>
        `;
    }

    // Modal
    function showModal(title, bodyHTML) {
        document.getElementById('modalTitle').textContent = title;
        document.getElementById('modalBody').innerHTML = bodyHTML;
        document.getElementById('modalOverlay').style.display = 'flex';
    }

    function closeModal() {
        document.getElementById('modalOverlay').style.display = 'none';
    }

    // Toast
    function showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    // Utilities
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function formatTime(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Initialize
    function init() {
        ws.connect();
        initRouter();
        document.getElementById('refreshBtn')?.addEventListener('click', () => renderPage(state.currentPage));
        document.getElementById('modalClose')?.addEventListener('click', closeModal);
        document.getElementById('modalOverlay')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget) closeModal();
        });
        document.getElementById('globalSearch')?.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') {
                const q = e.target.value;
                if (q) window.location.hash = `#/events`;
            }
        });
    }

    // Public API
    window.ThreatForge = {
        loadAlerts, loadEvents, loadIncidents, loadNetwork, loadThreats,
        loadForensics, loadLogs, loadSettings,
        ackAlert, resolveAlert,
        showCreateIncident, createIncident, viewIncident,
        showAddIOC, addIOC, removeIOC,
        showAddFeed, addFeed,
        analyzeArtifact, filterLogs, searchLogs, searchEvents,
        showModal, closeModal, showToast,
    };

    document.addEventListener('DOMContentLoaded', init);
})();
