// ==========================================================================
// CORREL-SIEM // Main Dashboard Controller
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    // State
    let isRunning = false;
    let currentFilter = 'ALL';
    let knownIncidentIds = new Set();
    let currentIncidentInModal = null;
    let pollTimer = null;

    // DOM Elements
    const btnPlayPause = document.getElementById('btnPlayPause');
    const playIcon = document.getElementById('playIcon');
    const playPauseLabel = document.getElementById('playPauseLabel');
    const btnReset = document.getElementById('btnReset');
    const speedSelect = document.getElementById('speedSelect');
    const scenarioSelect = document.getElementById('scenarioSelect');
    const btnTriggerScenario = document.getElementById('btnTriggerScenario');
    const simStatusChip = document.getElementById('simStatusChip');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const threatKpiCard = document.getElementById('threatKpiCard');
    const threatLevelBadge = document.getElementById('threatLevelBadge');
    const kpiThreatLevel = document.getElementById('kpiThreatLevel');
    const kpiThreatSub = document.getElementById('kpiThreatSub');
    const kpiTotalLogs = document.getElementById('kpiTotalLogs');
    const kpiIncidents = document.getElementById('kpiIncidents');
    const kpiAnomaliesCount = document.getElementById('kpiAnomaliesCount');
    const kpiHighRiskUsers = document.getElementById('kpiHighRiskUsers');
    const incidentsList = document.getElementById('incidentsList');
    const incidentsBadge = document.getElementById('incidentsBadge');
    const userRiskList = document.getElementById('userRiskList');
    const rawLogTerminal = document.getElementById('rawLogTerminal');
    const chkAutoScroll = document.getElementById('chkAutoScroll');
    const logSourceFilter = document.getElementById('logSourceFilter');

    // Modals
    const incidentModal = document.getElementById('incidentModal');
    const btnCloseIncidentModal = document.getElementById('btnCloseIncidentModal');
    const btnCloseIncidentModalBtn = document.getElementById('btnCloseIncidentModalBtn');
    const modalSeverityBadge = document.getElementById('modalSeverityBadge');
    const modalIncidentTitle = document.getElementById('modalIncidentTitle');
    const modalIncidentBody = document.getElementById('modalIncidentBody');
    const modalStatusSelect = document.getElementById('modalStatusSelect');
    const btnUpdateStatus = document.getElementById('btnUpdateStatus');

    const injectModal = document.getElementById('injectModal');
    const btnOpenInjectModal = document.getElementById('btnOpenInjectModal');
    const btnCloseInjectModal = document.getElementById('btnCloseInjectModal');
    const customLogForm = document.getElementById('customLogForm');
    const injectResultBox = document.getElementById('injectResultBox');

    const rulesModal = document.getElementById('rulesModal');
    const btnViewRulesModal = document.getElementById('btnViewRulesModal');
    const btnCloseRulesModal = document.getElementById('btnCloseRulesModal');
    const rulesTableBody = document.getElementById('rulesTableBody');

    const btnExportReport = document.getElementById('btnExportReport');
    const toastContainer = document.getElementById('toastContainer');

    // Initialize Charts
    ChartsManager.initCharts();

    // Setup Event Listeners
    setupEventListeners();

    // Initial Data Fetch
    fetchStatusAndRefresh();

    // Start Polling (every 1.2 seconds)
    pollTimer = setInterval(fetchStatusAndRefresh, 1200);

    function setupEventListeners() {
        // Play / Pause
        btnPlayPause.addEventListener('click', async () => {
            if (isRunning) {
                await API.pauseSimulation();
                setSimulationUiState(false);
            } else {
                await API.startSimulation();
                setSimulationUiState(true);
            }
            fetchStatusAndRefresh();
        });

        // Reset
        btnReset.addEventListener('click', async () => {
            if (confirm("Reset SIEM buffer, logs, and incidents?")) {
                await API.resetSimulation();
                setSimulationUiState(false);
                knownIncidentIds.clear();
                incidentsList.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-radar"></div>
                        <p class="empty-title">Simulation Buffer Reset</p>
                        <p class="empty-desc">Ingestion pipeline is cleared. Ready for new stream.</p>
                    </div>`;
                rawLogTerminal.innerHTML = `
                    <div class="terminal-entry terminal-system">
                        <span class="term-time">[SYS]</span>
                        <span class="term-msg">Buffer cleared and SIEM correlation rules reloaded.</span>
                    </div>`;
                fetchStatusAndRefresh();
            }
        });

        // Speed change
        speedSelect.addEventListener('change', async (e) => {
            await API.setSpeed(e.target.value);
        });

        // Trigger Scenario
        btnTriggerScenario.addEventListener('click', async () => {
            const sc = scenarioSelect.value;
            if (!sc) {
                alert("Please select a threat scenario from the dropdown first.");
                return;
            }
            btnTriggerScenario.disabled = true;
            btnTriggerScenario.textContent = "Injecting...";
            try {
                const res = await API.triggerScenario(sc);
                showToast("Scenario Simulated", `${res.scenario} (${res.events_injected} logs injected)`);
                await fetchStatusAndRefresh();
            } catch (err) {
                console.error(err);
            } finally {
                btnTriggerScenario.disabled = false;
                btnTriggerScenario.textContent = "Simulate";
            }
        });

        // Filter Pills
        document.querySelectorAll('.filter-pill').forEach(pill => {
            pill.addEventListener('click', (e) => {
                document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
                e.target.classList.add('active');
                currentFilter = e.target.getAttribute('data-filter');
                refreshIncidents();
            });
        });

        // Log Source Filter in Terminal
        logSourceFilter.addEventListener('change', () => {
            refreshLogs();
        });

        // Custom Log Inject Modal
        btnOpenInjectModal.addEventListener('click', () => {
            injectResultBox.style.display = 'none';
            injectModal.classList.add('active');
        });

        btnCloseInjectModal.addEventListener('click', () => {
            injectModal.classList.remove('active');
        });

        customLogForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const payload = {
                user_id: document.getElementById('injectUser').value,
                source: document.getElementById('injectSource').value,
                action: document.getElementById('injectAction').value,
                details: {
                    param: document.getElementById('injectParam1').value,
                    classification: document.getElementById('injectParam2').value,
                    info: document.getElementById('injectSize').value
                },
                is_threat: document.getElementById('injectParam2').value !== 'NORMAL'
            };

            const res = await API.injectCustomLog(payload);
            injectResultBox.style.display = 'block';
            if (res.triggered_incident) {
                injectResultBox.className = 'alert-box threat';
                injectResultBox.textContent = `🚨 Alert Triggered! Injected log correlated with past events to trigger ${res.new_incidents.length} incident(s)!`;
            } else {
                injectResultBox.className = 'alert-box success';
                injectResultBox.textContent = `✅ Log event successfully ingested into correlation buffer.`;
            }

            fetchStatusAndRefresh();
        });

        // Rules Modal
        btnViewRulesModal.addEventListener('click', async () => {
            rulesModal.classList.add('active');
            const data = await API.getRules();
            renderRulesTable(data.rules || []);
        });

        btnCloseRulesModal.addEventListener('click', () => {
            rulesModal.classList.remove('active');
        });

        // Export Report
        btnExportReport.addEventListener('click', () => {
            window.location.href = '/api/export-report';
        });

        // Incident Detail Modal Close
        btnCloseIncidentModal.addEventListener('click', () => incidentModal.classList.remove('active'));
        btnCloseIncidentModalBtn.addEventListener('click', () => incidentModal.classList.remove('active'));

        // Update Incident Status
        btnUpdateStatus.addEventListener('click', async () => {
            if (!currentIncidentInModal) return;
            const newStatus = modalStatusSelect.value;
            await API.updateIncidentStatus(currentIncidentInModal.incident_id, newStatus);
            showToast("Status Updated", `Incident ${currentIncidentInModal.incident_id} is now ${newStatus}`);
            incidentModal.classList.remove('active');
            refreshIncidents();
        });

        // Close modals on background click
        [incidentModal, injectModal, rulesModal].forEach(m => {
            m.addEventListener('click', (e) => {
                if (e.target === m) m.classList.remove('active');
            });
        });
    }

    function setSimulationUiState(running) {
        isRunning = running;
        if (running) {
            statusDot.classList.add('active');
            statusText.textContent = "INGESTING";
            playIcon.innerHTML = `<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>`;
            playPauseLabel.textContent = "Pause Stream";
            btnPlayPause.classList.add('btn-primary');
        } else {
            statusDot.classList.remove('active');
            statusText.textContent = "PAUSED";
            playIcon.innerHTML = `<path d="M8 5v14l11-7z"/>`;
            playPauseLabel.textContent = "Start Stream";
        }
    }

    async function fetchStatusAndRefresh() {
        try {
            const status = await API.getStatus();
            setSimulationUiState(status.is_running);
            
            // Sync speed dropdown
            if (speedSelect.value !== status.speed.toString()) {
                speedSelect.value = status.speed.toString();
            }

            // Update KPIs
            const a = status.analytics;
            if (a) {
                updateThreatLevel(a.threat_level);
                kpiTotalLogs.textContent = a.total_logs.toLocaleString();
                kpiIncidents.textContent = a.total_incidents.toLocaleString();
                incidentsBadge.textContent = a.total_incidents.toLocaleString();
                kpiAnomaliesCount.textContent = `${a.anomalies_detected} Correlated Micro-Anomalies`;
                kpiHighRiskUsers.textContent = a.high_risk_users_count;
                kpiMonitoredIdentities.textContent = `Across ${a.active_users_tracked} Active Identities`;

                // Update charts
                ChartsManager.updateData(a);
            }

            // Refresh lists
            await Promise.all([
                refreshIncidents(),
                refreshUsers(),
                refreshLogs()
            ]);

        } catch (err) {
            console.error("Fetch status error:", err);
        }
    }

    function updateThreatLevel(level) {
        kpiThreatLevel.textContent = level;
        threatLevelBadge.textContent = level;

        threatKpiCard.classList.remove('state-critical', 'state-elevated');
        threatLevelBadge.classList.remove('badge-critical', 'badge-elevated');

        if (level === 'CRITICAL') {
            threatKpiCard.classList.add('state-critical');
            threatLevelBadge.classList.add('badge-critical');
            kpiThreatSub.textContent = "Immediate Action Required: Active Insider Violation";
        } else if (level === 'ELEVATED') {
            threatKpiCard.classList.add('state-elevated');
            threatLevelBadge.classList.add('badge-elevated');
            kpiThreatSub.textContent = "Warning: Multiple Suspicious Access Patterns Correlated";
        } else {
            kpiThreatSub.textContent = "All Ingestion Streams Nominal";
        }
    }

    async function refreshIncidents() {
        const data = await API.getIncidents(currentFilter);
        const incidents = data.incidents || [];

        if (incidents.length === 0) {
            incidentsList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-radar"></div>
                    <p class="empty-title">No Threats In Current Filter</p>
                    <p class="empty-desc">No events match filter [${currentFilter}]. Trigger a scenario to inject correlated threat patterns.</p>
                </div>`;
            return;
        }

        // Check for new critical/high incidents to pop a toast
        incidents.forEach(inc => {
            if (!knownIncidentIds.has(inc.incident_id)) {
                knownIncidentIds.add(inc.incident_id);
                showToast(`🚨 ${inc.severity} Threat Detected`, `${inc.title} (${inc.user_name})`);
            }
        });

        incidentsList.innerHTML = incidents.map(inc => {
            const sevClass = inc.severity.toLowerCase();
            const events = inc.correlated_events || [];

            // Build mini chain
            const miniChainHtml = events.slice(0, 3).map((e, idx) => `
                <div class="chain-step-node">
                    <span class="chain-icon-badge">${e.source.split(' ')[0]}</span>
                    <span>${e.action}</span>
                </div>
                ${idx < Math.min(events.length, 3) - 1 ? '<span class="chain-arrow">&rarr;</span>' : ''}
            `).join('');

            return `
                <div class="incident-item sev-${sevClass}" onclick="openIncidentForensics('${inc.incident_id}')">
                    <div class="incident-head">
                        <div class="incident-tags">
                            <span class="tag-severity tag-${sevClass}">${inc.severity}</span>
                            <span class="tag-id">${inc.incident_id}</span>
                            <span class="tag-score">Risk Score: ${inc.risk_score}/100</span>
                            <span class="rule-meta-tag">[${inc.rule_id}] ${inc.rule_name}</span>
                        </div>
                        <span class="incident-timestamp">${inc.detected_at}</span>
                    </div>

                    <div class="incident-title">${inc.title}</div>

                    <div class="incident-user-bar">
                        <span>Insider: <strong class="user-name-bold">${inc.user_name}</strong> (${inc.user_id})</span>
                        <span>&bull;</span>
                        <span>Dept: <strong>${inc.department}</strong></span>
                        <span>&bull;</span>
                        <span class="mitre-tag">${inc.mitre_technique}</span>
                    </div>

                    <p class="incident-summary-text">${inc.summary}</p>

                    <div class="correlation-mini-chain">
                        <span class="text-muted text-xs">Chain:</span>
                        ${miniChainHtml}
                        ${events.length > 3 ? `<span class="text-muted">+${events.length - 3} more</span>` : ''}
                    </div>

                    <div class="card-action-bar">
                        <button class="btn btn-outline-sm" onclick="event.stopPropagation(); openIncidentForensics('${inc.incident_id}')">
                            Forensic Investigation &rarr;
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function refreshUsers() {
        const data = await API.getUsers();
        const users = data.users || [];

        userRiskList.innerHTML = users.map(u => {
            const initials = u.user_name.split(' ').map(n => n[0]).join('');
            let fillClass = 'fill-low';
            if (u.risk_score >= 80) fillClass = 'fill-critical';
            else if (u.risk_score >= 60) fillClass = 'fill-high';
            else if (u.risk_score >= 35) fillClass = 'fill-medium';

            return `
                <div class="user-risk-row">
                    <div class="user-row-header">
                        <div class="user-identity">
                            <div class="user-avatar-circle">${initials}</div>
                            <div>
                                <div class="user-name-title">${u.user_name}</div>
                                <div class="user-dept-text">${u.department} &bull; ${u.user_id}</div>
                            </div>
                        </div>
                        <span class="user-score-badge ${fillClass.replace('fill-', 'text-')}">${u.risk_score}/100</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-fill ${fillClass}" style="width: ${u.risk_score}%"></div>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function refreshLogs() {
        const source = logSourceFilter.value;
        const data = await API.getLogs(40, source);
        const logs = data.logs || [];

        if (logs.length === 0) return;

        // Render in chronological order inside terminal
        const reversed = [...logs].reverse();

        rawLogTerminal.innerHTML = reversed.map(l => {
            const isThreat = l.is_synthetic_threat ? 'term-threat' : '';
            const detailsStr = Object.entries(l.details || {})
                .map(([k, v]) => `${k}=${v}`)
                .join(' ');

            return `
                <div class="terminal-entry ${isThreat}">
                    <span class="term-time">${l.timestamp.split(' ')[1]}</span>
                    <span class="term-src">${l.source.split(' ')[0]}</span>
                    <span class="term-user">${l.user_id}</span>
                    <span class="term-action">${l.action}</span>
                    <span class="term-details">${detailsStr}</span>
                </div>
            `;
        }).join('');

        if (chkAutoScroll.checked) {
            rawLogTerminal.scrollTop = rawLogTerminal.scrollHeight;
        }
    }

    // Window global for onclick forensic modal
    window.openIncidentForensics = async function(incidentId) {
        const inc = await API.getIncidentDetails(incidentId);
        if (!inc) return;

        currentIncidentInModal = inc;
        modalSeverityBadge.textContent = inc.severity;
        modalSeverityBadge.className = `modal-severity-badge tag-${inc.severity.toLowerCase()}`;
        modalIncidentTitle.textContent = `${inc.title} [${inc.incident_id}]`;
        modalStatusSelect.value = inc.status || 'OPEN';

        // Render Evidence timeline
        const events = inc.correlated_events || [];
        const timelineStepsHtml = events.map((e, idx) => {
            const rawDetails = JSON.stringify(e.details, null, 2);
            return `
                <div class="timeline-step">
                    <div class="step-meta">
                        <span class="step-src-badge">[STEP #${idx + 1}] ${e.source}</span>
                        <span>${e.timestamp}</span>
                    </div>
                    <div class="step-action-title">${e.action}</div>
                    <div class="step-raw-box"><pre>${rawDetails}</pre></div>
                </div>
            `;
        }).join('');

        const recommendationsHtml = (inc.recommendations || []).map(r => `<li>${r}</li>`).join('');

        modalIncidentBody.innerHTML = `
            <div>
                <p><strong>Correlated SIEM Rule:</strong> [${inc.rule_id}] ${inc.rule_name}</p>
                <p><strong>MITRE ATT&CK Classification:</strong> <span class="mitre-tag">${inc.mitre_technique}</span></p>
                <p><strong>Composite Risk Score:</strong> <strong class="text-crimson">${inc.risk_score} / 100</strong></p>
                <p style="margin-top:8px; color: var(--text-secondary);">${inc.summary}</p>
            </div>

            <div>
                <h4 style="color:#fff; margin-bottom: 12px; font-size: 0.95rem;">Forensic Correlation Chain (${events.length} Disparate Events Linked):</h4>
                <div class="evidence-timeline">
                    ${timelineStepsHtml}
                </div>
            </div>

            <div class="recommendations-box">
                <div class="rec-title">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>Recommended SOC Containment & Remediation Actions</span>
                </div>
                <ul class="rec-list">
                    ${recommendationsHtml}
                </ul>
            </div>
        `;

        incidentModal.classList.add('active');
    };

    function renderRulesTable(rules) {
        rulesTableBody.innerHTML = rules.map(r => `
            <tr>
                <td><strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${r.rule_id}</strong></td>
                <td>
                    <strong>${r.name}</strong>
                    <div style="font-size:0.72rem; color:var(--text-muted);">${r.description}</div>
                </td>
                <td><span class="tag-severity tag-${r.severity.toLowerCase()}">${r.severity}</span></td>
                <td><span class="mitre-tag">${r.mitre_technique}</span></td>
                <td style="font-family:var(--font-mono);">${r.time_window_seconds / 60} mins</td>
                <td style="font-family:var(--font-mono); font-weight:700;">${r.base_risk_score}</td>
            </tr>
        `).join('');
    }

    function showToast(title, msg) {
        const toast = document.createElement('div');
        toast.className = 'threat-toast';
        toast.innerHTML = `
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-msg">${msg}</div>
            </div>
        `;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.transition = 'all 0.3s ease';
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }
});
