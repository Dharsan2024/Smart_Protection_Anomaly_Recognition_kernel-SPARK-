/*
 * SPARK WEB UI
 * Core Application Logic (WebSockets, ApexCharts, AI Analyst)
 */

// ═══════════════════════════════════════════════════════
// STATE & CONFIG
// ═══════════════════════════════════════════════════════
const API_BASE = 'http://localhost:8000/api';
const WS_URL = 'ws://localhost:8000/ws/stream';

let ws = null;
let isRunning = false;
let startTime = Date.now();
let uptimeInterval = null;

// Kill Switch & Gemini State
let isolatedIds = new Set();
let lastThreatId = null;
let activeGeminiContent = null;
let activeClassification = null;

// Chart Instances
let timelineChart = null;
let donutChart = null;

// Data Buffers
const MAX_DATAPOINTS = 50;
const historyData = {
    labels: [],
    normal: [],
    dos: [],
    fuzzy: [],
    spoofing: [],
    replay: []
};

// Threat Knowledge Base
const THREAT_INTEL = {
    'DoS': {
        title: 'Denial of Service (DoS) Attack',
        mechanism: 'Flooding the network with highest-priority CAN ID 0x000.',
        impact: ['Legitimate ECUs blocked', 'Loss of power steering / ABS'],
        mitigation: ['CAN message rate limiting', 'Hardware ID filtering'],
        severity: 'CRITICAL',
        mitre: 'T0800', cve: 'CVE-2022-26269'
    },
    'Fuzzy': {
        title: 'Fuzzy Injection Attack',
        mechanism: 'Injecting massive volumes of randomized CAN IDs and payloads.',
        impact: ['Chaotic behavior across multiple ECUs', 'Unintended actuation'],
        mitigation: ['CAN ID whitelist filtering', 'Entropy anomaly thresholds'],
        severity: 'HIGH',
        mitre: 'T0803', cve: 'CVE-2019-12797'
    },
    'Spoofing': {
        title: 'ECU Impersonation Attack',
        mechanism: 'Injecting fabricated payloads on known IDs (e.g., RPM 0x316).',
        impact: ['Targeted physical malfunctions', 'False sensor data decisions'],
        mitigation: ['Message Authentication Codes (MAC)', 'Rolling counters'],
        severity: 'CRITICAL',
        mitre: 'T0856', cve: 'CVE-2020-8539'
    },
    'Replay': {
        title: 'Sequence Replay Attack',
        mechanism: 'Re-injecting captured legitimate traffic out of context.',
        impact: ['Bypasses payload inspection', 'Triggers outdated vehicle states'],
        mitigation: ['Timestamp freshness validation', 'LSTM temporal analysis'],
        severity: 'HIGH',
        mitre: 'T0882', cve: 'CVE-2021-22156'
    }
};

// ═══════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    setupEventListeners();
    connectWebSocket();
    startUptimeClock();
});

function setupEventListeners() {
    // Controls
    document.getElementById('btn-start').addEventListener('click', () => sendControlCommand('start'));
    document.getElementById('btn-stop').addEventListener('click', () => sendControlCommand('stop'));
    document.getElementById('btn-reset').addEventListener('click', () => sendControlCommand('reset'));
    
    // Sliders — sync label text AND CSS gradient fill
    function updateSliderFill(slider) {
        const min = parseFloat(slider.min) || 0;
        const max = parseFloat(slider.max) || 100;
        const val = ((parseFloat(slider.value) - min) / (max - min)) * 100;
        slider.style.setProperty('--val', val + '%');
    }

    const sliders = [
        { id: 'attack-dur', valId: 'dur-val', unit: 's' },
        { id: 'attack-int', valId: 'int-val', unit: '%' }
    ];

    sliders.forEach(s => {
        const el = document.getElementById(s.id);
        const valEl = document.getElementById(s.valId);
        if (el && valEl) {
            el.addEventListener('input', (e) => {
                valEl.textContent = e.target.value + s.unit;
                updateSliderFill(e.target);
            });
            // Initial fill
            updateSliderFill(el);
        }
    });

    // Fallback wrapper for safe listener attachment
    const addListenerIfExist = (id, event, callback) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener(event, callback);
    };

    // Inject
    addListenerIfExist('btn-inject', 'click', injectAttack);
    
    // Kill Switch
    addListenerIfExist('btn-kill-switch', 'click', activateKillSwitch);
    
    // PDF Export
    addListenerIfExist('btn-export-pdf', 'click', exportIncidentReport);

    // Auto-IPS Toggle
    addListenerIfExist('btn-auto-ips', 'click', toggleAutoIPS);

    // Audit Modal
    addListenerIfExist('btn-audit', 'click', runSystemAudit);
    // AI Analyst Manual Trigger
    addListenerIfExist('btn-analyze-threat', 'click', analyzeLatestThreat);

    addListenerIfExist('btn-close-modal', 'click', () => {
        document.getElementById('audit-modal').style.display = 'none';
    });
}

// ═══════════════════════════════════════════════════════
// AUTONOMOUS IPS LOGIC
// ═══════════════════════════════════════════════════════
let autoIPSEnabled = false;

async function toggleAutoIPS() {
    autoIPSEnabled = !autoIPSEnabled;
    const btn = document.getElementById('btn-auto-ips');
    
    // Optimistic UI Update
    if (autoIPSEnabled) {
        btn.innerHTML = '<span class="ips-icon">🤖</span> AUTO-IPS: ACTIVE';
        btn.classList.remove('ips-inactive');
        btn.classList.add('ips-active');
    } else {
        btn.innerHTML = '<span class="ips-icon">🤖</span> AUTO-IPS: OFFLINE';
        btn.classList.remove('ips-active');
        btn.classList.add('ips-inactive');
    }
    
    try {
        await fetch(`${API_BASE}/control/auto-ips`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: autoIPSEnabled })
        });
    } catch (e) {
        console.error(`Failed to toggle Auto-IPS:`, e);
        // Revert UI on failure
        autoIPSEnabled = !autoIPSEnabled;
        if (!autoIPSEnabled) { // meaning it failed to turn ON
            btn.innerHTML = '<span class="ips-icon">🤖</span> AUTO-IPS: OFFLINE';
            btn.classList.remove('ips-active');
            btn.classList.add('ips-inactive');
        } else {
            btn.innerHTML = '<span class="ips-icon">🤖</span> AUTO-IPS: ACTIVE';
            btn.classList.remove('ips-inactive');
            btn.classList.add('ips-active');
        }
    }
}

// ═══════════════════════════════════════════════════════
// WEBSOCKETS & API
// ═══════════════════════════════════════════════════════
function connectWebSocket() {
    ws = new WebSocket(WS_URL);
    
    ws.onopen = () => {
        console.log("🟢 WebSocket Connected");
        updateSystemStatus(isRunning); 
    };
    
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleStreamData(msg);
    };
    
    ws.onclose = () => {
        console.warn("🔴 WebSocket Disconnected. Reconnecting in 3s...");
        setTimeout(connectWebSocket, 3000);
    };
}

function handleStreamData(payload) {
    const { type, data } = payload;
    
    if (type === 'system_state') {
        isRunning = data.is_running;
        updateSystemStatus(isRunning);
        if (data.models_loaded) {
            updateModelStatus('xgb', data.models_loaded.xgb);
            updateModelStatus('rf', data.models_loaded.rf);
            updateModelStatus('iso', data.models_loaded.iso);
            updateModelStatus('lstm', data.models_loaded.lstm);
        }
    } 
    else if (type === 'metrics') {
        console.log("Metrics received:", data);
        updateKPIs(data.stats, data.threats);
        updateDonutChart(data.threats.counts);
    } 
    else if (type === 'verdict') {
        const cls = data.classification;
        
        // Track the last anomalous ID for the Kill Switch
        if (cls !== 'Normal') lastThreatId = data.can_id_hex;
        
        // Don't render metrics for this message if it's already from an isolated ID
        if (isolatedIds.has(data.can_id_hex)) return;
        
        if (data.auto_mitigated) {
            triggerGlobalAlert('protected');
            appendThreatFeed(data); 
            // We DO want to chart the packet to visualize the blocked attack, but NOT trigger 'compromised'
            updateTimelineData(data);
            return;
        }

        appendThreatFeed(data);
        updateTimelineData(data);
        
        if (cls !== 'Normal') {
            triggerGlobalAlert('compromised');
            document.getElementById('btn-analyze-threat').style.display = 'inline-block';
        }
    }
    else if (type === 'ai_insight_loading') {
        renderAILoading(data.classification);
        document.getElementById('btn-export-pdf').style.display = 'none';
    }
    else if (type === 'ai_insight') {
        activeClassification = data.classification;
        activeGeminiContent = data.content;
        renderAIGemini(data.classification, data.content);
        document.getElementById('btn-export-pdf').style.display = 'inline-block';
        document.getElementById('btn-analyze-threat').style.display = 'none';
    }
    else if (type === 'system_reset') {
        // Clear all arrays
        historyData.labels = [];
        historyData.normal = [];
        historyData.dos = [];
        historyData.fuzzy = [];
        historyData.spoofing = [];
        historyData.replay = [];
        currentCounts = { normal: 0, dos: 0, fuzzy: 0, spoofing: 0, replay: 0 };
        currentSecond = Math.floor(Date.now() / 1000);
        
        donutChart.updateSeries([0, 0, 0, 0, 0]);
        
        document.getElementById('threat-feed').innerHTML = '<div class="feed-empty">Awaiting incoming CAN bus traffic...</div>';
        document.getElementById('kpi-pps').textContent = '0';
        document.getElementById('kpi-total').textContent = '0';
        document.getElementById('kpi-threats').textContent = '0';
        document.getElementById('kpi-ratio').textContent = '0.0%';
        resetAIAnalyst();
        
        // Reset Time
        document.getElementById('uptime-clock').textContent = "00:00:00";
        startTime = Date.now();
    }
    else if (type === 'quarantine_update') {
        if (data.action === 'isolated') {
            isolatedIds.add(data.can_id_hex);
            console.log("Isolated entity:", data.can_id_hex);
            
            // Hide the manual kill switch
            const ks = document.getElementById('kill-switch-container');
            if(ks) ks.style.display = 'none';
            // Also hide the analyze button if an action was just taken
            const btnAnalyze = document.getElementById('btn-analyze-threat');
            if (btnAnalyze) btnAnalyze.style.display = 'none';
            
            // If this was an autonomous action, inject a prominent alert into the feed
            if (data.auto) {
                const feed = document.getElementById('threat-feed');
                const alertHtml = `
                    <div class="threat-item glass-panel" style="border-left: 4px solid var(--accent-cyan); background: rgba(56, 189, 248, 0.1);">
                        <div class="threat-header">
                            <span class="threat-title" style="color: var(--accent-cyan);">⚡ AUTO-MITIGATION ENFORCED</span>
                            <span class="threat-time">${new Date().toISOString().split('T')[1].slice(0,-1)}</span>
                        </div>
                        <div class="threat-details">
                            Intrusion attempt blocked. The compromised physical ECU port has been perfectly isolated from the network.
                        </div>
                    </div>
                `;
                feed.insertAdjacentHTML('afterbegin', alertHtml);
                
                // Keep feed scrollable but trim old items
                if (feed.children.length > 50) feed.lastElementChild.remove();
            }
        } else {
            isolatedIds.clear();
        }
    }
}

async function sendControlCommand(action) {
    try {
        await fetch(`${API_BASE}/control/${action}`, { method: 'POST' });
    } catch (e) {
        console.error(`Failed to ${action} engine:`, e);
    }
}

async function injectAttack() {
    if (!isRunning) return alert("System is IDLE. Start the engine first.");
    
    const type = document.getElementById('attack-type').value;
    const dur = parseInt(document.getElementById('attack-dur').value);
    const intensity = parseInt(document.getElementById('attack-int').value);
    
    const btn = document.getElementById('btn-inject');
    btn.textContent = "INJECTING...";
    btn.disabled = true;
    
    try {
        await fetch(`${API_BASE}/attacks/inject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: type, duration: dur, intensity: intensity })
        });
        
        const statusMsg = document.getElementById('attack-status-msg');
        statusMsg.className = "attack-status-active";
        statusMsg.style.color = "var(--accent-red)";
        statusMsg.textContent = `🚨 ${type} Attack Deployed!`;
        
        setTimeout(() => {
            statusMsg.className = "attack-status-hidden";
            btn.textContent = "🚀 LAUNCH ATTACK";
            btn.disabled = false;
        }, 3000);
        
    } catch (e) {
        console.error("Injection failed:", e);
        btn.textContent = "🚀 LAUNCH ATTACK";
        btn.disabled = false;
    }
}

async function analyzeLatestThreat() {
    const btn = document.getElementById('btn-analyze-threat');
    btn.disabled = true;
    btn.textContent = "🛰️ ANALYZING...";
    
    try {
        const resp = await fetch(`${API_BASE}/gemini/analyze`, { method: 'POST' });
        const data = await resp.json();
        if (data.status === 'error') {
            alert(data.message);
            btn.disabled = false;
            btn.textContent = "🛰️ ANALYZE THREAT";
        }
    } catch (e) {
        console.error("AI Analysis failed:", e);
        btn.disabled = false;
        btn.textContent = "🛰️ ANALYZE THREAT";
    }
}

async function activateKillSwitch() {
    if (!lastThreatId) return;
    
    try {
        await fetch(`${API_BASE}/control/isolate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ can_id_hex: lastThreatId })
        });
        
        // Visual feedback
        const btn = document.getElementById('btn-kill-switch');
        btn.textContent = `🛑 ECU ${lastThreatId} ISOLATED`;
        btn.style.animation = "none";
        btn.className = "btn";
        btn.style.background = "var(--accent-red)";
        
        setTimeout(() => {
            document.getElementById('kill-switch-container').style.display = 'none';
            btn.textContent = "⚠️ ISOLATE COMPROMISED ECU";
            btn.style.animation = "pulseAlert 1.5s infinite";
            btn.className = "btn btn-danger";
            btn.style.background = "";
        }, 3000);
        
    } catch (e) {
        console.error("Kill Switch failed:", e);
    }
}

// ═══════════════════════════════════════════════════════
// UI UPDATERS
// ═══════════════════════════════════════════════════════
function startUptimeClock() {
    setInterval(() => {
        if (!isRunning) return;
        const now = Date.now();
        const diff = new Date(now - startTime);
        document.getElementById('uptime-clock').textContent = diff.toISOString().substr(11, 8);
    }, 1000);
}

function updateSystemStatus(active) {
    const box = document.getElementById('status-indicator');
    const text = document.getElementById('status-text');
    
    if (active) {
        box.className = "status-box status-active";
        text.textContent = "SYSTEM ACTIVE";
        if (historyData.labels.length === 0) startTime = Date.now();
    } else {
        box.className = "status-box status-idle";
        text.textContent = "SYSTEM IDLE";
    }
}

function updateModelStatus(id, active) {
    const el = document.getElementById(`mod-${id}`);
    if (!el) return;
    el.className = active ? 'badge bg-green' : 'badge bg-red';
    el.textContent = active ? 'ACTIVE' : 'OFFLINE';
}

function triggerGlobalAlert(stateType) {
    const display = document.getElementById('global-threat-display');
    if (!display) return;
    const val = display.querySelector('.threat-value');
    
    // Clear any existing reset timeout
    if (window.alertTimeout) clearTimeout(window.alertTimeout);

    if (stateType === 'compromised') {
        val.textContent = "COMPROMISED";
        val.className = "threat-value danger";
        val.style.textShadow = "none";
        val.style.color = "";
        
        const ks = document.getElementById('kill-switch-container');
        if (ks) ks.style.display = 'block';
        
        window.alertTimeout = setTimeout(() => {
            val.textContent = "SECURE";
            val.className = "threat-value safe";
            if (ks) ks.style.display = 'none';
            const exp = document.getElementById('btn-export-pdf');
            if (exp) exp.style.display = 'none';
            resetAIAnalyst();
        }, 5000);
    } else if (stateType === 'protected') {
        val.textContent = "SECURE (PROTECTED)";
        val.className = "threat-value safe";
        val.style.textShadow = "0 0 10px rgba(56, 189, 248, 0.8)";
        val.style.color = "var(--accent-cyan)";
        
        const ks = document.getElementById('kill-switch-container');
        if (ks) ks.style.display = 'none';
        
        window.alertTimeout = setTimeout(() => {
            val.textContent = "SECURE";
            val.className = "threat-value safe";
            val.style.textShadow = "none";
            val.style.color = "";
        }, 3000);
    }
}

function updateKPIs(stats, threats) {
    document.getElementById('kpi-pps').textContent = Math.round(stats.messages_per_second).toLocaleString();
    
    let t = threats.total_analyzed;
    let t_str = t >= 1000000 ? (t/1000000).toFixed(1)+'M' : (t >= 1000 ? (t/1000).toFixed(1)+'K' : t);
    document.getElementById('kpi-total').textContent = t_str;
    
    document.getElementById('kpi-threats').textContent = threats.total_threats.toLocaleString();
    
    // Live Threats: Sum of non-normal counts in the current second
    const liveThreats = (currentCounts.dos || 0) + (currentCounts.fuzzy || 0) + 
                        (currentCounts.spoofing || 0) + (currentCounts.replay || 0);
    document.getElementById('kpi-live-threats').textContent = liveThreats.toLocaleString();
    
    // Alert styling applied if threats exist
    const threatCard = document.getElementById('card-threats');
    if (threats.total_threats > 0) threatCard.classList.add('kpi-alert');
}

// ═══════════════════════════════════════════════════════
// APEXCHARTS
// ═══════════════════════════════════════════════════════
function initCharts() {
    const commonOpts = {
        chart: {
            background: 'transparent',
            toolbar: { show: false },
            animations: {
                enabled: true,
                easing: 'linear',
                dynamicAnimation: { speed: 800 }
            }
        },
        theme: { mode: 'dark' }
    };

    // Timeline Area Chart
    const lineOpts = {
        ...commonOpts,
        chart: { ...commonOpts.chart, type: 'area', height: 280, stacked: false },
        colors: ['#10B981', '#ef233c', '#8b5cf6', '#eab308', '#06b6d4'],
        dataLabels: { enabled: false },
        stroke: { curve: 'smooth', width: [2, 3, 3, 3, 3] },
        fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0.05 } },
        series: [
            { name: 'Normal', data: [] },
            { name: 'DoS', data: [] },
            { name: 'Fuzzy', data: [] },
            { name: 'Spoofing', data: [] },
            { name: 'Replay', data: [] }
        ],
        xaxis: { categories: [], labels: { show: false }, axisBorder: { show: false }, axisTicks: { show: false } },
        yaxis: { labels: { style: { colors: '#64748B' } } },
        legend: { position: 'top', horizontalAlign: 'right', labels: { colors: '#94A3B8' } }
    };
    timelineChart = new ApexCharts(document.querySelector("#timeline-chart"), lineOpts);
    timelineChart.render();

    // Donut Chart
    const donutOpts = {
        ...commonOpts,
        chart: { ...commonOpts.chart, type: 'donut', height: 280 },
        colors: ['#10B981', '#ef233c', '#8b5cf6', '#eab308', '#06b6d4'],
        series: [0, 0, 0, 0, 0],
        labels: ['Normal', 'DoS', 'Fuzzy', 'Spoofing', 'Replay'],
        dataLabels: { enabled: false },
        stroke: { show: true, colors: ['#050814'], width: 2 },
        plotOptions: { pie: { donut: { size: '65%' } } },
        legend: { position: 'right', labels: { colors: '#94A3B8' } }
    };
    donutChart = new ApexCharts(document.querySelector("#donut-chart"), donutOpts);
    donutChart.render();
    
    // Periodic Chart Updater Loop
    setInterval(() => {
        if (!isRunning) return;
        
        // Push finished second into history
        const now = Math.floor(Date.now() / 1000);
        if (now > currentSecond) {
            historyData.labels.push(new Date(currentSecond*1000).toLocaleTimeString());
            historyData.normal.push(currentCounts.normal);
            historyData.dos.push(currentCounts.dos);
            historyData.fuzzy.push(currentCounts.fuzzy);
            historyData.spoofing.push(currentCounts.spoofing);
            historyData.replay.push(currentCounts.replay);
            
            if (historyData.labels.length > MAX_DATAPOINTS) {
                historyData.labels.shift();
                historyData.normal.shift();
                historyData.dos.shift();
                historyData.fuzzy.shift();
                historyData.spoofing.shift();
                historyData.replay.shift();
            }
            
            currentSecond = now;
            currentCounts = { normal: 0, dos: 0, fuzzy: 0, spoofing: 0, replay: 0 };
        }

        timelineChart.updateSeries([
            { data: historyData.normal },
            { data: historyData.dos },
            { data: historyData.fuzzy },
            { data: historyData.spoofing },
            { data: historyData.replay }
        ]);
    }, 1000);
}

// Bin verdicts into seconds for the timeline
let currentSecond = Math.floor(Date.now() / 1000);
let currentCounts = { normal: 0, dos: 0, fuzzy: 0, spoofing: 0, replay: 0 };

function updateTimelineData(verdict) {
    const c = verdict.classification.toLowerCase();
    if (currentCounts[c] !== undefined) currentCounts[c]++;
}

function updateDonutChart(counts) {
    const series = [
        counts['Normal'] || 0,
        counts['DoS'] || 0,
        counts['Fuzzy'] || 0,
        counts['Spoofing'] || 0,
        counts['Replay'] || 0
    ];
    // Don't update if nothing has changed to avoid flicker
    if (series.reduce((a, b) => a + b, 0) > 0) {
        donutChart.updateSeries(series);
    }
}

// ═══════════════════════════════════════════════════════
// FEED & AI ANALYST
// ═══════════════════════════════════════════════════════
function appendThreatFeed(verdict) {
    const feed = document.getElementById('threat-feed');
    const empty = feed.querySelector('.feed-empty');
    if (empty) empty.remove();
    
    const isThreat = verdict.classification !== 'Normal';
    
    // Only show threats and occasional normal packets (1%) to prevent browser lag
    if (!isThreat && Math.random() > 0.01) return;
    
    let icon = isThreat ? '🚨' : '🟢';
    let clsName = `alert-${verdict.classification.toLowerCase()}`;
    let timeRaw = new Date();
    let timeStr = `${timeRaw.getHours()}:${timeRaw.getMinutes()}:${timeRaw.getSeconds()}.${timeRaw.getMilliseconds()}`;
    
    const item = document.createElement('div');
    item.className = `feed-item ${clsName}`;
    item.innerHTML = `
        <div class="feed-icon">${icon}</div>
        <div class="feed-content">
            <div class="feed-header">
                <span class="feed-type">${verdict.classification.toUpperCase()} DETECTED</span>
                <span class="feed-time">${timeStr}</span>
            </div>
            <div class="feed-meta">
                ID: <span class="feed-id">${verdict.can_id_hex}</span> | 
                Conf: ${Math.round(verdict.confidence * 100)}% | 
                Sev: ${verdict.severity}
            </div>
        </div>
    `;
    
    feed.prepend(item);
    
    // Limit feed size
    while (feed.children.length > 30) feed.removeChild(feed.lastChild);
}

// Gemini 2.5 UI Renderers
function renderAILoading(classification) {
    const container = document.getElementById('ai-analyst-content');
    container.innerHTML = `
        <div class="intel-card">
            <div class="intel-header">
                <span class="intel-title" style="color: var(--accent-cyan);">🧠 Gemini AI Analyst Querying...</span>
                <span class="intel-sev">ANALYZING ${classification.toUpperCase()}</span>
            </div>
            <div class="intel-desc">
                <em>Extracting threat intelligence via Google Generative AI...</em>
            </div>
        </div>
    `;
}

function renderAIGemini(classification, markdownContent) {
    const container = document.getElementById('ai-analyst-content');
    
    // Pre-process markdown for custom classes
    let htmlContent = marked.parse(markdownContent);
    
    container.innerHTML = `
        <div class="intel-card gemini-card">
            <div class="intel-header">
                <span class="intel-title">🧠 Gemini 2.5 Flash Insight</span>
                <span class="intel-sev">${classification.toUpperCase()}</span>
            </div>
            <div class="gemini-content">
                ${htmlContent}
            </div>
        </div>
    `;
}

function resetAIAnalyst() {
    const container = document.getElementById('ai-analyst-content');
    container.innerHTML = `
        <div class="analyst-safe">
            <div class="icon">✅</div>
            <h4>All Systems Nominal</h4>
            <p>The dual-layer AI detection engine is actively monitoring all CAN bus traffic. No anomalous patterns have been detected. Payload entropy and frequencies are within operational parameters.</p>
        </div>
    `;
}

// ═══════════════════════════════════════════════════════
// REPORT EXPORT
// ═══════════════════════════════════════════════════════
async function exportIncidentReport() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
    doc.setFont("helvetica", "bold");
    doc.text("SPARK AI Incident Report", 20, 20);
    
    doc.setFont("helvetica", "normal");
    doc.text("Classification: " + (activeClassification || "Unknown").toUpperCase(), 20, 30);
    
    const splitText = doc.splitTextToSize(activeGeminiContent || "No AI insight available.", 170);
    doc.text(splitText, 20, 45);
    
    doc.save("spark-incident-report.pdf");
}

async function runSystemAudit() {
    const modal = document.getElementById('audit-modal');
    const result = document.getElementById('audit-result');
    
    modal.style.display = 'flex';
    result.innerHTML = '<div class="loading-spinner"></div><p>Gemini is auditing system telemetry and ECU behavior patterns...</p>';
    
    try {
        const resp = await fetch(`${API_BASE}/gemini/forensics`, { method: 'POST' });
        const data = await resp.json();
        
        if (data.audit) {
            result.innerHTML = marked.parse(data.audit);
        } else {
            result.innerHTML = `<p class="error">Audit failed: ${data.error || 'Unknown error'}</p>`;
        }
    } catch (e) {
        result.innerHTML = `<p class="error">Connection error: ${e.message}</p>`;
    }
}
