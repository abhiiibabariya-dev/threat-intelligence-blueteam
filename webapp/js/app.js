// ═══════════════════════════════════════════════════════
// BLUESHELL - Hacker Terminal UI Engine
// ═══════════════════════════════════════════════════════

// ── Boot Sequence ──
const bootMessages = [
    "BLUESHELL v2.0 // Threat Intelligence Platform",
    "─────────────────────────────────────────────",
    "[BOOT] Initializing secure environment...",
    "[BOOT] Loading kernel modules..............OK",
    "[BOOT] Mounting encrypted filesystem.......OK",
    "[BOOT] Starting network stack..............OK",
    "[BOOT] Loading MITRE ATT&CK v15 framework.OK",
    "[BOOT] Initializing detection engine.......OK",
    "[LOAD] SIEM Platforms: 14 loaded",
    "[LOAD] EDR Platforms: 4 loaded",
    "[LOAD] XDR Platforms: 3 loaded",
    "[LOAD] SOAR Platforms: 7 loaded",
    "[LOAD] Detection Rules: 500+ loaded",
    "[LOAD] Threat Intel Feeds: 8 configured",
    "[SCAN] Running integrity check.............OK",
    "[SCAN] Verifying rule signatures...........OK",
    "[NET ] Connecting to OSINT feeds...........OK",
    "[NET ] abuse.ch URLhaus...................LIVE",
    "[NET ] MalwareBazaar.....................LIVE",
    "[NET ] AlienVault OTX....................LIVE",
    "[NET ] MITRE ATT&CK......................LIVE",
    "[AUTH] Security context established........OK",
    "",
    "┌─────────────────────────────────────────┐",
    "│  ____  _    _   _ _____ ____  _   _ ___ │",
    "│ | __ )| |  | | | | ____/ ___|| | | |_ _|│",
    "│ |  _ \\| |  | | | |  _| \\___ \\| |_| || | │",
    "│ | |_) | |__| |_| | |___ ___) |  _  || | │",
    "│ |____/|_____\\___/|_____|____/|_| |_|___|│",
    "│                                         │",
    "│   COMMAND CENTER // READY               │",
    "└─────────────────────────────────────────┘",
    "",
    "[READY] All systems operational. Welcome, Operator."
];

let bootIndex = 0;
const bootLog = document.getElementById('boot-log');
const bootScreen = document.getElementById('boot-screen');
const app = document.getElementById('app');

function runBoot() {
    if (bootIndex < bootMessages.length) {
        bootLog.textContent += bootMessages[bootIndex] + '\n';
        bootLog.scrollTop = bootLog.scrollHeight;
        bootIndex++;
        const delay = bootMessages[bootIndex - 1].startsWith('[') ? 60 : 30;
        setTimeout(runBoot, delay);
    } else {
        setTimeout(() => {
            bootScreen.style.opacity = '0';
            bootScreen.style.transition = 'opacity 0.5s';
            setTimeout(() => {
                bootScreen.style.display = 'none';
                app.classList.remove('hidden');
                startMatrixRain();
                startClock();
                startLiveFeed();
                animateStats();
            }, 500);
        }, 800);
    }
}

// Start boot
setTimeout(runBoot, 300);

// ── Matrix Rain ──
let matrixActive = true;

function startMatrixRain() {
    const canvas = document.getElementById('matrix-bg');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()_+-=[]{}|;:,.<>?/~`ァカサタナハマヤラワンヰヱヲ';
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = new Array(columns).fill(1);

    function draw() {
        if (!matrixActive) return;
        ctx.fillStyle = 'rgba(10, 14, 23, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff41';
        ctx.font = fontSize + 'px monospace';

        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
        requestAnimationFrame(draw);
    }
    draw();

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

function toggleMatrix() {
    matrixActive = !matrixActive;
    if (matrixActive) startMatrixRain();
}

// ── Clock ──
function startClock() {
    const clockEl = document.getElementById('clock');
    function update() {
        const now = new Date();
        clockEl.textContent = now.toISOString().substring(11, 19) + ' UTC';
    }
    update();
    setInterval(update, 1000);
}

// ── Sidebar Navigation ──
function toggleSection(id) {
    const section = document.getElementById('section-' + id);
    const arrow = document.getElementById('arrow-' + id);
    section.classList.toggle('hidden');
    arrow.classList.toggle('open');
}

// ── Page Loading ──
const pageData = {
    splunk: { title: "SPLUNK", type: "SIEM", desc: "Enterprise SIEM with SPL query language", features: ["SPL Detection Rules (9 MITRE categories)", "Correlation Rules (brute force, lateral movement, exfil)", "SOC Overview Dashboard", "Threat Hunting Dashboard", "Zero-to-Hero Training Guide", "Risk-Based Alerting (RBA)", "Enterprise Security (ES) App", "Threat Intelligence Framework"], path: "../siem-rules/splunk/" },
    sentinel: { title: "MICROSOFT SENTINEL", type: "SIEM", desc: "Cloud-native SIEM with KQL analytics", features: ["KQL Analytics Rules (6 categories)", "Hunting Queries", "Workbooks & Dashboards", "Logic App Playbooks", "UEBA Integration", "Zero-to-Hero Training Guide", "Content Hub Solutions", "Cost Optimization Guide"], path: "../siem-rules/microsoft-sentinel/" },
    qradar: { title: "IBM QRADAR", type: "SIEM", desc: "Enterprise SIEM with AQL query language", features: ["AQL Detection Rules (5 categories)", "XML Correlation & Offense Rules", "IOC Reference Sets", "Zero-to-Hero Training Guide", "QRadar SOAR Integration", "Custom Properties & DSM Config"], path: "../siem-rules/ibm-qradar/" },
    elastic: { title: "ELASTIC SIEM", type: "SIEM", desc: "Open-source SIEM with KQL and EQL", features: ["TOML Detection Rules (8 MITRE categories)", "EQL Event Queries", "Kibana Dashboards (NDJSON)", "Zero-to-Hero Training Guide", "Machine Learning Jobs", "Fleet & Elastic Agent"], path: "../siem-rules/elastic-siem/" },
    wazuh: { title: "WAZUH", type: "SIEM/XDR", desc: "Open-source security platform", features: ["XML Detection Rules (10 MITRE categories, 90+ rules)", "Custom Decoders", "Active Response Scripts", "File Integrity Monitoring", "Vulnerability Detection", "Zero-to-Hero Training Guide", "Shuffle SOAR Integration", "API Reference"], path: "../siem-rules/wazuh/" },
    exabeam: { title: "EXABEAM FUSION", type: "SIEM/UEBA", desc: "UEBA-powered SIEM platform", features: ["YAML Correlation Rules (7 categories)", "Insider Threat Detection (UEBA)", "Smart Timelines", "Peer Group Analytics", "Anomaly Scoring", "Zero-to-Hero Training Guide", "30+ Use Cases"], path: "../siem-rules/exabeam-fusion/" },
    logrhythm: { title: "LOGRHYTHM", type: "SIEM", desc: "SIEM with AI Engine analytics", features: ["AI Engine Rules (5 types: statistical, behavioral, threshold, unique, trend)", "Detection Rules (7 categories)", "SmartResponse Automation", "Zero-to-Hero Training Guide", "30+ Use Cases"], path: "../siem-rules/logrhythm/" },
    securonix: { title: "SECURONIX", type: "SIEM/UEBA", desc: "Cloud UEBA and SIEM platform", features: ["Spotter Search Queries (6 categories)", "Insider Threat Detection", "Threat Models (JSON)", "Security Policies", "Risk Scoring & Peer Groups", "Zero-to-Hero Training Guide", "30+ Use Cases"], path: "../siem-rules/securonix/" },
    mcafee: { title: "MCAFEE ESM / TRELLIX", type: "SIEM", desc: "Enterprise security manager", features: ["XML Correlation Rules (5 categories)", "Watchlists & Data Sources", "Advanced Correlation Engine", "Zero-to-Hero Training Guide", "30+ Use Cases"], path: "../siem-rules/mcafee-esm/" },
    logpoint: { title: "LOGPOINT", type: "SIEM", desc: "European SIEM with LPQL", features: ["LPQL Search Queries (6 categories)", "Alert Rules & Enrichment", "UEBA Module", "SOAR Module", "Zero-to-Hero Training Guide", "30+ Use Cases"], path: "../siem-rules/logpoint/" },
    insightidr: { title: "RAPID7 INSIGHTIDR", type: "SIEM", desc: "Cloud SIEM with LEQL", features: ["LEQL Queries (6 categories)", "Custom Alert Definitions", "Attacker Behavior Analytics", "Deception Technology", "Zero-to-Hero Training Guide", "30+ Use Cases"], path: "../siem-rules/insightidr/" },
    chronicle: { title: "GOOGLE CHRONICLE", type: "SIEM", desc: "Cloud SIEM with YARA-L", features: ["YARA-L 2.0 Detection Rules", "Entity Analytics", "UDM Data Model", "Chronicle SOAR", "Zero-to-Hero Training Guide"], path: "../siem-rules/chronicle/" },
    arcsight: { title: "ARCSIGHT ESM", type: "SIEM", desc: "Legacy enterprise SIEM", features: ["XML Correlation Rules", "Active Channels & Filters", "FlexConnector Config", "Zero-to-Hero Training Guide"], path: "../siem-rules/arcsight/" },
    fortisiem: { title: "FORTISIEM", type: "SIEM", desc: "Fortinet SIEM platform", features: ["XML Detection Rules", "FortiGuard Integration", "CMDB Auto-Discovery", "Zero-to-Hero Training Guide"], path: "../siem-rules/fortisiem/" },
    crowdstrike: { title: "CROWDSTRIKE FALCON", type: "EDR", desc: "Cloud-native endpoint protection", features: ["Custom IOA Rules (5 YAML files)", "Falcon LQL Hunting Queries", "Real Time Response (RTR)", "Zero-to-Hero Training Guide"], path: "../edr-rules/crowdstrike-falcon/" },
    mde: { title: "MICROSOFT DEFENDER FOR ENDPOINT", type: "EDR", desc: "Microsoft endpoint detection", features: ["Custom Detection Rules (JSON)", "KQL Advanced Hunting (5 categories)", "ASR Rules", "Zero-to-Hero Training Guide"], path: "../edr-rules/microsoft-defender-endpoint/" },
    sentinelone: { title: "SENTINELONE", type: "EDR", desc: "Autonomous endpoint protection", features: ["STAR Rules (JSON)", "Deep Visibility SQL Queries", "Storyline Active Response", "Zero-to-Hero Training Guide"], path: "../edr-rules/sentinelone/" },
    carbonblack: { title: "CARBON BLACK", type: "EDR", desc: "VMware endpoint security", features: ["Threat Feeds (JSON)", "Watchlist Queries", "Live Response", "Zero-to-Hero Training Guide"], path: "../edr-rules/carbon-black/" },
    cortex: { title: "PALO ALTO CORTEX XDR", type: "XDR", desc: "Extended detection & response", features: ["XQL Hunting Queries", "BIOC Rules", "Correlation Rules", "Zero-to-Hero Training Guide"], path: "../xdr-rules/palo-alto-cortex-xdr/" },
    m365: { title: "MICROSOFT 365 DEFENDER", type: "XDR", desc: "Microsoft XDR platform", features: ["Cross-Workload KQL Queries", "Custom Detections", "AIR Automation", "Zero-to-Hero Training Guide"], path: "../xdr-rules/microsoft-365-defender/" },
    visionone: { title: "TREND MICRO VISION ONE", type: "XDR", desc: "Trend Micro XDR", features: ["Detection Models (YAML)", "Search Queries", "Workbench Investigation", "Zero-to-Hero Training Guide"], path: "../xdr-rules/trend-micro-vision-one/" },
    fetcher: { title: "THREAT INTEL AUTO-FETCHER", type: "TOOL", desc: "Automated IOC collection from OSINT feeds", features: ["8 OSINT feed integrations (abuse.ch, OTX, MITRE, NIST, CISA)", "Multi-format output (JSON, CSV, STIX2)", "Auto-generate rules for 14 SIEMs", "Scheduled fetching", "Python CLI tool"], path: "../tools/" },
    rulegen: { title: "SIEM RULE GENERATOR", type: "TOOL", desc: "Convert IOCs to platform-specific detection rules", features: ["14 SIEM platform support", "Splunk SPL, Sentinel KQL, QRadar AQL", "Wazuh XML, Chronicle YARA-L", "Batch generation from IOC feeds"], path: "../tools/" },
    usecases: { title: "DETECTION USE CASE LIBRARY", type: "BLUE TEAM", desc: "100+ detection use cases mapped to MITRE ATT&CK", features: ["12 MITRE ATT&CK tactics covered", "Multi-SIEM query examples (SPL, KQL, AQL)", "False positive guidance", "Response action recommendations", "Severity scoring"], path: "../blue-team-resources/detection-engineering/" },
    ir: { title: "INCIDENT RESPONSE PLAYBOOKS", type: "BLUE TEAM", desc: "8 comprehensive IR playbooks", features: ["Phishing Response", "Ransomware Response", "Data Breach Response", "Insider Threat Response", "DDoS Response", "Supply Chain Compromise", "Cloud Security Incident", "Business Email Compromise"], path: "../blue-team-resources/incident-response/" },
    hunting: { title: "THREAT HUNTING PLAYBOOKS", type: "BLUE TEAM", desc: "Hypothesis-driven threat hunting", features: ["20+ hunting hypotheses", "Ransomware pre-encryption", "APT persistence", "Insider data theft", "Living-off-the-land", "C2 communication patterns", "Query examples (SPL + KQL)"], path: "../threat-intelligence/threat-hunting/" },
};

function loadPage(pageId) {
    const page = pageData[pageId];
    if (!page) return;

    document.getElementById('dashboard').classList.add('hidden');
    const content = document.getElementById('page-content');
    content.classList.remove('hidden');

    const featuresHtml = page.features.map(f => `<tr><td>▸ ${f}</td></tr>`).join('');

    content.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">${page.title}</h1>
                <span class="card-tag" style="position:static">${page.type}</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">${page.desc}</p>
        </div>

        <div class="section-title">⟦ AVAILABLE CONTENT ⟧</div>
        <table><tbody>${featuresHtml}</tbody></table>

        <div class="section-title" style="margin-top:24px">⟦ FILE LOCATION ⟧</div>
        <pre><code>${page.path}</code></pre>

        <div class="section-title" style="margin-top:24px">⟦ QUICK ACTIONS ⟧</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn-hack" onclick="loadPage('${pageId}')">↻ REFRESH</button>
            <button class="btn-hack" onclick="goHome()">◂ BACK TO DASHBOARD</button>
        </div>
    `;

    // Update active nav
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    event?.target?.classList?.add('active');
}

function goHome() {
    document.getElementById('dashboard').classList.remove('hidden');
    document.getElementById('page-content').classList.add('hidden');
}

// ── Terminal ──
let terminalVisible = false;

function toggleTerminal() {
    const terminal = document.getElementById('terminal');
    terminalVisible = !terminalVisible;
    terminal.classList.toggle('hidden');
    if (terminalVisible) document.getElementById('terminal-input').focus();
}

function executeCommand() {
    const input = document.getElementById('terminal-input');
    const cmd = input.value.trim();
    input.value = '';
    if (!cmd) return;

    const body = document.getElementById('terminal-body');
    body.innerHTML += `<div class="terminal-line"><span class="prompt">root@blueshell:~#</span> <span class="typed">${escapeHtml(cmd)}</span></div>`;

    const parts = cmd.toLowerCase().split(' ');
    let output = '';

    switch (parts[0]) {
        case 'help':
            output = `<span class="output">Available commands:
  help          - Show this help
  platforms     - List all platforms
  siem          - List SIEM platforms
  edr           - List EDR platforms
  xdr           - List XDR platforms
  soar          - List SOAR platforms
  tools         - List available tools
  mitre         - Show MITRE ATT&CK coverage
  fetch         - Run threat intel fetcher
  status        - System status
  clear         - Clear terminal
  whoami        - Who are you?
  matrix        - Toggle matrix rain</span>`;
            break;
        case 'platforms':
        case 'siem':
            output = `<span class="output">SIEM Platforms:
  [01] Splunk            [08] Wazuh
  [02] Microsoft Sentinel[09] Exabeam Fusion
  [03] IBM QRadar        [10] LogRhythm
  [04] Elastic SIEM      [11] Securonix
  [05] Google Chronicle   [12] McAfee ESM/Trellix
  [06] ArcSight ESM      [13] LogPoint
  [07] FortiSIEM         [14] Rapid7 InsightIDR</span>`;
            break;
        case 'edr':
            output = '<span class="output">EDR: CrowdStrike Falcon | Microsoft Defender | SentinelOne | Carbon Black</span>';
            break;
        case 'xdr':
            output = '<span class="output">XDR: Palo Alto Cortex XDR | Microsoft 365 Defender | Trend Micro Vision One</span>';
            break;
        case 'soar':
            output = '<span class="output">SOAR: Splunk SOAR | Sentinel SOAR | QRadar SOAR | XSOAR | Shuffle | TheHive | FortiSOAR</span>';
            break;
        case 'tools':
            output = '<span class="output">Tools: threat-intel-fetcher.py | siem-rule-generator.py</span>';
            break;
        case 'fetch':
            output = '<span class="output">[*] Starting threat intel fetch...\n[*] URLhaus: 200 IOCs fetched\n[*] MalwareBazaar: 150 hashes fetched\n[*] ThreatFox: 180 IOCs fetched\n[*] FeodoTracker: 95 C2 IPs fetched\n[+] Total: 625 unique IOCs collected\n[+] Run: python tools/threat-intel-fetcher.py --all</span>';
            break;
        case 'status':
            output = `<span class="output">[SYSTEM] BlueShell v2.0 - OPERATIONAL
[RULES]  500+ detection rules loaded
[FEEDS]  8/8 threat intel feeds ACTIVE
[MITRE]  70+ techniques covered
[UPTIME] ${Math.floor(Math.random()*99+1)} days</span>`;
            break;
        case 'whoami':
            output = '<span class="output">root@blueshell // SOC Operator // Blue Team</span>';
            break;
        case 'clear':
            body.innerHTML = '';
            return;
        case 'matrix':
            toggleMatrix();
            output = '<span class="output">Matrix rain toggled.</span>';
            break;
        case 'mitre':
            output = `<span class="output">MITRE ATT&CK Coverage:
  Initial Access ████████░ 89%
  Execution      ██████░░░ 69%
  Persistence    ████░░░░░ 42%
  Priv Escalation███░░░░░░ 38%
  Defense Evasion█░░░░░░░░ 19%
  Credential     █████░░░░ 56%
  Discovery      █░░░░░░░░ 19%
  Lateral Move   ██████░░░ 67%
  Exfiltration   █████░░░░ 56%
  C2             ████░░░░░ 44%</span>`;
            break;
        default:
            output = `<span class="error">Command not found: ${escapeHtml(cmd)}. Type 'help' for available commands.</span>`;
    }

    body.innerHTML += `<div class="terminal-line">${output}</div>`;
    body.scrollTop = body.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ── Live Feed ──
const feedMessages = [
    { sev: 'critical', msg: 'abuse.ch: New Emotet C2 IP detected - 185.xxx.xxx.xxx' },
    { sev: 'high', msg: 'URLhaus: 15 new malicious URLs added to blocklist' },
    { sev: 'medium', msg: 'MITRE ATT&CK: Technique T1059.001 updated with new procedures' },
    { sev: 'high', msg: 'ThreatFox: AsyncRAT IOC cluster identified - 12 indicators' },
    { sev: 'critical', msg: 'CISA KEV: New actively exploited vulnerability added' },
    { sev: 'low', msg: 'NVD: 47 new CVEs published in last 24 hours' },
    { sev: 'high', msg: 'MalwareBazaar: LockBit 3.0 sample submitted - SHA256 tracked' },
    { sev: 'medium', msg: 'Emerging Threats: 23 new Suricata rules published' },
    { sev: 'critical', msg: 'FeodoTracker: Qakbot resurgence - 8 new C2 servers' },
    { sev: 'high', msg: 'AlienVault OTX: APT29 pulse updated with new indicators' },
    { sev: 'medium', msg: 'Detection rule updated: Kerberoasting via RC4 TGS' },
    { sev: 'low', msg: 'Wazuh: 3 new decoders added for FortiGate logs' },
    { sev: 'high', msg: 'Sentinel: New fusion detection for multi-stage attack' },
    { sev: 'critical', msg: 'Splunk ES: Risk score threshold exceeded for DC01' },
    { sev: 'medium', msg: 'Chronicle: YARA-L rule matched DNS tunneling pattern' },
];

function startLiveFeed() {
    const feed = document.getElementById('live-feed');
    let idx = 0;

    setInterval(() => {
        const item = feedMessages[idx % feedMessages.length];
        const time = new Date().toISOString().substring(11, 19);
        const el = document.createElement('div');
        el.className = 'feed-item';
        el.innerHTML = `
            <span class="feed-time">${time}</span>
            <span class="feed-severity ${item.sev}">${item.sev.toUpperCase().substring(0, 4)}</span>
            <span class="feed-msg">${item.msg}</span>
        `;
        feed.insertBefore(el, feed.firstChild);
        if (feed.children.length > 20) feed.removeChild(feed.lastChild);
        idx++;
    }, 4000);
}

// ── Animate Stats ──
function animateStats() {
    document.querySelectorAll('.stat-fill').forEach(el => {
        const width = el.style.width;
        el.style.width = '0%';
        setTimeout(() => { el.style.width = width; }, 100);
    });
    document.querySelectorAll('.tactic-fill').forEach(el => {
        const width = el.style.width;
        el.style.width = '0%';
        setTimeout(() => { el.style.width = width; }, 300);
    });
}
