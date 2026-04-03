// ═══════════════════════════════════════════════════════
// BLUESHELL - SOC Dashboard Engine v3.0
// ═══════════════════════════════════════════════════════

// ── Initialize App (no boot sequence) ──
const app = document.getElementById('app');

let _appInitialized = false;
function initApp() {
    if (_appInitialized) return;
    _appInitialized = true;
    startClock();
    startLiveFeed();
    setTimeout(animateStats, 200);
}

// Start when ready
document.addEventListener('DOMContentLoaded', initApp);
setTimeout(initApp, 300);

// ── Mobile Menu ──
function toggleMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    sidebar.classList.toggle('sidebar-open');
    overlay.classList.toggle('active');
}

// ── Matrix Rain (disabled for clean theme) ──
function startMatrixRain() { /* disabled */ }
function toggleMatrix() { /* disabled */ }

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
    rulebuilder: { title: "RULE BUILDER", type: "TOOL", desc: "Drag-and-drop visual SIEM rule & use case builder", features: ["Visual drag-and-drop rule composition", "7 SIEM platform output formats", "MITRE ATT&CK tactic mapping", "Use case metadata & export", "Splunk SPL, Sentinel KQL, QRadar AQL, Elastic EQL, Wazuh XML, Chronicle YARA-L, Sigma"], path: "interactive" },
    splunksoar: { title: "SPLUNK SOAR (PHANTOM)", type: "SOAR", desc: "Security orchestration, automation & response by Splunk", features: ["Visual Playbook Editor", "400+ App Integrations", "Custom Actions & Python Playbooks", "Case Management & SLA Tracking", "Clustering & HA Deployment", "REST API & Webhooks", "Zero-to-Hero Training Guide", "Community Playbook Templates"], path: "../soar/splunk-soar/" },
    sentinelsoar: { title: "MICROSOFT SENTINEL SOAR", type: "SOAR", desc: "Logic Apps-based automation for Sentinel", features: ["Logic App Playbooks (ARM Templates)", "Automation Rules & Triggers", "Entity-Based Playbooks", "Incident Management Automation", "Azure Functions Integration", "Watchlist Enrichment", "Zero-to-Hero Training Guide", "Cost-Optimized Automation Patterns"], path: "../soar/sentinel-soar/" },
    xsoar: { title: "PALO ALTO XSOAR", type: "SOAR", desc: "Cortex XSOAR orchestration platform", features: ["Playbook YAML Definitions", "700+ Content Pack Integrations", "War Room & Collaboration", "Indicator Management (TIM)", "Custom Automation Scripts (Python)", "Machine Learning-Assisted Triage", "Zero-to-Hero Training Guide", "Marketplace Content Packs"], path: "../soar/palo-alto-xsoar/" },
    qradarsoar: { title: "IBM QRADAR SOAR (RESILIENT)", type: "SOAR", desc: "Incident response orchestration platform", features: ["Dynamic Playbooks & Tasks", "NIST/SANS Framework Alignment", "Breach Response Module", "Privacy & Compliance Workflows", "REST API Functions", "Custom Actions & Scripts", "Zero-to-Hero Training Guide", "Threat Intelligence Integration"], path: "../soar/qradar-soar/" },
    shuffle: { title: "SHUFFLE SOAR", type: "SOAR", desc: "Open-source SOAR with visual workflow builder", features: ["Visual Drag-and-Drop Workflows", "OpenAPI App Generation", "Webhook Triggers & Schedules", "Wazuh & TheHive Integration", "Docker-Based Architecture", "Community Workflow Library", "Zero-to-Hero Training Guide", "Self-Hosted Deployment Guide"], path: "../soar/shuffle-soar/" },
    thehive: { title: "THEHIVE + CORTEX", type: "SOAR", desc: "Open-source incident response & analysis", features: ["Case & Task Management", "Observable Analysis (Cortex Analyzers)", "30+ Cortex Responders", "MISP Integration", "Alert Feeder System", "Custom Dashboards & Metrics", "Zero-to-Hero Training Guide", "Multi-Tenant Support"], path: "../soar/thehive-cortex/" },
    fortisoar: { title: "FORTISOAR", type: "SOAR", desc: "Fortinet security orchestration platform", features: ["Playbook Designer (JSON/YAML)", "350+ Connector Integrations", "Recommendation Engine (ML)", "War Room Collaboration", "Role-Based Access Control", "FortiGuard Integration", "Zero-to-Hero Training Guide", "SOC Maturity Assessment Tools"], path: "../soar/fortisoar/" },
    ioc: { title: "IOC MANAGEMENT", type: "TOOL", desc: "Indicator of Compromise lifecycle management", features: ["IOC Collection & Normalization", "STIX/TAXII Feed Integration", "IOC Aging & Confidence Scoring", "Multi-SIEM Distribution", "IP/Domain/Hash/URL Enrichment", "Threat Actor Attribution", "IOC Export (CSV, JSON, STIX2)", "Blocklist Generation"], path: "../threat-intelligence/ioc-management/" },
    mitre: { title: "MITRE ATT&CK MAP", type: "TOOL", desc: "Interactive MITRE ATT&CK technique coverage mapping", features: ["14 Tactics Coverage Visualization", "Technique-to-Rule Mapping", "Coverage Gap Analysis", "Heat Map by Detection Confidence", "Enterprise + ICS Frameworks", "Navigator Layer Export", "Detection Priority Scoring", "Quarterly Coverage Trending"], path: "../threat-intelligence/mitre-attack-mapping/" },
    detection: { title: "DETECTION ENGINEERING", type: "BLUE TEAM", desc: "Build, test & maintain high-fidelity detection rules", features: ["Detection-as-Code Pipeline (CI/CD)", "Sigma Rule Development", "Rule Testing & Validation", "Detection Coverage Matrix", "False Positive Reduction", "Data Source Onboarding", "Detection Maturity Model", "Alert Tuning Methodology"], path: "../blue-team-resources/detection-engineering/" },
    triage: { title: "ALERT TRIAGE", type: "BLUE TEAM", desc: "SOC analyst alert triage procedures & workflows", features: ["Triage Decision Trees", "Priority & Severity Matrix", "Enrichment Workflows (IP, Hash, Domain)", "Escalation Criteria & Procedures", "Analyst Runbook Templates", "SLA Management (P1-P4)", "Common False Positive Catalog", "Triage Automation Playbooks"], path: "../blue-team-resources/alert-triage/" },
    runbooks: { title: "SOC RUNBOOKS", type: "BLUE TEAM", desc: "Step-by-step operational procedures for SOC analysts", features: ["L1/L2/L3 Analyst Procedures", "Shift Handoff Templates", "Escalation Workflow Guides", "Tool-Specific Runbooks (SIEM, EDR, SOAR)", "Communication Templates", "Evidence Collection Procedures", "Metrics & KPI Tracking", "Knowledge Transfer Guides"], path: "../blue-team-resources/soc-runbooks/" },
};

function loadPage(pageId) {
    // Route CrowdStrike to full POC module
    if (pageId === 'crowdstrike' && typeof loadCrowdStrikePOC === 'function') {
        loadCrowdStrikePOC();
        return;
    }

    const page = pageData[pageId];
    if (!page) return;

    document.getElementById('dashboard').classList.add('hidden');
    const content = document.getElementById('page-content');
    content.classList.remove('hidden');

    // Close mobile menu if open
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (sidebar) sidebar.classList.remove('sidebar-open');
    if (overlay) overlay.classList.remove('active');

    // Check if rich content exists (from platform-pages.js)
    if (typeof richPageContent !== 'undefined' && richPageContent[pageId]) {
        content.innerHTML = richPageContent[pageId];
        content.scrollTop = 0;
        // Run post-render initializers (e.g., MITRE heatmap)
        if (pageId === 'mitre' && typeof initMitreHeatmap === 'function') {
            initMitreHeatmap();
        }
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        event?.target?.classList?.add('active');
        return;
    }

    const typeColors = {
        'SIEM': '#06b6d4', 'EDR': '#a855f7', 'XDR': '#ef4444',
        'SOAR': '#eab308', 'TOOL': '#3b82f6', 'BLUE TEAM': '#22c55e',
        'SIEM/XDR': '#06b6d4', 'SIEM/UEBA': '#06b6d4'
    };
    const typeColor = typeColors[page.type] || 'var(--accent)';

    const featuresHtml = page.features.map((f, i) =>
        `<div class="page-feature-item" style="animation-delay:${i*50}ms">
            <span class="page-feature-icon" style="color:${typeColor}">▸</span>
            <span class="page-feature-text">${f}</span>
        </div>`
    ).join('');

    content.innerHTML = `
        <div class="page-detail">
            <div class="page-detail-header" style="border-left:3px solid ${typeColor}">
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;flex-wrap:wrap">
                    <h1 style="margin:0;border:none;padding:0">${page.title}</h1>
                    <span class="card-tag" style="position:static;background:${typeColor};color:#000">${page.type}</span>
                </div>
                <p style="color:var(--text-secondary);font-size:13px;margin:0">${page.desc}</p>
            </div>

            <div class="section-title" style="margin-top:24px">⟦ CAPABILITIES & CONTENT (${page.features.length}) ⟧</div>
            <div class="page-feature-grid">${featuresHtml}</div>

            <div class="section-title" style="margin-top:24px">⟦ FILE LOCATION ⟧</div>
            <pre style="margin-bottom:0"><code>${page.path}</code></pre>

            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:24px;padding-bottom:16px">
                <button class="btn-hack" onclick="goHome()">◂ BACK TO DASHBOARD</button>
                <button class="btn-hack" onclick="loadPage('${pageId}')">↻ REFRESH</button>
                ${typeof renderKnowledgeBase === 'function' ? '<button class="btn-hack" onclick="renderKnowledgeBase()" style="border-color:var(--accent)">⚛ KNOWLEDGE BASE</button>' : ''}
            </div>
        </div>
    `;

    content.scrollTop = 0;
    // Update active nav
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    event?.target?.classList?.add('active');
}

function goHome() {
    document.getElementById('dashboard').classList.remove('hidden');
    document.getElementById('page-content').classList.add('hidden');
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (sidebar) sidebar.classList.remove('sidebar-open');
    if (overlay) overlay.classList.remove('active');
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
  crowdstrike   - Open CrowdStrike Falcon POC Module
  kb            - SOC Knowledge Base (kb search, kb list, kb show)
  mitre         - Show MITRE ATT&CK coverage
  fetch         - Run threat intel fetcher
  status        - System status
  clear         - Clear terminal
  whoami        - Who are you?
  matrix        - Toggle matrix rain
  open [page]   - Open any platform page (e.g. open splunk)</span>`;
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
            output = `<span class="output">EDR Platforms (use 'open [id]' to view):
  crowdstrike  - CrowdStrike Falcon [POC MODULE]
  mde          - Microsoft Defender for Endpoint
  sentinelone  - SentinelOne
  carbonblack  - Carbon Black</span>`;
            break;
        case 'xdr':
            output = `<span class="output">XDR Platforms (use 'open [id]' to view):
  cortex       - Palo Alto Cortex XDR
  m365         - Microsoft 365 Defender
  visionone    - Trend Micro Vision One</span>`;
            break;
        case 'soar':
            output = `<span class="output">SOAR Platforms (use 'open [id]' to view):
  splunksoar   - Splunk SOAR (Phantom)
  sentinelsoar - Microsoft Sentinel SOAR
  xsoar        - Palo Alto XSOAR
  qradarsoar   - QRadar SOAR (Resilient)
  shuffle      - Shuffle (Open Source)
  thehive      - TheHive + Cortex
  fortisoar    - FortiSOAR</span>`;
            break;
        case 'tools':
            output = `<span class="output">Tools & Resources:
  fetcher      - Threat Intel Auto-Fetcher (Python)
  rulegen      - SIEM Rule Generator
  ioc          - IOC Management
  mitre        - MITRE ATT&CK Navigator
  detection    - Detection Engineering Guide
  ir           - Incident Response Playbooks
  hunting      - Threat Hunting Playbooks
  triage       - Alert Triage Framework
  runbooks     - SOC Runbooks</span>`;
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
        case 'crowdstrike':
        case 'cs':
        case 'falcon':
            if (typeof loadCrowdStrikePOC === 'function') {
                loadCrowdStrikePOC();
                output = '<span class="output">[+] CrowdStrike Falcon POC Module loaded. Check main content area.</span>';
            } else {
                output = '<span class="error">CrowdStrike POC module not loaded.</span>';
            }
            break;
        case 'open':
            if (parts[1] && pageData[parts[1]]) {
                loadPage(parts[1]);
                output = `<span class="output">[+] Opened ${pageData[parts[1]].title}. Check main content area.</span>`;
            } else if (parts[1]) {
                output = `<span class="error">Unknown page: ${escapeHtml(parts[1])}. Type 'platforms' to see available pages.</span>`;
            } else {
                output = '<span class="error">Usage: open [page-id]. Type "platforms" to see available page IDs.</span>';
            }
            break;
        case 'kb':
            if (typeof handleKBTerminalCommand === 'function') {
                output = handleKBTerminalCommand(parts.slice(1));
            } else {
                output = '<span class="error">Knowledge Base module not loaded.</span>';
            }
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
const escapeHTML = escapeHtml;

// ── Live Feed ──
const feedMessages = [
    {
        sev: 'critical', msg: 'abuse.ch: New Emotet C2 IP detected - 185.xxx.xxx.xxx',
        detail: {
            source: 'abuse.ch FeodoTracker',
            description: 'A new Emotet command-and-control server has been identified at IP 185.234.72.19. This IP is actively distributing Emotet loader payloads via HTTPS on port 443. The server was first observed 2 hours ago and has already been linked to 47 unique beacon check-ins from compromised endpoints worldwide.',
            mitre: ['T1071.001 — Web Protocols', 'T1059.001 — PowerShell', 'T1547.001 — Registry Run Keys'],
            iocs: ['185.234.72.19:443', 'emotet_e5_loader.dll (SHA256: a1b2c3...d4e5f6)', 'hxxps://185.234.72.19/wp-content/update.php'],
            actions: ['Block IP on perimeter firewall', 'Hunt for beacon traffic in SIEM', 'Scan endpoints for loader DLL']
        }
    },
    {
        sev: 'high', msg: 'URLhaus: 15 new malicious URLs added to blocklist',
        detail: {
            source: 'abuse.ch URLhaus',
            description: '15 new malicious URLs have been submitted and verified in the last hour. The URLs are primarily distributing IcedID banking trojan via fake invoice lures. Delivery method is ZIP archives containing ISO files with embedded LNK shortcuts that trigger PowerShell download cradles.',
            mitre: ['T1566.001 — Spearphishing Attachment', 'T1204.002 — Malicious File', 'T1059.001 — PowerShell'],
            iocs: ['hxxps://invoice-doc[.]net/dl/inv_2024.zip', 'hxxps://secure-update[.]top/payload.iso', '15 URLs across 8 domains'],
            actions: ['Update URL blocklist on proxy', 'Alert SOC for phishing triage', 'Check email gateway for matching lures']
        }
    },
    {
        sev: 'medium', msg: 'MITRE ATT&CK: Technique T1059.001 updated with new procedures',
        detail: {
            source: 'MITRE ATT&CK v15',
            description: 'The PowerShell execution technique (T1059.001) has been updated with 4 new procedure examples observed in recent campaigns by FIN7 and Lazarus Group. New sub-techniques include obfuscated Invoke-Expression patterns and AMSI bypass chains. Detection coverage should be reviewed.',
            mitre: ['T1059.001 — PowerShell', 'T1027 — Obfuscated Files', 'T1562.001 — Disable or Modify Tools'],
            iocs: ['N/A — Technique update, no direct IOCs'],
            actions: ['Review PowerShell detection rules', 'Update AMSI bypass signatures', 'Validate logging coverage for ScriptBlock']
        }
    },
    {
        sev: 'high', msg: 'ThreatFox: AsyncRAT IOC cluster identified - 12 indicators',
        detail: {
            source: 'abuse.ch ThreatFox',
            description: 'A new AsyncRAT campaign cluster has been identified with 12 indicators including 4 C2 IPs, 3 domains, and 5 file hashes. The campaign uses Discord CDN for initial payload delivery and DuckDNS dynamic DNS for C2 resolution. Primary targets appear to be SMB organizations in LATAM.',
            mitre: ['T1219 — Remote Access Software', 'T1071.001 — Web Protocols', 'T1568.002 — Domain Generation Algorithms'],
            iocs: ['194.59.31.87:6606', 'asyncupdate.duckdns[.]org', 'cdn.discordapp[.]com/attachments/.../stub.exe', '5 SHA256 hashes'],
            actions: ['Block DuckDNS at DNS resolver', 'Hunt for AsyncRAT mutexes', 'Check Discord CDN traffic in proxy logs']
        }
    },
    {
        sev: 'critical', msg: 'CISA KEV: New actively exploited vulnerability added',
        detail: {
            source: 'CISA Known Exploited Vulnerabilities',
            description: 'CVE-2024-21887 (Ivanti Connect Secure command injection, CVSS 9.1) has been added to the KEV catalog. Active exploitation confirmed by multiple threat actors including UNC5221. Chained with CVE-2023-46805 for unauthenticated RCE. Federal agencies must patch by 2024-02-02.',
            mitre: ['T1190 — Exploit Public-Facing Application', 'T1059 — Command and Scripting Interpreter'],
            iocs: ['CVE-2024-21887', 'CVE-2023-46805', 'Web shells: GLASSTOKEN, BUSHWALK'],
            actions: ['Patch Ivanti Connect Secure immediately', 'Run Ivanti integrity checker', 'Hunt for web shell indicators on VPN appliances']
        }
    },
    {
        sev: 'low', msg: 'NVD: 47 new CVEs published in last 24 hours',
        detail: {
            source: 'NIST National Vulnerability Database',
            description: '47 new CVEs published in the last 24 hours. Breakdown: 3 Critical (CVSS 9.0+), 11 High (7.0-8.9), 18 Medium (4.0-6.9), 15 Low (<4.0). Notable entries include a critical RCE in Apache Struts and a high-severity auth bypass in Fortinet FortiOS.',
            mitre: ['T1190 — Exploit Public-Facing Application'],
            iocs: ['CVE-2024-XXXXX (Apache Struts RCE)', 'CVE-2024-XXXXX (FortiOS auth bypass)'],
            actions: ['Prioritize critical CVEs for patching', 'Cross-reference with asset inventory', 'Update vulnerability scanner signatures']
        }
    },
    {
        sev: 'high', msg: 'MalwareBazaar: LockBit 3.0 sample submitted - SHA256 tracked',
        detail: {
            source: 'abuse.ch MalwareBazaar',
            description: 'A new LockBit 3.0 ransomware sample has been submitted and confirmed. The sample uses a unique packer not previously seen in LockBit campaigns. Analysis shows it targets both Windows and VMware ESXi environments. The binary performs anti-VM checks and disables Windows Defender before encryption.',
            mitre: ['T1486 — Data Encrypted for Impact', 'T1490 — Inhibit System Recovery', 'T1562.001 — Disable or Modify Tools'],
            iocs: ['SHA256: 7f3e8c...a9b2d1 (LockBit 3.0)', 'Mutex: Global\\{8761ABBD-7F85-42EE-B272}', 'Ransom note: !!!-Restore-My-Files-!!!.txt'],
            actions: ['Update EDR signatures', 'Block hash at email gateway', 'Validate backup integrity and isolation']
        }
    },
    {
        sev: 'medium', msg: 'Emerging Threats: 23 new Suricata rules published',
        detail: {
            source: 'Proofpoint Emerging Threats',
            description: '23 new Suricata IDS/IPS rules released covering: 8 rules for Cobalt Strike Malleable C2 profiles, 6 rules for SocGholish fake browser update chains, 5 rules for DNS-over-HTTPS abuse, and 4 rules for credential harvesting kits. SID range: 2048901-2048923.',
            mitre: ['T1071.001 — Web Protocols', 'T1189 — Drive-by Compromise', 'T1572 — Protocol Tunneling'],
            iocs: ['SID 2048901-2048923', 'Cobalt Strike Malleable C2 JA3 hashes', 'SocGholish staging domains'],
            actions: ['Deploy rules to Suricata/Snort sensors', 'Test in IDS mode before IPS enforcement', 'Validate no false positives on staging']
        }
    },
    {
        sev: 'critical', msg: 'FeodoTracker: Qakbot resurgence - 8 new C2 servers',
        detail: {
            source: 'abuse.ch FeodoTracker',
            description: 'Qakbot (QBot) has resurfaced after the August 2023 takedown. 8 new C2 servers identified in the last 6 hours across hosting providers in Russia and Moldova. The new variant uses updated encryption and a modified communication protocol. Initial access via phishing emails with PDF attachments containing embedded URLs.',
            mitre: ['T1566.001 — Spearphishing Attachment', 'T1071.001 — Web Protocols', 'T1055 — Process Injection'],
            iocs: ['194.135.33.41:443', '91.215.85.17:2222', '45.63.99.180:443', '5 additional C2 IPs'],
            actions: ['Block C2 IPs at firewall', 'Hunt for Qakbot registry persistence', 'Alert email security team for PDF lure detection']
        }
    },
    {
        sev: 'high', msg: 'AlienVault OTX: APT29 pulse updated with new indicators',
        detail: {
            source: 'AlienVault Open Threat Exchange',
            description: 'The APT29 (Cozy Bear / Midnight Blizzard) OTX pulse has been updated with 34 new indicators from their latest campaign targeting diplomatic entities. New TTPs include HTML smuggling for initial access and abuse of Microsoft Graph API for C2 communication. Attribution confidence: HIGH.',
            mitre: ['T1027.006 — HTML Smuggling', 'T1102.002 — Bidirectional Communication', 'T1078 — Valid Accounts'],
            iocs: ['34 new indicators (IPs, domains, hashes)', 'Graph API C2 endpoints', 'HTML smuggling dropper hashes'],
            actions: ['Ingest IOCs into TIP', 'Hunt for Graph API anomalies', 'Review diplomatic sector exposure']
        }
    },
    {
        sev: 'medium', msg: 'Detection rule updated: Kerberoasting via RC4 TGS',
        detail: {
            source: 'Internal Detection Engineering',
            description: 'Updated detection rule for Kerberoasting attacks requesting RC4-encrypted TGS tickets (encryption type 0x17). The rule now includes exception handling for legacy service accounts and reduces false positives by correlating with abnormal requesting account patterns. Covers tools: Rubeus, Impacket GetUserSPNs, PowerView.',
            mitre: ['T1558.003 — Kerberoasting', 'T1078.002 — Domain Accounts'],
            iocs: ['Event ID 4769 with 0x17 encryption', 'Rubeus.exe hash signatures', 'Impacket GetUserSPNs artifacts'],
            actions: ['Deploy updated rule to SIEM', 'Validate exception list for legacy SPNs', 'Run detection test with Atomic Red Team']
        }
    },
    {
        sev: 'low', msg: 'Wazuh: 3 new decoders added for FortiGate logs',
        detail: {
            source: 'Wazuh Community',
            description: '3 new Wazuh decoders added for FortiGate NGFW logs: (1) SSL-VPN authentication events including MFA status, (2) IPS signature matches with full context fields, (3) Web filter category blocks with URL and user identity. Decoders normalize fields to Wazuh schema for consistent alerting.',
            mitre: ['T1133 — External Remote Services', 'T1190 — Exploit Public-Facing Application'],
            iocs: ['N/A — Log parsing enhancement'],
            actions: ['Deploy decoders to Wazuh manager', 'Test with sample FortiGate logs', 'Create corresponding alert rules']
        }
    },
    {
        sev: 'high', msg: 'Sentinel: New fusion detection for multi-stage attack',
        detail: {
            source: 'Microsoft Sentinel',
            description: 'New Fusion detection rule correlates: initial access via compromised OAuth app → mailbox rule creation for email forwarding → suspicious Azure AD sign-in from anonymizing service → SharePoint mass file download. This multi-stage detection identifies sophisticated BEC and data exfiltration campaigns with high fidelity.',
            mitre: ['T1550.001 — Application Access Token', 'T1114.003 — Email Forwarding Rule', 'T1530 — Data from Cloud Storage'],
            iocs: ['Fusion incident correlation ID patterns', 'OAuth app client IDs under investigation'],
            actions: ['Enable Fusion rule in Sentinel', 'Review OAuth app consent policies', 'Audit email forwarding rules org-wide']
        }
    },
    {
        sev: 'critical', msg: 'Splunk ES: Risk score threshold exceeded for DC01',
        detail: {
            source: 'Splunk Enterprise Security',
            description: 'Domain controller DC01 risk score exceeded threshold (current: 847, threshold: 500). Contributing factors: 12 failed admin logons in 10 min, NTDS.dit access attempt via Volume Shadow Copy, suspicious scheduled task creation pointing to external IP, and LSASS memory dump detected by Sysmon.',
            mitre: ['T1003.001 — LSASS Memory', 'T1003.003 — NTDS', 'T1053.005 — Scheduled Task', 'T1110.001 — Password Guessing'],
            iocs: ['DC01 (10.0.1.5)', 'External callback: 203.0.113.42:8443', 'Scheduled task: \\Microsoft\\Windows\\SvcUpdate'],
            actions: ['Isolate DC01 from network immediately', 'Initiate IR playbook for DC compromise', 'Reset krbtgt password twice', 'Forensic image of DC01']
        }
    },
    {
        sev: 'medium', msg: 'Chronicle: YARA-L rule matched DNS tunneling pattern',
        detail: {
            source: 'Google Chronicle SIEM',
            description: 'YARA-L detection rule identified DNS tunneling activity from endpoint WS-PC089 (10.0.5.89). The host is making high-frequency DNS TXT queries to a suspicious domain (xf7k2.datacache[.]cloud) with base64-encoded subdomains. Pattern matches known iodine/dnscat2 tunneling signatures. Data exfiltration estimated at ~2.4 MB over 45 minutes.',
            mitre: ['T1572 — Protocol Tunneling', 'T1048.001 — Exfiltration Over Alternative Protocol', 'T1071.004 — DNS'],
            iocs: ['xf7k2.datacache[.]cloud', 'WS-PC089 (10.0.5.89)', 'High-frequency DNS TXT queries (>500/hr)'],
            actions: ['Block domain at DNS resolver', 'Isolate WS-PC089 for investigation', 'Check for dnscat2/iodine artifacts on host']
        }
    },
];

// ── Feed Detail Modal ──
function createFeedDetailModal() {
    if (document.getElementById('feed-detail-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'feed-detail-overlay';
    overlay.className = 'feed-detail-overlay';
    overlay.addEventListener('click', closeFeedDetail);

    const modal = document.createElement('div');
    modal.id = 'feed-detail-modal';
    modal.className = 'feed-detail-modal';

    document.body.appendChild(overlay);
    document.body.appendChild(modal);
}

function showFeedDetail(item, timestamp) {
    createFeedDetailModal();
    const modal = document.getElementById('feed-detail-modal');
    const overlay = document.getElementById('feed-detail-overlay');
    const d = item.detail;
    const sevLabel = item.sev.toUpperCase();

    modal.innerHTML = `
        <div class="feed-detail-header">
            <div>
                <div style="margin-bottom:8px">
                    <span class="feed-severity ${item.sev}" style="font-size:11px">${sevLabel}</span>
                    <span style="color:var(--text-muted);font-size:11px;margin-left:8px">${timestamp}</span>
                </div>
                <h3>${escapeHTML(item.msg)}</h3>
            </div>
            <button class="feed-detail-close" onclick="closeFeedDetail()" title="Close">&times;</button>
        </div>
        <div class="feed-detail-body">
            <div class="feed-detail-row">
                <span class="feed-detail-label">Source</span>
                <span class="feed-detail-value"><span class="feed-detail-tag source">${escapeHTML(d.source)}</span></span>
            </div>
            <div class="feed-detail-row">
                <span class="feed-detail-label">Description</span>
                <span class="feed-detail-value">${escapeHTML(d.description)}</span>
            </div>
            <div class="feed-detail-row">
                <span class="feed-detail-label">MITRE ATT&CK</span>
                <span class="feed-detail-value">
                    <div class="feed-detail-tags">${d.mitre.map(t => `<span class="feed-detail-tag mitre">${escapeHTML(t)}</span>`).join('')}</div>
                </span>
            </div>
            <div class="feed-detail-row">
                <span class="feed-detail-label">IOCs</span>
                <span class="feed-detail-value">${d.iocs.map(i => `<code>${escapeHTML(i)}</code>`).join('<br>')}</span>
            </div>
            <div class="feed-detail-row">
                <span class="feed-detail-label">Actions</span>
                <span class="feed-detail-value">
                    ${d.actions.map((a, i) => `<div style="margin-bottom:4px;color:var(--text-secondary)"><span style="color:var(--cyan);font-weight:700;margin-right:6px">${i + 1}.</span>${escapeHTML(a)}</div>`).join('')}
                </span>
            </div>
        </div>
        <div class="feed-detail-actions">
            <button class="primary" onclick="closeFeedDetail()">Acknowledge</button>
            <button onclick="navigator.clipboard.writeText(JSON.stringify(${escapeHTML(JSON.stringify(d))}, null, 2)); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy IOCs',1500)">Copy IOCs</button>
            <button onclick="closeFeedDetail()">Dismiss</button>
        </div>
    `;

    requestAnimationFrame(() => {
        overlay.classList.add('active');
        modal.classList.add('active');
    });
}

function closeFeedDetail() {
    const modal = document.getElementById('feed-detail-modal');
    const overlay = document.getElementById('feed-detail-overlay');
    if (modal) modal.classList.remove('active');
    if (overlay) overlay.classList.remove('active');
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeFeedDetail();
});

function startLiveFeed() {
    const feed = document.getElementById('live-feed');
    let idx = 0;

    // Make existing static feed items clickable with sample details
    feed.querySelectorAll('.feed-item').forEach(el => {
        el.addEventListener('click', () => {
            const msgEl = el.querySelector('.feed-msg');
            const sevEl = el.querySelector('.feed-severity');
            const timeEl = el.querySelector('.feed-time');
            const msg = msgEl ? msgEl.textContent : '';
            const sevText = sevEl ? sevEl.textContent.trim().toLowerCase() : 'medium';
            const sevMap = { 'crit': 'critical', 'high': 'high', 'med': 'medium', 'low': 'low', 'info': 'low' };
            const sev = sevMap[sevText] || 'medium';
            showFeedDetail({
                sev: sev,
                msg: msg,
                detail: {
                    source: 'SOC Live Monitoring',
                    description: msg + ' — This event was detected by the SOC monitoring pipeline and correlated across multiple data sources. Immediate triage recommended based on severity classification.',
                    mitre: ['See event details for mapped techniques'],
                    iocs: ['See SIEM for full IOC extraction'],
                    actions: ['Triage in SIEM console', 'Correlate with related alerts', 'Escalate if confirmed true positive']
                }
            }, timeEl ? timeEl.textContent : '');
        });
    });

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
        el.addEventListener('click', () => showFeedDetail(item, time));
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

// ═══════════════════════════════════════════════════════
// RULE BUILDER - Drag & Drop Visual Detection Rule Builder
// ═══════════════════════════════════════════════════════

const rbComponents = {
    datasource: {
        label: 'Data Sources',
        items: ['Windows Event Log', 'Syslog', 'Firewall', 'DNS', 'Proxy', 'Cloud Trail', 'EDR Telemetry', 'Network Flow']
    },
    tactic: {
        label: 'MITRE Tactics',
        items: ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'C2', 'Impact']
    },
    condition: {
        label: 'Conditions / Logic',
        items: ['AND', 'OR', 'NOT', 'COUNT >', 'THRESHOLD', 'TIME WINDOW', 'SEQUENCE', 'AGGREGATION']
    },
    field: {
        label: 'Fields',
        items: ['Source IP', 'Dest IP', 'Username', 'Process Name', 'Command Line', 'File Hash', 'URL', 'Domain', 'Port', 'Registry Key', 'Parent Process', 'Service Name']
    },
    action: {
        label: 'Actions',
        items: ['Alert', 'Block', 'Quarantine', 'Isolate Host', 'Disable Account', 'Email Notify', 'Ticket Create', 'Enrich IOC']
    },
    severity: {
        label: 'Severity',
        items: ['Critical', 'High', 'Medium', 'Low', 'Informational']
    }
};

const rbLanes = [
    { id: 'datasource', label: 'Data Sources', accepts: ['datasource'] },
    { id: 'tactic', label: 'MITRE Tactics', accepts: ['tactic'] },
    { id: 'condition', label: 'Conditions & Fields', accepts: ['condition', 'field'] },
    { id: 'action', label: 'Actions & Severity', accepts: ['action', 'severity'] }
];

// MITRE tactic to ID mapping
const mitreTacticMap = {
    'Initial Access': 'TA0001', 'Execution': 'TA0002', 'Persistence': 'TA0003',
    'Privilege Escalation': 'TA0004', 'Defense Evasion': 'TA0005', 'Credential Access': 'TA0006',
    'Discovery': 'TA0007', 'Lateral Movement': 'TA0008', 'Collection': 'TA0009',
    'Exfiltration': 'TA0010', 'C2': 'TA0011', 'Impact': 'TA0040'
};

// Field name mapping for queries
const fieldMap = {
    'Source IP': { splunk: 'src_ip', kql: 'SourceIP', aql: 'sourceip', eql: 'source.ip', wazuh: 'srcip', yaral: 'principal.ip', sigma: 'src_ip' },
    'Dest IP': { splunk: 'dest_ip', kql: 'DestinationIP', aql: 'destinationip', eql: 'destination.ip', wazuh: 'dstip', yaral: 'target.ip', sigma: 'dst_ip' },
    'Username': { splunk: 'user', kql: 'AccountName', aql: 'username', eql: 'user.name', wazuh: 'dstuser', yaral: 'principal.user.userid', sigma: 'User' },
    'Process Name': { splunk: 'process_name', kql: 'ProcessName', aql: '"Process Name"', eql: 'process.name', wazuh: 'data.win.eventdata.image', yaral: 'principal.process.file.full_path', sigma: 'Image' },
    'Command Line': { splunk: 'process', kql: 'CommandLine', aql: '"Command Line"', eql: 'process.command_line', wazuh: 'data.win.eventdata.commandLine', yaral: 'principal.process.command_line', sigma: 'CommandLine' },
    'File Hash': { splunk: 'file_hash', kql: 'FileHash', aql: '"File Hash"', eql: 'file.hash.sha256', wazuh: 'syscheck.sha256_after', yaral: 'target.file.sha256', sigma: 'Hashes' },
    'URL': { splunk: 'url', kql: 'Url', aql: 'url', eql: 'url.original', wazuh: 'data.url', yaral: 'target.url', sigma: 'TargetUrl' },
    'Domain': { splunk: 'query', kql: 'DomainName', aql: '"DNS Domain"', eql: 'dns.question.name', wazuh: 'data.win.eventdata.queryName', yaral: 'network.dns.questions.name', sigma: 'QueryName' },
    'Port': { splunk: 'dest_port', kql: 'DestinationPort', aql: 'destinationport', eql: 'destination.port', wazuh: 'dstport', yaral: 'target.port', sigma: 'DestinationPort' },
    'Registry Key': { splunk: 'registry_path', kql: 'RegistryKey', aql: '"Registry Key"', eql: 'registry.path', wazuh: 'data.win.eventdata.targetObject', yaral: 'target.registry.registry_key', sigma: 'TargetObject' },
    'Parent Process': { splunk: 'parent_process_name', kql: 'ParentProcessName', aql: '"Parent Process"', eql: 'process.parent.name', wazuh: 'data.win.eventdata.parentImage', yaral: 'principal.process.parent_process.file.full_path', sigma: 'ParentImage' },
    'Service Name': { splunk: 'service_name', kql: 'ServiceName', aql: '"Service Name"', eql: 'service.name', wazuh: 'data.win.eventdata.serviceName', yaral: 'target.resource.name', sigma: 'ServiceName' }
};

// Data source index mapping
const dsMap = {
    'Windows Event Log': { splunk: 'index=wineventlog', kql: 'SecurityEvent', aql: "SELECT * FROM events WHERE devicetype = 12", eql: 'any where true', wazuh: '<if_group>windows</if_group>', yaral: 'events', sigma: 'windows' },
    'Syslog': { splunk: 'index=syslog', kql: 'Syslog', aql: "SELECT * FROM events WHERE devicetype = 11", eql: 'any where event.module == "system"', wazuh: '<if_group>syslog</if_group>', yaral: 'events', sigma: 'linux' },
    'Firewall': { splunk: 'index=firewall', kql: 'CommonSecurityLog', aql: "SELECT * FROM events WHERE category = 'Firewall'", eql: 'any where event.category == "network"', wazuh: '<if_group>firewall</if_group>', yaral: 'events', sigma: 'firewall' },
    'DNS': { splunk: 'index=dns', kql: 'DnsEvents', aql: "SELECT * FROM events WHERE category = 'DNS'", eql: 'dns where true', wazuh: '<if_group>ossec-dns</if_group>', yaral: 'events', sigma: 'dns_query' },
    'Proxy': { splunk: 'index=proxy', kql: 'WebProxy', aql: "SELECT * FROM events WHERE category = 'Web'", eql: 'any where event.category == "web"', wazuh: '<if_group>web-log</if_group>', yaral: 'events', sigma: 'proxy' },
    'Cloud Trail': { splunk: 'index=aws sourcetype=aws:cloudtrail', kql: 'AWSCloudTrail', aql: "SELECT * FROM events WHERE devicetype = 347", eql: 'any where event.provider == "cloudtrail"', wazuh: '<if_group>amazon</if_group>', yaral: 'events', sigma: 'aws' },
    'EDR Telemetry': { splunk: 'index=edr', kql: 'DeviceEvents', aql: "SELECT * FROM events WHERE category = 'Endpoint'", eql: 'process where true', wazuh: '<if_group>sysmon</if_group>', yaral: 'events', sigma: 'process_creation' },
    'Network Flow': { splunk: 'index=netflow', kql: 'AzureNetworkAnalytics_CL', aql: "SELECT * FROM flows", eql: 'network where true', wazuh: '<if_group>netflow</if_group>', yaral: 'events', sigma: 'network_connection' }
};

let rbCanvasState = {
    datasource: [],
    tactic: [],
    condition: [],
    action: []
};

function loadRuleBuilder() {
    document.getElementById('dashboard').classList.add('hidden');
    const content = document.getElementById('page-content');
    content.classList.remove('hidden');

    // Reset canvas state
    rbCanvasState = { datasource: [], tactic: [], condition: [], action: [] };

    // Build palette HTML
    let paletteHtml = '';
    for (const [cat, data] of Object.entries(rbComponents)) {
        const itemsHtml = data.items.map(item =>
            `<span class="rb-component" draggable="true" data-category="${cat}" data-value="${item}" ontouchstart="rbTouchAdd(this)">${item}</span>`
        ).join('');
        paletteHtml += `
            <div class="rb-cat-header" onclick="rbToggleCat(this)">
                ${data.label}
                <span class="rb-cat-arrow open">&#9654;</span>
            </div>
            <div class="rb-cat-items open">${itemsHtml}</div>
        `;
    }

    // Build lanes HTML
    let lanesHtml = '';
    rbLanes.forEach((lane, i) => {
        lanesHtml += `
            <div class="rb-lane" id="rb-lane-${lane.id}" data-lane="${lane.id}" data-accepts="${lane.accepts.join(',')}">
                <div class="rb-lane-label">${lane.label}</div>
                <div class="rb-lane-items" id="rb-lane-items-${lane.id}"></div>
            </div>
        `;
        if (i < rbLanes.length - 1) {
            lanesHtml += '<div class="rb-connector">&#9661;</div>';
        }
    });

    content.innerHTML = `
        <div class="rb-container">
            <div class="rb-header">
                <h1>&#x29C9; RULE &amp; USE CASE BUILDER</h1>
                <button class="rb-back-btn" onclick="goHome()">&#9666; DASHBOARD</button>
            </div>

            <div class="rb-palette">
                ${paletteHtml}
            </div>

            <div class="rb-canvas-wrapper">
                <div class="rb-canvas-toolbar">
                    <span class="rb-toolbar-label">CANVAS:</span>
                    <button onclick="rbClearCanvas()">CLEAR ALL</button>
                    <button onclick="rbAutoPopulate()">DEMO RULE</button>
                </div>
                <div class="rb-canvas" id="rb-canvas">
                    <div class="rb-flow" id="rb-flow">
                        ${lanesHtml}
                    </div>
                </div>
            </div>

            <div class="rb-output">
                <div class="rb-output-section">
                    <label>Platform Output</label>
                    <select id="rb-platform" onchange="rbGenerateRule()">
                        <option value="splunk">Splunk SPL</option>
                        <option value="kql">Sentinel KQL</option>
                        <option value="aql">QRadar AQL</option>
                        <option value="eql">Elastic EQL</option>
                        <option value="wazuh">Wazuh XML</option>
                        <option value="yaral">Chronicle YARA-L</option>
                        <option value="sigma">Sigma (Generic)</option>
                    </select>
                </div>

                <div class="rb-output-section">
                    <div class="rb-meta-grid">
                        <div class="rb-meta-field">
                            <label>Rule Name</label>
                            <input type="text" id="rb-rule-name" placeholder="e.g. Suspicious Process Execution" oninput="rbGenerateRule()">
                        </div>
                        <div class="rb-meta-field">
                            <label>Description</label>
                            <textarea id="rb-rule-desc" rows="2" placeholder="Detection use case description..." oninput="rbGenerateRule()"></textarea>
                        </div>
                        <div class="rb-meta-field">
                            <label>MITRE ATT&CK ID</label>
                            <input type="text" id="rb-mitre-id" placeholder="Auto-populated from tactics" readonly>
                        </div>
                        <div class="rb-meta-field">
                            <label>False Positive Guidance</label>
                            <input type="text" id="rb-fp-guidance" placeholder="e.g. Admin scripts may trigger this" oninput="rbGenerateRule()">
                        </div>
                    </div>
                </div>

                <!-- Multi-Card Output: SIEM / EDR / XDR / SOAR -->
                <div class="rb-cards-tabs" style="display:flex;gap:2px;margin-bottom:0">
                    <button class="rb-card-tab rb-card-tab-active" data-card="siem" onclick="rbSwitchCard('siem')" style="flex:1;padding:8px 0;font-size:11px;font-weight:700;font-family:var(--font-sans);background:var(--bg-card);color:var(--accent);border:1px solid var(--accent);border-bottom:2px solid var(--accent);border-radius:var(--radius) var(--radius) 0 0;cursor:pointer;letter-spacing:0.5px">&#128202; SIEM</button>
                    <button class="rb-card-tab" data-card="edr" onclick="rbSwitchCard('edr')" style="flex:1;padding:8px 0;font-size:11px;font-weight:700;font-family:var(--font-sans);background:var(--bg-tertiary);color:var(--text-dim);border:1px solid var(--border);border-bottom:1px solid var(--border);border-radius:var(--radius) var(--radius) 0 0;cursor:pointer;letter-spacing:0.5px">&#128187; EDR</button>
                    <button class="rb-card-tab" data-card="xdr" onclick="rbSwitchCard('xdr')" style="flex:1;padding:8px 0;font-size:11px;font-weight:700;font-family:var(--font-sans);background:var(--bg-tertiary);color:var(--text-dim);border:1px solid var(--border);border-bottom:1px solid var(--border);border-radius:var(--radius) var(--radius) 0 0;cursor:pointer;letter-spacing:0.5px">&#128279; XDR</button>
                    <button class="rb-card-tab" data-card="soar" onclick="rbSwitchCard('soar')" style="flex:1;padding:8px 0;font-size:11px;font-weight:700;font-family:var(--font-sans);background:var(--bg-tertiary);color:var(--text-dim);border:1px solid var(--border);border-bottom:1px solid var(--border);border-radius:var(--radius) var(--radius) 0 0;cursor:pointer;letter-spacing:0.5px">&#128680; SOAR</button>
                </div>

                <!-- SIEM Card -->
                <div class="rb-card-panel" id="rb-card-siem" style="background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius) var(--radius);padding:12px;margin-bottom:8px">
                    <div class="rb-code-header">
                        <span>SIEM Detection Query</span>
                        <div class="rb-code-actions"><button onclick="rbCopyRule()">COPY</button></div>
                    </div>
                    <div class="rb-code-output" id="rb-code-output">// Drop components to generate a detection rule...</div>
                </div>

                <!-- EDR Card -->
                <div class="rb-card-panel" id="rb-card-edr" style="display:none;background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius) var(--radius);padding:12px;margin-bottom:8px">
                    <div class="rb-code-header">
                        <span>EDR Detection (CrowdStrike / MDE)</span>
                        <div class="rb-code-actions"><button onclick="rbCopyCard('edr')">COPY</button></div>
                    </div>
                    <div class="rb-code-output" id="rb-edr-output">// Build a SIEM rule first, EDR detection will auto-generate...</div>
                </div>

                <!-- XDR Card -->
                <div class="rb-card-panel" id="rb-card-xdr" style="display:none;background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius) var(--radius);padding:12px;margin-bottom:8px">
                    <div class="rb-code-header">
                        <span>XDR Correlation (Cross-Signal)</span>
                        <div class="rb-code-actions"><button onclick="rbCopyCard('xdr')">COPY</button></div>
                    </div>
                    <div class="rb-code-output" id="rb-xdr-output">// Build a SIEM rule first, XDR correlation will auto-generate...</div>
                </div>

                <!-- SOAR Card -->
                <div class="rb-card-panel" id="rb-card-soar" style="display:none;background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius) var(--radius);padding:12px;margin-bottom:8px">
                    <div class="rb-code-header">
                        <span>SOAR Playbook (Response Automation)</span>
                        <div class="rb-code-actions"><button onclick="rbCopyCard('soar')">COPY</button></div>
                    </div>
                    <div class="rb-code-output" id="rb-soar-output">// Build a SIEM rule first, SOAR playbook will auto-generate...</div>
                </div>

                <div class="rb-export-bar">
                    <button onclick="rbCopyRule()">Copy to Clipboard</button>
                    <button onclick="rbExport('yaml')">Export YAML</button>
                    <button onclick="rbExport('json')">Export JSON</button>
                </div>
            </div>
        </div>
    `;

    // Initialize drag-and-drop
    rbInitDragDrop();

    // Update active nav
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
}

function rbToggleCat(el) {
    const items = el.nextElementSibling;
    const arrow = el.querySelector('.rb-cat-arrow');
    items.classList.toggle('open');
    arrow.classList.toggle('open');
}

function rbInitDragDrop() {
    // Make palette components draggable
    document.querySelectorAll('.rb-component').forEach(comp => {
        comp.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', JSON.stringify({
                category: comp.dataset.category,
                value: comp.dataset.value
            }));
            e.dataTransfer.effectAllowed = 'copy';
            comp.style.opacity = '0.5';
        });
        comp.addEventListener('dragend', (e) => {
            comp.style.opacity = '1';
        });
    });

    // Set up drop zones (lanes)
    document.querySelectorAll('.rb-lane').forEach(lane => {
        lane.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
            lane.classList.add('drag-over-lane');
        });
        lane.addEventListener('dragleave', (e) => {
            lane.classList.remove('drag-over-lane');
        });
        lane.addEventListener('drop', (e) => {
            e.preventDefault();
            lane.classList.remove('drag-over-lane');
            try {
                const data = JSON.parse(e.dataTransfer.getData('text/plain'));
                const accepts = lane.dataset.accepts.split(',');
                if (accepts.includes(data.category)) {
                    rbAddToLane(lane.dataset.lane, data.category, data.value);
                }
            } catch (err) {}
        });
    });
}

// Touch fallback: tap to add component to appropriate lane
function rbTouchAdd(el) {
    // Only use this as fallback on touch devices where drag doesn't work well
    if ('ontouchstart' in window) {
        const cat = el.dataset.category;
        const val = el.dataset.value;
        // Find the appropriate lane
        for (const lane of rbLanes) {
            if (lane.accepts.includes(cat)) {
                rbAddToLane(lane.id, cat, val);
                break;
            }
        }
    }
}

function rbAddToLane(laneId, category, value) {
    // Check if already in this lane
    const items = rbCanvasState[laneId] || [];
    if (items.some(i => i.value === value && i.category === category)) return;
    items.push({ category, value });
    rbCanvasState[laneId] = items;
    rbRenderLane(laneId);
    rbUpdateMitreId();
    rbGenerateRule();
}

function rbRemoveFromLane(laneId, index) {
    rbCanvasState[laneId].splice(index, 1);
    rbRenderLane(laneId);
    rbUpdateMitreId();
    rbGenerateRule();
}

function rbRenderLane(laneId) {
    const container = document.getElementById('rb-lane-items-' + laneId);
    if (!container) return;
    const items = rbCanvasState[laneId] || [];
    container.innerHTML = items.map((item, i) =>
        `<span class="rb-dropped rb-component" data-category="${item.category}">${item.value}<span class="rb-remove" onclick="rbRemoveFromLane('${laneId}', ${i})">&#10005;</span></span>`
    ).join('');
}

function rbUpdateMitreId() {
    const tactics = rbCanvasState.tactic || [];
    const ids = tactics.map(t => mitreTacticMap[t.value]).filter(Boolean);
    const mitreInput = document.getElementById('rb-mitre-id');
    if (mitreInput) mitreInput.value = ids.join(', ');
}

function rbClearCanvas() {
    rbCanvasState = { datasource: [], tactic: [], condition: [], action: [] };
    rbLanes.forEach(l => rbRenderLane(l.id));
    rbUpdateMitreId();
    rbGenerateRule();
}

function rbAutoPopulate() {
    rbClearCanvas();
    // Demo: Suspicious PowerShell Execution
    rbCanvasState = {
        datasource: [{ category: 'datasource', value: 'Windows Event Log' }, { category: 'datasource', value: 'EDR Telemetry' }],
        tactic: [{ category: 'tactic', value: 'Execution' }, { category: 'tactic', value: 'Defense Evasion' }],
        condition: [
            { category: 'field', value: 'Process Name' },
            { category: 'field', value: 'Command Line' },
            { category: 'field', value: 'Parent Process' },
            { category: 'condition', value: 'AND' },
            { category: 'condition', value: 'NOT' }
        ],
        action: [
            { category: 'action', value: 'Alert' },
            { category: 'action', value: 'Enrich IOC' },
            { category: 'severity', value: 'High' }
        ]
    };
    rbLanes.forEach(l => rbRenderLane(l.id));
    const nameInput = document.getElementById('rb-rule-name');
    const descInput = document.getElementById('rb-rule-desc');
    const fpInput = document.getElementById('rb-fp-guidance');
    if (nameInput) nameInput.value = 'Suspicious PowerShell Execution';
    if (descInput) descInput.value = 'Detects encoded or obfuscated PowerShell commands commonly used by attackers for initial payload execution and defense evasion.';
    if (fpInput) fpInput.value = 'Legitimate admin scripts using encoded commands, SCCM deployments';
    rbUpdateMitreId();
    rbGenerateRule();
}

// ── Rule Generation Engine ──

// ── Rule Builder Card Switching ────────────────────────────────────────

function rbSwitchCard(cardId) {
    document.querySelectorAll('.rb-card-panel').forEach(p => { p.style.display = 'none'; });
    document.querySelectorAll('.rb-card-tab').forEach(b => {
        const isActive = b.dataset.card === cardId;
        b.style.background = isActive ? 'var(--bg-card)' : 'var(--bg-tertiary)';
        b.style.color = isActive ? 'var(--accent)' : 'var(--text-dim)';
        b.style.borderColor = isActive ? 'var(--accent)' : 'var(--border)';
        b.style.borderBottomColor = isActive ? 'var(--accent)' : 'var(--border)';
        b.style.borderBottomWidth = isActive ? '2px' : '1px';
        b.classList.toggle('rb-card-tab-active', isActive);
    });
    const panel = document.getElementById('rb-card-' + cardId);
    if (panel) panel.style.display = 'block';
}

function rbCopyCard(cardId) {
    const el = document.getElementById('rb-' + cardId + '-output');
    if (el) {
        navigator.clipboard.writeText(el.textContent).then(() => {
            const btns = el.parentElement.querySelectorAll('button');
            const btn = Array.from(btns).find(b => b.textContent === 'COPY');
            if (btn) { btn.textContent = 'COPIED!'; setTimeout(() => { btn.textContent = 'COPY'; }, 1500); }
        });
    }
}

// ── EDR/XDR/SOAR Auto-Generator from Rule Builder State ──────────────

function rbGenEDR(ruleName, severity, ds, fields, actions, mitreId) {
    const dsNames = ds.map(d => d.value).join(', ');
    const fieldNames = fields.map(f => f.value).join(', ');
    const actionNames = actions.map(a => a.value).join(', ');

    return `/* ═══ EDR Detection: ${ruleName} ═══ */
/* Severity: ${severity} | MITRE: ${mitreId} */

/* Process Behavior Indicators */
Monitor: Suspicious process execution matching rule criteria
Data Sources: ${dsNames || 'Endpoint telemetry'}
Fields: ${fieldNames || 'Process name, command-line, parent process'}

/* Parent-Child Process Relationships */
Alert when:
  - Unusual parent spawns child process (e.g. Office → cmd/powershell)
  - Process with suspicious command-line flags (-enc, -nop, -w hidden)
  - Non-standard process accessing sensitive resources (LSASS, SAM)

/* CrowdStrike Falcon IOA */
IOA Name: ${ruleName}
Severity: ${severity}
Action: ${actionNames || 'Detect'}
Behavior: Monitor for ${fieldNames || 'suspicious endpoint activity'}

/* Microsoft Defender for Endpoint */
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any ("${fieldNames || 'suspicious_pattern'}")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName`;
}

function rbGenXDR(ruleName, severity, ds, fields, mitreId) {
    const fieldNames = fields.map(f => f.value).join(', ');

    return `/* ═══ XDR Correlation: ${ruleName} ═══ */
/* Severity: ${severity} | MITRE: ${mitreId} */

/* Multi-Source Correlation Logic */
PHASE 1 - Identity Layer:
  - Authentication events (4624, 4625, 4672)
  - Correlate: user, source IP, logon type

PHASE 2 - Endpoint Layer:
  - Process creation, script execution
  - Correlate: process tree, command-line, ${fieldNames || 'file indicators'}

PHASE 3 - Network Layer:
  - Network connections (SMB 445, RDP 3389, HTTP/S)
  - Correlate: destination, data volume, frequency

/* Correlation Window */
Alert when 2+ phases match within 30 minutes for same user/host

/* Microsoft 365 Defender Advanced Hunting */
let identity = IdentityLogonEvents | where Timestamp > ago(30m);
let endpoint = DeviceProcessEvents | where Timestamp > ago(30m);
let network = DeviceNetworkEvents | where Timestamp > ago(30m);
identity
| join kind=inner endpoint on AccountName
| join kind=leftouter network on DeviceName
| project Timestamp, AccountName, DeviceName, ProcessCommandLine, RemoteIP`;
}

function rbGenSOAR(ruleName, severity, actions, mitreId) {
    const actionNames = actions.map(a => a.value);
    const hasIsolate = actionNames.some(a => /isolat/i.test(a));
    const hasBlock = actionNames.some(a => /block/i.test(a));
    const hasDisable = actionNames.some(a => /disable/i.test(a));
    const hasAlert = actionNames.some(a => /alert/i.test(a));

    return `/* ═══ SOAR Playbook: ${ruleName} ═══ */
/* Severity: ${severity} | MITRE: ${mitreId} */

/* Trigger Condition */
SIEM alert fires for "${ruleName}" with severity >= ${severity}

/* Playbook Steps */
STEP 1: ENRICH (Automatic)
  - Query AD: user group membership, adminCount, lastLogon
  - Query CMDB: asset tier, owner, business criticality
  - Query Threat Intel: source IP reputation, geo lookup
  - Query EDR: running processes, network connections

STEP 2: TRIAGE (Automatic)
  - Calculate confidence score from enrichment
  - IF score >= 8 AND tier0_asset → CRITICAL → Step 3a
  - ELSE → HIGH → Step 3b (analyst approval)

STEP 3a: AUTO-CONTAIN (Critical)
${hasIsolate ? '  - EDR API: Isolate host (POST /devices/actions/contain)' : '  - EDR API: Isolate host if confirmed malicious'}
${hasDisable ? '  - AD API: Disable-ADAccount -Identity $user' : '  - AD API: Disable compromised account'}
${hasBlock ? '  - Firewall: Block source IP at perimeter' : '  - Firewall: Block malicious IPs/domains'}
  - EDR RTR: Kill suspicious processes
  - Force logoff active sessions

STEP 3b: APPROVAL REQUIRED (High)
  - Send approval request to SOC Tier 2
  - Timeout: 15 min → auto-escalate to 3a
  - On approval → execute containment

STEP 4: NOTIFY
  - Create IR ticket (ServiceNow/Jira)
  - Page SOC on-call via PagerDuty
  - Post to #soc-alerts Slack channel
${severity === 'Critical' ? '  - Email CISO + IR Lead' : ''}

STEP 5: COLLECT EVIDENCE
  - Export EDR timeline (T0 ± 2 hours)
  - Export SIEM logs for affected user (24 hours)
  - Snapshot network flow data
  - Store in case folder: IR-$TICKET_ID/`;
}

function rbGenerateRule() {
    const platform = document.getElementById('rb-platform')?.value || 'splunk';
    const ruleName = document.getElementById('rb-rule-name')?.value || 'Untitled Rule';
    const ruleDesc = document.getElementById('rb-rule-desc')?.value || '';
    const mitreId = document.getElementById('rb-mitre-id')?.value || '';
    const fpGuidance = document.getElementById('rb-fp-guidance')?.value || '';

    const ds = rbCanvasState.datasource || [];
    const tactics = rbCanvasState.tactic || [];
    const condFields = rbCanvasState.condition || [];
    const actSev = rbCanvasState.action || [];

    const fields = condFields.filter(c => c.category === 'field');
    const conditions = condFields.filter(c => c.category === 'condition');
    const actions = actSev.filter(c => c.category === 'action');
    const sevItems = actSev.filter(c => c.category === 'severity');
    const severity = sevItems.length > 0 ? sevItems[0].value : 'Medium';

    if (ds.length === 0 && fields.length === 0 && conditions.length === 0) {
        document.getElementById('rb-code-output').textContent = '// Drop components onto the canvas to generate a detection rule...\n// Flow: Data Source -> Conditions/Fields -> Actions';
        const edr = document.getElementById('rb-edr-output');
        const xdr = document.getElementById('rb-xdr-output');
        const soar = document.getElementById('rb-soar-output');
        if (edr) edr.textContent = '// Build a SIEM rule first — EDR detection auto-generates from your rule components';
        if (xdr) xdr.textContent = '// Build a SIEM rule first — XDR correlation auto-generates from your rule components';
        if (soar) soar.textContent = '// Build a SIEM rule first — SOAR playbook auto-generates from your rule components';
        return;
    }

    // Generate SIEM query (existing logic)
    let code = '';
    switch (platform) {
        case 'splunk': code = rbGenSplunk(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
        case 'kql': code = rbGenKQL(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
        case 'aql': code = rbGenAQL(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
        case 'eql': code = rbGenEQL(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
        case 'wazuh': code = rbGenWazuh(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
        case 'yaral': code = rbGenYARAL(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
        case 'sigma': code = rbGenSigma(ruleName, ruleDesc, ds, fields, conditions, actions, severity, mitreId, fpGuidance); break;
    }

    // Populate SIEM card
    const output = document.getElementById('rb-code-output');
    if (output) output.textContent = code;

    // Auto-generate EDR / XDR / SOAR cards
    const edrOutput = document.getElementById('rb-edr-output');
    const xdrOutput = document.getElementById('rb-xdr-output');
    const soarOutput = document.getElementById('rb-soar-output');

    if (edrOutput) edrOutput.textContent = rbGenEDR(ruleName, severity, ds, fields, actions, mitreId);
    if (xdrOutput) xdrOutput.textContent = rbGenXDR(ruleName, severity, ds, fields, mitreId);
    if (soarOutput) soarOutput.textContent = rbGenSOAR(ruleName, severity, actions, mitreId);
}

function rbSlug(name) {
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

function rbGenSplunk(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const dsStr = ds.length > 0 ? dsMap[ds[0].value]?.splunk || 'index=main' : 'index=main';
    let search = dsStr;

    if (fields.length > 0) {
        const hasNot = conditions.some(c => c.value === 'NOT');
        const hasOr = conditions.some(c => c.value === 'OR');
        const joiner = hasOr ? ' OR ' : ' ';
        const fieldClauses = fields.map(f => {
            const fn = fieldMap[f.value]?.splunk || f.value.toLowerCase().replace(/ /g, '_');
            return `${fn}=*`;
        });
        if (hasNot && fieldClauses.length > 1) {
            search += '\n| search ' + fieldClauses.slice(0, -1).join(joiner) + ' NOT ' + fieldClauses[fieldClauses.length - 1];
        } else {
            search += '\n| search ' + fieldClauses.join(joiner);
        }
    }

    const hasCount = conditions.some(c => c.value === 'COUNT >');
    const hasThreshold = conditions.some(c => c.value === 'THRESHOLD');
    const hasTimeWindow = conditions.some(c => c.value === 'TIME WINDOW');
    const hasAgg = conditions.some(c => c.value === 'AGGREGATION');

    if (hasCount || hasThreshold || hasAgg) {
        const groupBy = fields.length > 0 ? fieldMap[fields[0].value]?.splunk || 'src_ip' : 'src_ip';
        search += `\n| stats count by ${groupBy}`;
        search += '\n| where count > 5';
    }

    if (hasTimeWindow) {
        search = `${dsStr} earliest=-15m latest=now\n` + search.split('\n').slice(1).join('\n');
    }

    const hasSequence = conditions.some(c => c.value === 'SEQUENCE');
    if (hasSequence) {
        search += '\n| transaction user maxspan=5m';
    }

    const actionStrs = actions.map(a => a.value.toLowerCase()).join(', ');

    let result = `\`\`\` Splunk SPL Detection Rule \`\`\`
\`\`\` Rule: ${name} \`\`\`
\`\`\` Description: ${desc} \`\`\`
\`\`\` MITRE ATT&CK: ${mitreId} \`\`\`
\`\`\` Severity: ${severity} \`\`\`
\`\`\` False Positives: ${fp} \`\`\`
\`\`\` Response Actions: ${actionStrs || 'alert'} \`\`\`

${search}
| eval severity="${severity.toLowerCase()}"
| eval mitre_attack="${mitreId}"`;

    if (actions.some(a => a.value === 'Alert')) {
        result += '\n| sendalert notable';
    }

    return result;
}

function rbGenKQL(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const dsStr = ds.length > 0 ? dsMap[ds[0].value]?.kql || 'SecurityEvent' : 'SecurityEvent';
    let query = `// ${name}\n// ${desc}\n// MITRE: ${mitreId} | Severity: ${severity}\n// False Positives: ${fp}\n\n${dsStr}`;

    const hasTimeWindow = conditions.some(c => c.value === 'TIME WINDOW');
    if (hasTimeWindow) {
        query += '\n| where TimeGenerated > ago(15m)';
    }

    if (fields.length > 0) {
        const hasNot = conditions.some(c => c.value === 'NOT');
        const hasOr = conditions.some(c => c.value === 'OR');
        const joiner = hasOr ? ' or ' : ' and ';
        const clauses = fields.map(f => {
            const fn = fieldMap[f.value]?.kql || f.value.replace(/ /g, '');
            return `isnotempty(${fn})`;
        });
        if (hasNot && clauses.length > 1) {
            const last = clauses.pop();
            query += '\n| where ' + clauses.join(joiner) + ' and not(' + last + ')';
        } else {
            query += '\n| where ' + clauses.join(joiner);
        }
    }

    const hasCount = conditions.some(c => c.value === 'COUNT >');
    const hasThreshold = conditions.some(c => c.value === 'THRESHOLD');
    const hasAgg = conditions.some(c => c.value === 'AGGREGATION');

    if (hasCount || hasThreshold || hasAgg) {
        const groupBy = fields.length > 0 ? fieldMap[fields[0].value]?.kql || 'SourceIP' : 'SourceIP';
        query += `\n| summarize Count = count() by ${groupBy}`;
        query += '\n| where Count > 5';
    }

    const hasSequence = conditions.some(c => c.value === 'SEQUENCE');
    if (hasSequence && fields.length > 0) {
        const groupBy = fieldMap[fields[0].value]?.kql || 'AccountName';
        query += `\n| order by TimeGenerated asc\n| serialize\n| extend SessionId = row_number(1, prev(${groupBy}) != ${groupBy})`;
    }

    query += `\n| extend AlertSeverity = "${severity}"`;
    query += `\n| extend MitreAttack = "${mitreId}"`;

    return query;
}

function rbGenAQL(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const dsStr = ds.length > 0 ? dsMap[ds[0].value]?.aql || "SELECT * FROM events" : "SELECT * FROM events";
    let query = `-- ${name}\n-- ${desc}\n-- MITRE: ${mitreId} | Severity: ${severity}\n-- False Positives: ${fp}\n\n`;

    const fieldNames = fields.map(f => fieldMap[f.value]?.aql || `"${f.value}"`);
    const selectFields = fieldNames.length > 0 ? fieldNames.join(', ') : '*';
    const baseFrom = dsStr.includes('SELECT') ? dsStr.replace('SELECT * FROM', `SELECT ${selectFields},\n    LOGSOURCENAME(logsourceid) as log_source FROM`) : `SELECT ${selectFields} FROM events`;

    query += baseFrom;

    if (fields.length > 0) {
        const hasNot = conditions.some(c => c.value === 'NOT');
        const hasOr = conditions.some(c => c.value === 'OR');
        const joiner = hasOr ? ' OR ' : ' AND ';
        const clauses = fields.map(f => {
            const fn = fieldMap[f.value]?.aql || `"${f.value}"`;
            return `${fn} IS NOT NULL`;
        });

        const whereExists = baseFrom.includes('WHERE');
        const prefix = whereExists ? '\n    AND ' : '\n WHERE ';

        if (hasNot && clauses.length > 1) {
            const last = clauses.pop();
            query += prefix + clauses.join(joiner) + ' AND NOT ' + last;
        } else {
            query += prefix + clauses.join(joiner);
        }
    }

    const hasCount = conditions.some(c => c.value === 'COUNT >');
    const hasThreshold = conditions.some(c => c.value === 'THRESHOLD');
    if (hasCount || hasThreshold) {
        const groupBy = fields.length > 0 ? fieldMap[fields[0].value]?.aql || 'sourceip' : 'sourceip';
        query += `\n GROUP BY ${groupBy}\n HAVING COUNT(*) > 5`;
    }

    const hasTimeWindow = conditions.some(c => c.value === 'TIME WINDOW');
    if (hasTimeWindow) {
        query += "\n    AND DATERANGE('last 15 minutes')";
    }

    query += `\n ORDER BY starttime DESC\n LAST 100`;

    return query;
}

function rbGenEQL(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const dsBase = ds.length > 0 ? dsMap[ds[0].value]?.eql || 'any where true' : 'any where true';
    const parts = dsBase.split(' where ');
    const eventType = parts[0];
    let whereClauses = parts[1] && parts[1] !== 'true' ? [parts[1]] : [];

    let query = `/* ${name} */\n/* ${desc} */\n/* MITRE: ${mitreId} | Severity: ${severity} */\n/* False Positives: ${fp} */\n\n`;

    if (fields.length > 0) {
        const hasNot = conditions.some(c => c.value === 'NOT');
        const hasOr = conditions.some(c => c.value === 'OR');
        const joiner = hasOr ? ' or ' : ' and ';
        const clauses = fields.map(f => {
            const fn = fieldMap[f.value]?.eql || f.value.toLowerCase().replace(/ /g, '.');
            return `${fn} != null`;
        });
        if (hasNot && clauses.length > 1) {
            const last = clauses.pop();
            whereClauses.push(clauses.join(joiner) + ' and not ' + last);
        } else {
            whereClauses.push(clauses.join(joiner));
        }
    }

    const hasSequence = conditions.some(c => c.value === 'SEQUENCE');
    if (hasSequence && fields.length >= 2) {
        const f1 = fieldMap[fields[0].value]?.eql || 'process.name';
        const f2 = fieldMap[fields[1].value]?.eql || 'process.command_line';
        query += `sequence by user.name with maxspan=5m\n  [${eventType} where ${f1} != null]\n  [${eventType} where ${f2} != null]`;
    } else {
        const allWhere = whereClauses.length > 0 ? whereClauses.join(' and ') : 'true';
        query += `${eventType} where ${allWhere}`;
    }

    return query;
}

function rbGenWazuh(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const sevLevel = { 'Critical': '15', 'High': '12', 'Medium': '8', 'Low': '4', 'Informational': '2' };
    const level = sevLevel[severity] || '8';
    const ruleId = 100000 + Math.floor(Math.random() * 9000);

    const mitreIds = mitreId.split(',').map(s => s.trim()).filter(Boolean);
    const mitreTags = mitreIds.map(id => `      <mitre>\n        <id>${id}</id>\n      </mitre>`).join('\n');

    let fieldMatch = '';
    if (fields.length > 0) {
        fields.forEach(f => {
            const fn = fieldMap[f.value]?.wazuh || f.value.toLowerCase().replace(/ /g, '_');
            fieldMatch += `    <field name="${fn}">\\.+</field>\n`;
        });
    }

    const dsGroup = ds.length > 0 ? dsMap[ds[0].value]?.wazuh || '<if_group>syslog</if_group>' : '<if_group>syslog</if_group>';

    let activeResponse = '';
    if (actions.some(a => a.value === 'Block' || a.value === 'Isolate Host')) {
        activeResponse = `\n  <!-- Active Response -->\n  <active-response>\n    <command>firewall-drop</command>\n    <location>local</location>\n    <rules_id>${ruleId}</rules_id>\n    <timeout>600</timeout>\n  </active-response>`;
    }

    const hasCount = conditions.some(c => c.value === 'COUNT >' || c.value === 'THRESHOLD');
    let freqBlock = '';
    if (hasCount) {
        freqBlock = `    <frequency>5</frequency>\n    <timeframe>300</timeframe>\n`;
    }

    return `<!-- ${name} -->
<!-- ${desc} -->
<!-- MITRE: ${mitreId} | Severity: ${severity} -->
<!-- False Positives: ${fp} -->

<group name="${rbSlug(name)},">
  <rule id="${ruleId}" level="${level}">
    ${dsGroup}
${freqBlock}${fieldMatch}    <description>${name}: ${desc}</description>
    <options>no_full_log</options>
    <group>${rbSlug(name)},${mitreIds.join(',')},</group>
${mitreTags}
  </rule>
</group>${activeResponse}`;
}

function rbGenYARAL(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const slug = rbSlug(name);
    const sevMap = { 'Critical': 'CRITICAL', 'High': 'HIGH', 'Medium': 'MEDIUM', 'Low': 'LOW', 'Informational': 'INFORMATIONAL' };
    const sev = sevMap[severity] || 'MEDIUM';

    let eventFilter = '';
    if (fields.length > 0) {
        const clauses = fields.map(f => {
            const fn = fieldMap[f.value]?.yaral || 'principal.hostname';
            return `      $e.${fn} != ""`;
        });
        const hasOr = conditions.some(c => c.value === 'OR');
        const joiner = hasOr ? ' or\n' : ' and\n';
        const hasNot = conditions.some(c => c.value === 'NOT');
        if (hasNot && clauses.length > 1) {
            const last = clauses.pop();
            eventFilter = clauses.join(joiner) + ' and\n      not ' + last.trim();
        } else {
            eventFilter = clauses.join(joiner);
        }
    }

    let matchSection = '';
    const hasCount = conditions.some(c => c.value === 'COUNT >' || c.value === 'THRESHOLD');
    if (hasCount) {
        const groupBy = fields.length > 0 ? `$e.${fieldMap[fields[0].value]?.yaral || 'principal.ip'}` : '$e.principal.ip';
        matchSection = `\n  match:\n    ${groupBy} over 15m\n\n  condition:\n    #e > 5`;
    } else {
        matchSection = '\n  condition:\n    $e';
    }

    const hasTimeWindow = conditions.some(c => c.value === 'TIME WINDOW');
    const windowClause = hasTimeWindow ? ' over 15m' : '';

    return `// ${name}
// ${desc}
// MITRE: ${mitreId} | Severity: ${severity}
// False Positives: ${fp}

rule ${slug} {
  meta:
    author = "BlueShell Rule Builder"
    description = "${desc}"
    severity = "${sev}"
    mitre_attack = "${mitreId}"

  events:
    $e.metadata.event_type = "GENERIC_EVENT"
${eventFilter ? eventFilter : '    $e.principal.hostname != ""'}
${matchSection}

  outcome:
    $risk_score = max(if(#e > 10, 80, 50))
    $severity = "${sev}"

  options:
    allow_zero_values = false
}`;
}

function rbGenSigma(name, desc, ds, fields, conditions, actions, severity, mitreId, fp) {
    const logsource = ds.length > 0 ? dsMap[ds[0].value]?.sigma || 'process_creation' : 'process_creation';
    const sevMap = { 'Critical': 'critical', 'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'informational' };
    const sev = sevMap[severity] || 'medium';

    const mitreIds = mitreId.split(',').map(s => s.trim()).filter(Boolean);
    const mitreTags = mitreIds.map(id => `    - attack.${id.toLowerCase()}`).join('\n');
    const tacticTags = (rbCanvasState.tactic || []).map(t => `    - attack.${t.value.toLowerCase().replace(/ /g, '_')}`).join('\n');

    let detectionBlock = '  selection:\n';
    let hasFilter = false;

    if (fields.length > 0) {
        const hasNot = conditions.some(c => c.value === 'NOT');
        fields.forEach((f, i) => {
            const fn = fieldMap[f.value]?.sigma || f.value;
            if (hasNot && i === fields.length - 1) {
                detectionBlock += `  filter:\n    ${fn}|contains: ''\n`;
                hasFilter = true;
            } else {
                detectionBlock += `    ${fn}|contains: '*'\n`;
            }
        });
    } else {
        detectionBlock += "    EventID: '*'\n";
    }

    detectionBlock += hasFilter ? '  condition: selection and not filter' : '  condition: selection';

    const hasCount = conditions.some(c => c.value === 'COUNT >' || c.value === 'THRESHOLD');
    if (hasCount) {
        detectionBlock += ' | count() by ' + (fields.length > 0 ? fieldMap[fields[0].value]?.sigma || 'src_ip' : 'src_ip') + ' > 5';
    }

    const hasTimeWindow = conditions.some(c => c.value === 'TIME WINDOW');
    if (hasTimeWindow) {
        detectionBlock += '\n  timeframe: 15m';
    }

    // Determine logsource category
    let logsourceBlock = '';
    const catMap = {
        'process_creation': 'category: process_creation\n    product: windows',
        'windows': 'product: windows\n    service: security',
        'linux': 'product: linux\n    service: syslog',
        'firewall': 'category: firewall',
        'dns_query': 'category: dns_query',
        'proxy': 'category: proxy',
        'aws': 'product: aws\n    service: cloudtrail',
        'network_connection': 'category: network_connection\n    product: windows'
    };
    logsourceBlock = catMap[logsource] || `category: ${logsource}`;

    return `title: ${name}
id: ${crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16); })}
status: experimental
description: |
  ${desc}
references:
  - https://attack.mitre.org/
author: BlueShell Rule Builder
date: ${new Date().toISOString().split('T')[0]}
tags:
${tacticTags}
${mitreTags}
logsource:
    ${logsourceBlock}
detection:
${detectionBlock}
falsepositives:
    - ${fp || 'Unknown'}
level: ${sev}`;
}

// ── Copy & Export ──

function rbCopyRule() {
    const code = document.getElementById('rb-code-output')?.textContent || '';
    if (!code || code.startsWith('//')) return;
    navigator.clipboard.writeText(code).then(() => {
        rbShowToast('Rule copied to clipboard');
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = code;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        rbShowToast('Rule copied to clipboard');
    });
}

function rbExport(format) {
    const ruleName = document.getElementById('rb-rule-name')?.value || 'Untitled Rule';
    const ruleDesc = document.getElementById('rb-rule-desc')?.value || '';
    const mitreId = document.getElementById('rb-mitre-id')?.value || '';
    const fpGuidance = document.getElementById('rb-fp-guidance')?.value || '';
    const platform = document.getElementById('rb-platform')?.value || 'splunk';
    const code = document.getElementById('rb-code-output')?.textContent || '';
    const actSev = rbCanvasState.action || [];
    const sevItems = actSev.filter(c => c.category === 'severity');
    const severity = sevItems.length > 0 ? sevItems[0].value : 'Medium';

    const exportData = {
        name: ruleName,
        description: ruleDesc,
        mitre_attack_ids: mitreId.split(',').map(s => s.trim()).filter(Boolean),
        mitre_tactics: (rbCanvasState.tactic || []).map(t => t.value),
        severity: severity,
        false_positives: fpGuidance,
        platform: platform,
        data_sources: (rbCanvasState.datasource || []).map(d => d.value),
        fields: (rbCanvasState.condition || []).filter(c => c.category === 'field').map(c => c.value),
        conditions: (rbCanvasState.condition || []).filter(c => c.category === 'condition').map(c => c.value),
        actions: (rbCanvasState.action || []).filter(c => c.category === 'action').map(c => c.value),
        rule_code: code,
        exported_at: new Date().toISOString(),
        tool: 'BlueShell Rule Builder'
    };

    let content, filename, mimeType;

    if (format === 'yaml') {
        content = rbToYaml(exportData);
        filename = rbSlug(ruleName) + '.yaml';
        mimeType = 'text/yaml';
    } else {
        content = JSON.stringify(exportData, null, 2);
        filename = rbSlug(ruleName) + '.json';
        mimeType = 'application/json';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    rbShowToast(`Exported as ${format.toUpperCase()}: ${filename}`);
}

function rbToYaml(obj, indent) {
    indent = indent || 0;
    const pad = '  '.repeat(indent);
    let yaml = '';
    for (const [key, val] of Object.entries(obj)) {
        if (Array.isArray(val)) {
            yaml += `${pad}${key}:\n`;
            val.forEach(v => {
                if (typeof v === 'object') {
                    yaml += `${pad}  -\n` + rbToYaml(v, indent + 2);
                } else {
                    yaml += `${pad}  - ${JSON.stringify(v)}\n`;
                }
            });
        } else if (typeof val === 'object' && val !== null) {
            yaml += `${pad}${key}:\n` + rbToYaml(val, indent + 1);
        } else if (typeof val === 'string' && val.includes('\n')) {
            yaml += `${pad}${key}: |\n`;
            val.split('\n').forEach(line => { yaml += `${pad}  ${line}\n`; });
        } else {
            yaml += `${pad}${key}: ${JSON.stringify(val)}\n`;
        }
    }
    return yaml;
}

function rbShowToast(msg) {
    const existing = document.querySelector('.rb-toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.className = 'rb-toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
}
