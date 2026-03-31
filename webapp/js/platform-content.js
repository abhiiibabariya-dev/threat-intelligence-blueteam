// ═══════════════════════════════════════════════════════
// BLUESHELL - Platform Content Engine
// Rich detailed content for every platform page
// ═══════════════════════════════════════════════════════

// ── Utility: Copy code block to clipboard ──
function copyCodeBlock(btn) {
    const pre = btn.closest('.code-block-wrapper').querySelector('pre');
    const text = pre.innerText;
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'COPIED';
        btn.style.color = 'var(--accent)';
        setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
    });
}

// ── Helper: wrap code with copy button ──
function codeBlock(code, lang) {
    const escaped = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return `<div class="code-block-wrapper" style="position:relative;margin:10px 0">
        <div style="display:flex;justify-content:space-between;align-items:center;background:var(--bg-tertiary);border:1px solid var(--border);border-bottom:none;border-radius:4px 4px 0 0;padding:4px 12px">
            <span style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px">${lang||''}</span>
            <button onclick="copyCodeBlock(this)" class="btn-hack" style="font-size:9px;padding:2px 8px;border:1px solid var(--border)">COPY</button>
        </div>
        <pre style="margin:0;border-radius:0 0 4px 4px;border-top:none"><code>${escaped}</code></pre>
    </div>`;
}

// ── Helper: build tabbed interface ──
function buildTabs(pageId, tabs) {
    let btns = '', panels = '';
    tabs.forEach((t, i) => {
        const active = i === 0 ? 'active' : '';
        btns += `<button class="pc-tab-btn ${active}" data-tab="${pageId}-tab-${i}" onclick="switchPCTab(this)">${t.label}</button>`;
        panels += `<div class="pc-tab-panel ${active}" id="${pageId}-tab-${i}">${t.content}</div>`;
    });
    return `<div class="pc-tabs"><div class="pc-tab-bar">${btns}</div>${panels}</div>`;
}

function switchPCTab(btn) {
    const bar = btn.parentElement;
    const tabs = bar.parentElement;
    bar.querySelectorAll('.pc-tab-btn').forEach(b => b.classList.remove('active'));
    tabs.querySelectorAll('.pc-tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
}

// ── Inject tab styles ──
(function injectPCStyles(){
    const style = document.createElement('style');
    style.textContent = `
        .pc-tabs { margin-top: 16px; }
        .pc-tab-bar { display:flex; gap:0; border-bottom:1px solid var(--border); margin-bottom:16px; flex-wrap:wrap; }
        .pc-tab-btn { background:transparent; border:1px solid var(--border); border-bottom:none; color:var(--text-secondary); font-family:var(--font-mono); font-size:11px; padding:8px 18px; cursor:pointer; letter-spacing:1px; text-transform:uppercase; transition:all .2s; }
        .pc-tab-btn:hover { color:var(--accent); background:var(--accent-dim); }
        .pc-tab-btn.active { color:var(--accent); background:var(--bg-card); border-color:var(--accent); border-bottom:2px solid var(--bg-card); margin-bottom:-1px; text-shadow:0 0 8px var(--accent); }
        .pc-tab-panel { display:none; }
        .pc-tab-panel.active { display:block; }
        .pc-info-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:12px; margin:12px 0; }
        .pc-info-card { background:var(--bg-card); border:1px solid var(--border); border-radius:4px; padding:14px; }
        .pc-info-card h4 { color:var(--accent); font-size:12px; margin-bottom:6px; letter-spacing:1px; }
        .pc-info-card p, .pc-info-card li { color:var(--text-secondary); font-size:11px; line-height:1.6; }
        .pc-info-card ul { padding-left:16px; margin:4px 0; }
        .pc-step { display:flex; gap:12px; margin:10px 0; align-items:flex-start; }
        .pc-step-num { background:var(--accent); color:var(--bg-primary); width:24px; height:24px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; flex-shrink:0; }
        .pc-step-body { flex:1; }
        .pc-step-body h4 { color:var(--text-primary); font-size:12px; margin-bottom:4px; }
        .pc-step-body p { color:var(--text-secondary); font-size:11px; line-height:1.5; }
        .pc-warning { background:rgba(255,51,51,0.08); border:1px solid rgba(255,51,51,0.3); border-radius:4px; padding:12px; margin:10px 0; }
        .pc-warning h4 { color:var(--accent-red); font-size:12px; margin-bottom:4px; }
        .pc-warning li { color:var(--text-secondary); font-size:11px; line-height:1.6; }
        .pc-tip { background:rgba(0,255,65,0.05); border:1px solid rgba(0,255,65,0.2); border-radius:4px; padding:12px; margin:10px 0; }
        .pc-tip h4 { color:var(--accent); font-size:12px; margin-bottom:4px; }
        .pc-tip li, .pc-tip p { color:var(--text-secondary); font-size:11px; line-height:1.6; }
    `;
    document.head.appendChild(style);
})();

// ═══════════════════════════════════════════════════════
// SOAR PAGE DATA — add missing entries to pageData
// ═══════════════════════════════════════════════════════
const soarPages = {
    splunksoar: { title: "SPLUNK SOAR (PHANTOM)", type: "SOAR", desc: "Security orchestration, automation and response platform", features: ["Phantom Playbooks (Python)", "400+ App Integrations", "Visual Playbook Editor", "Custom Functions", "Case Management", "Zero-to-Hero Training Guide"], path: "../soar/" },
    sentinelsoar: { title: "MICROSOFT SENTINEL SOAR", type: "SOAR", desc: "Cloud-native SOAR with Logic Apps", features: ["Logic App Playbooks", "Automation Rules", "Playbook Templates Gallery", "Entity Triggers", "Cost Optimization", "Zero-to-Hero Training Guide"], path: "../soar/" },
    xsoar: { title: "PALO ALTO XSOAR", type: "SOAR", desc: "Cortex XSOAR orchestration platform", features: ["YAML Playbooks", "700+ Integrations", "War Room Collaboration", "Indicator Management", "XSOAR Marketplace", "Zero-to-Hero Training Guide"], path: "../soar/" },
    qradarsoar: { title: "IBM QRADAR SOAR (RESILIENT)", type: "SOAR", desc: "Incident response and SOAR platform", features: ["Dynamic Playbooks", "Custom Functions (Python)", "Rules & Conditions", "Data Tables", "Action Module", "Zero-to-Hero Training Guide"], path: "../soar/" },
    shuffle: { title: "SHUFFLE SOAR", type: "SOAR", desc: "Open-source security automation", features: ["Drag-and-Drop Workflows", "OpenAPI App Generation", "Wazuh Integration", "Docker-Based Architecture", "HTTP Webhooks", "Zero-to-Hero Training Guide"], path: "../soar/" },
    thehive: { title: "THEHIVE + CORTEX", type: "SOAR", desc: "Open-source case management and response", features: ["Case & Alert Management", "Cortex Analyzers (100+)", "Cortex Responders", "MISP Integration", "Custom Dashboards", "Zero-to-Hero Training Guide"], path: "../soar/" },
    fortisoar: { title: "FORTISOAR", type: "SOAR", desc: "Fortinet security orchestration platform", features: ["Visual Playbook Designer", "300+ Connectors", "Solution Packs", "Recommendation Engine", "Multi-Tenant Support", "Zero-to-Hero Training Guide"], path: "../soar/" }
};

// Merge SOAR pages into existing pageData
if (typeof pageData !== 'undefined') {
    Object.assign(pageData, soarPages);
}

// Also add missing blue team entries
const blueTeamExtraPages = {
    alerttriage: { title: "ALERT TRIAGE FRAMEWORK", type: "BLUE TEAM", desc: "Structured alert analysis and prioritization", features: ["Severity Matrix", "Triage Decision Tree", "False Positive Identification", "Escalation Criteria", "SLA Guidelines"], path: "../blue-team-resources/alert-triage/" },
    socrunbooks: { title: "SOC RUNBOOKS", type: "BLUE TEAM", desc: "Operational procedures for SOC analysts", features: ["Shift Handoff Procedures", "Escalation Paths", "Tool Access Runbooks", "Communication Templates", "Metrics & KPIs"], path: "../blue-team-resources/soc-runbooks/" },
    detectioneng: { title: "DETECTION ENGINEERING", type: "BLUE TEAM", desc: "Systematic approach to building detection rules", features: ["Rule Creation Methodology", "MITRE ATT&CK Mapping Guide", "Testing & Validation", "Detection-as-Code Pipeline", "Coverage Gap Analysis"], path: "../blue-team-resources/detection-engineering/" },
    iocmgmt: { title: "IOC MANAGEMENT", type: "BLUE TEAM", desc: "IOC lifecycle and threat intelligence sharing", features: ["IOC Types & Lifecycle", "STIX2 / TAXII Format", "Sharing Communities (ISACs)", "Enrichment Workflows", "Expiration Policies"], path: "../tools/" },
    mitremap: { title: "MITRE ATT&CK MAP", type: "TOOL", desc: "Interactive technique browser and coverage mapper", features: ["Technique Browser", "Detection Coverage Heatmap", "Gap Analysis", "Navigator Layer Export", "Custom Annotations"], path: "../tools/" }
};

if (typeof pageData !== 'undefined') {
    Object.assign(pageData, blueTeamExtraPages);
}

// ═══════════════════════════════════════════════════════
// PLATFORM CONTENT — detailed HTML for each platform
// ═══════════════════════════════════════════════════════

const platformContent = {};

// ─────────────────────────────────────────────────────
// 1. SPLUNK
// ─────────────────────────────────────────────────────
platformContent.splunk = {
    overview: `
        <h3>What is Splunk?</h3>
        <p>Splunk is an enterprise SIEM platform that ingests machine data from any source and uses the Search Processing Language (SPL) to search, correlate, and visualize security events in real time. Splunk Enterprise Security (ES) adds pre-built dashboards, correlation searches, and risk-based alerting on top of the core platform.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card">
                <h4>CORE COMPONENTS</h4>
                <ul>
                    <li>Search Head — runs SPL queries</li>
                    <li>Indexer — stores and indexes data</li>
                    <li>Forwarder (UF/HF) — ships logs</li>
                    <li>Deployment Server — manages configs</li>
                    <li>Enterprise Security (ES) app</li>
                </ul>
            </div>
            <div class="pc-info-card">
                <h4>KEY CONCEPTS</h4>
                <ul>
                    <li><code>index</code> — logical data store</li>
                    <li><code>sourcetype</code> — data format</li>
                    <li><code>fields</code> — extracted key-value pairs</li>
                    <li><code>notable events</code> — ES alerts</li>
                    <li><code>risk score</code> — RBA cumulative score</li>
                </ul>
            </div>
            <div class="pc-info-card">
                <h4>DEPLOYMENT GUIDE</h4>
                <ul>
                    <li>Install Splunk Enterprise or Cloud</li>
                    <li>Deploy Universal Forwarders to endpoints</li>
                    <li>Configure inputs.conf and outputs.conf</li>
                    <li>Install Enterprise Security app from Splunkbase</li>
                    <li>Enable CIM data models for ES compatibility</li>
                    <li>Configure index retention policies</li>
                </ul>
            </div>
        </div>

        <h3>Architecture Overview</h3>
        ${codeBlock(`┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Endpoints  │────▶│  Forwarders  │────▶│   Indexers   │
│ (UF agents)  │     │  (HF/UF)     │     │  (clustered) │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
┌──────────────┐     ┌──────────────┐     ┌──────▼───────┐
│  Analysts    │◀────│  Search Head │◀────│  ES App      │
│  (browser)   │     │  (SH cluster)│     │  (dashboards)│
└──────────────┘     └──────────────┘     └──────────────┘`, 'Architecture')}

        <h3>SPL Basics Quick Reference</h3>
        ${codeBlock(`# Basic search
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, user
| where count > 5

# Time-based search
index=firewall action=blocked earliest=-24h
| timechart span=1h count by src_ip

# Lookup enrichment
index=proxy | lookup threat_intel_lookup domain AS url_domain OUTPUT threat_score
| where threat_score > 70

# Transaction (group related events)
index=wineventlog EventCode IN (4624, 4625)
| transaction user maxspan=5m
| where eventcount > 10`, 'SPL')}
    `,

    rules: `
        <h3>Detection Rule 1: Brute Force Authentication</h3>
        <p>Detects multiple failed logins followed by a success from the same source, indicating a successful brute-force attack. Maps to MITRE T1110.</p>
        ${codeBlock(`index=wineventlog sourcetype=WinEventLog:Security
    (EventCode=4625 OR EventCode=4624)
| stats
    count(eval(EventCode=4625)) AS failed,
    count(eval(EventCode=4624)) AS success,
    values(EventCode) AS event_codes,
    latest(_time) AS last_event
    by src_ip, user
| where failed >= 5 AND success > 0
| eval risk_score = failed * 10
| sort - risk_score
| table src_ip, user, failed, success, risk_score, last_event`, 'SPL — Brute Force Detection')}

        <h3>Detection Rule 2: Suspicious PowerShell Execution</h3>
        <p>Identifies encoded PowerShell commands and known malicious patterns. Maps to MITRE T1059.001.</p>
        ${codeBlock(`index=wineventlog sourcetype=WinEventLog:Security EventCode=4688
    (New_Process_Name="*powershell.exe" OR New_Process_Name="*pwsh.exe")
| eval cmd=lower(Process_Command_Line)
| where match(cmd, "-enc|-encodedcommand|-e ") OR
        match(cmd, "invoke-expression|iex |downloadstring|downloadfile") OR
        match(cmd, "frombase64string|decompress|gzipstream") OR
        match(cmd, "bypass|hidden|-w hidden|-nop")
| eval risk_score = case(
    match(cmd,"frombase64string"), 90,
    match(cmd,"-enc"), 80,
    match(cmd,"downloadstring"), 85,
    1=1, 60)
| table _time, host, user, Process_Command_Line, risk_score`, 'SPL — PowerShell Detection')}

        <h3>Detection Rule 3: Lateral Movement via PsExec</h3>
        <p>Detects PsExec-style lateral movement by correlating service creation with network logons. Maps to MITRE T1021.002 and T1570.</p>
        ${codeBlock(`index=wineventlog sourcetype=WinEventLog:Security
    (EventCode=7045 OR EventCode=4624)
| eval event_type = case(EventCode=7045, "service_created", EventCode=4624, "logon")
| where (event_type="service_created" AND Service_Name="PSEXESVC") OR
        (event_type="logon" AND Logon_Type=3)
| stats
    count(eval(event_type="service_created")) AS svc_count,
    count(eval(event_type="logon")) AS net_logon_count,
    values(host) AS targets,
    dc(host) AS target_count
    by src_ip
| where svc_count > 0 AND target_count > 1
| table src_ip, targets, target_count, svc_count, net_logon_count`, 'SPL — Lateral Movement')}

        <h3>Detection Rule 4: Data Exfiltration via DNS</h3>
        <p>Detects DNS tunneling by identifying unusually long DNS queries and high query volumes to a single domain. Maps to MITRE T1048.003.</p>
        ${codeBlock(`index=dns sourcetype=dns
| eval query_length = len(query)
| eval subdomain_count = mvcount(split(query, ".")) - 2
| stats
    count AS query_count,
    avg(query_length) AS avg_len,
    max(query_length) AS max_len,
    dc(query) AS unique_queries,
    values(src_ip) AS sources
    by domain
| where (avg_len > 40 AND query_count > 50) OR
        (unique_queries > 100 AND max_len > 60)
| sort - query_count
| table domain, query_count, avg_len, max_len, unique_queries, sources`, 'SPL — DNS Exfiltration')}

        <h3>Detection Rule 5: Credential Dumping (LSASS Access)</h3>
        <p>Detects processes accessing LSASS memory, a common credential theft technique. Maps to MITRE T1003.001.</p>
        ${codeBlock(`index=wineventlog sourcetype=WinEventLog:Security EventCode=4663
    Object_Name="*\\\\lsass.exe"
| eval suspicious = if(
    NOT match(Process_Name, "(?i)(csrss|services|svchost|wininit|lsass)\\\\.exe$"), 1, 0)
| where suspicious=1
| stats count, values(Process_Name) AS accessing_process, latest(_time) AS last_seen by host, user
| where count > 0
| table _time, host, user, accessing_process, count`, 'SPL — LSASS Access Detection')}

        <h3>Splunk ES Dashboard XML Snippet</h3>
        <p>Simple XML dashboard panel for monitoring brute-force attempts:</p>
        ${codeBlock(`<dashboard>
  <label>SOC - Authentication Monitoring</label>
  <row>
    <panel>
      <title>Failed Logins by Source IP (Last 24h)</title>
      <chart>
        <search>
          <query>index=wineventlog EventCode=4625 earliest=-24h
| stats count by src_ip
| sort - count
| head 20</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.showDataLabels">all</option>
      </chart>
    </panel>
  </row>
</dashboard>`, 'XML — Splunk Dashboard')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>

        <div class="pc-step">
            <div class="pc-step-num">1</div>
            <div class="pc-step-body">
                <h4>Week 1-2: SPL Fundamentals</h4>
                <p>Learn search commands: <code>stats</code>, <code>eval</code>, <code>where</code>, <code>table</code>, <code>rename</code>, <code>rex</code>. Practice on Splunk's free Boss of the SOC (BOTS) dataset. Understand the search pipeline concept: every pipe passes results to the next command.</p>
            </div>
        </div>
        <div class="pc-step">
            <div class="pc-step-num">2</div>
            <div class="pc-step-body">
                <h4>Week 3-4: Data Onboarding</h4>
                <p>Configure inputs.conf, props.conf, transforms.conf. Set up a Heavy Forwarder for syslog collection. Understand CIM (Common Information Model) field normalization. Create custom sourcetypes with field extractions.</p>
            </div>
        </div>
        <div class="pc-step">
            <div class="pc-step-num">3</div>
            <div class="pc-step-body">
                <h4>Week 5-6: Enterprise Security (ES)</h4>
                <p>Install and configure ES. Understand Notable Events, Investigations, and the Risk Framework. Create correlation searches. Build custom dashboards with drilldowns. Configure adaptive response actions.</p>
            </div>
        </div>
        <div class="pc-step">
            <div class="pc-step-num">4</div>
            <div class="pc-step-body">
                <h4>Week 7-8: Advanced Detection & Hunting</h4>
                <p>Master subsearches, macros, and data models. Build risk-based alerting (RBA) rules. Use <code>tstats</code> for accelerated searches. Create threat hunting notebooks. Implement MITRE ATT&CK coverage tracking.</p>
            </div>
        </div>

        <h3>Essential SPL Commands for SOC Analysts</h3>
        ${codeBlock(`# stats — aggregate results
| stats count, dc(user) AS unique_users, values(src_ip) AS sources by dest

# eval — create calculated fields
| eval risk = if(action="blocked", severity*2, severity)

# rex — extract fields with regex
| rex field=Process_Command_Line "(?i)-enc(?:odedcommand)?\\s+(?<encoded_payload>[A-Za-z0-9+/=]+)"

# lookup — enrich with external data
| lookup geo_ip_lookup ip AS src_ip OUTPUT country, city, lat, lon

# tstats — fast search over data models
| tstats count FROM datamodel=Authentication WHERE Authentication.action=failure BY Authentication.src, Authentication.user

# transaction — group events into sessions
| transaction session_id maxspan=30m maxpause=5m

# map — subsearch for each result
| map search="search index=wineventlog user=$user$ EventCode=4624 | head 1"`, 'SPL Reference')}

        <h3>Recommended Certifications</h3>
        <div class="pc-info-grid">
            <div class="pc-info-card">
                <h4>SPLUNK CORE CERTIFIED USER</h4>
                <p>Foundation cert. Learn basic searching, reporting, dashboards, lookups, and scheduled searches.</p>
            </div>
            <div class="pc-info-card">
                <h4>SPLUNK CORE CERTIFIED POWER USER</h4>
                <p>Intermediate. Data models, CIM, advanced SPL, macros, tags, event types.</p>
            </div>
            <div class="pc-info-card">
                <h4>SPLUNK CERTIFIED SOC ANALYST</h4>
                <p>Security-focused. ES workflows, notable events, threat intelligence, investigation techniques.</p>
            </div>
        </div>
    `,

    bestpractices: `
        <h3>Best Practices</h3>
        <div class="pc-tip">
            <h4>PERFORMANCE OPTIMIZATION</h4>
            <ul>
                <li>Always specify <code>index</code> and <code>sourcetype</code> at the start of your search to limit data scanned</li>
                <li>Use <code>tstats</code> over data models instead of raw <code>search</code> for high-volume queries</li>
                <li>Avoid wildcard-only searches (<code>index=* *</code>) — they scan everything</li>
                <li>Use <code>earliest</code> and <code>latest</code> to narrow time ranges</li>
                <li>Place filtering commands (<code>where</code>, <code>search</code>) as early as possible in the pipeline</li>
                <li>Use summary indexing or report acceleration for expensive recurring searches</li>
            </ul>
        </div>
        <div class="pc-tip">
            <h4>DETECTION ENGINEERING</h4>
            <ul>
                <li>Use Risk-Based Alerting (RBA) to reduce alert fatigue — assign risk to entities, alert on cumulative risk</li>
                <li>Map every detection rule to a MITRE ATT&CK technique</li>
                <li>Include false-positive exclusion logic in rules (known admin accounts, scheduled tasks)</li>
                <li>Test rules against 30 days of historical data before enabling in production</li>
                <li>Use <code>| outputlookup</code> to maintain watchlists of known-good hashes, IPs, and domains</li>
            </ul>
        </div>
        <div class="pc-warning">
            <h4>COMMON MISTAKES TO AVOID</h4>
            <ul>
                <li>Not normalizing data to CIM before writing correlation searches — your ES dashboards will be empty</li>
                <li>Using <code>index=*</code> in production searches — causes massive performance degradation</li>
                <li>Creating too many real-time searches — use scheduled searches with short intervals instead</li>
                <li>Not setting up index retention policies — storage costs balloon quickly</li>
                <li>Ignoring license usage monitoring — exceeding license limits causes indexing to pause</li>
                <li>Writing overly specific rules that only catch one variant — build behavioral detections</li>
                <li>Not using role-based access control — all analysts should not have admin access</li>
            </ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 2. MICROSOFT SENTINEL
// ─────────────────────────────────────────────────────
platformContent.sentinel = {
    overview: `
        <h3>What is Microsoft Sentinel?</h3>
        <p>Microsoft Sentinel is a cloud-native SIEM and SOAR solution built on Azure. It uses Kusto Query Language (KQL) for log analytics, provides built-in AI/ML for threat detection, and integrates with Azure Logic Apps for automated response playbooks. Sentinel operates on a pay-per-GB ingestion model.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card">
                <h4>CORE COMPONENTS</h4>
                <ul>
                    <li>Log Analytics Workspace — data store</li>
                    <li>Data Connectors — ingest logs</li>
                    <li>Analytics Rules — detection logic</li>
                    <li>Workbooks — dashboards/visualization</li>
                    <li>Playbooks — Logic App automations</li>
                    <li>Hunting Queries — proactive search</li>
                </ul>
            </div>
            <div class="pc-info-card">
                <h4>KEY CONCEPTS</h4>
                <ul>
                    <li><code>KQL</code> — Kusto Query Language</li>
                    <li><code>Tables</code> — SecurityEvent, SigninLogs, etc.</li>
                    <li><code>Analytics Rules</code> — Scheduled, NRT, Fusion, ML</li>
                    <li><code>Entities</code> — Account, IP, Host, URL</li>
                    <li><code>Incidents</code> — grouped alerts</li>
                    <li><code>UEBA</code> — User Entity Behavior Analytics</li>
                </ul>
            </div>
            <div class="pc-info-card">
                <h4>SETUP GUIDE</h4>
                <ul>
                    <li>Create Azure subscription + Log Analytics workspace</li>
                    <li>Enable Microsoft Sentinel on the workspace</li>
                    <li>Connect data sources (M365, Azure AD, Syslog, CEF)</li>
                    <li>Enable analytics rule templates</li>
                    <li>Configure automation rules and playbooks</li>
                    <li>Deploy Content Hub solutions</li>
                </ul>
            </div>
        </div>

        <h3>Cost Optimization Tips</h3>
        <div class="pc-tip">
            <h4>REDUCE SENTINEL COSTS</h4>
            <ul>
                <li>Use commitment tiers (100 GB/day+) for predictable discounts vs pay-as-you-go</li>
                <li>Filter noisy logs at the source using Data Collection Rules (DCR)</li>
                <li>Move low-value logs to Basic Logs tier (cheaper, limited query capability)</li>
                <li>Use Azure Data Explorer (ADX) for long-term retention instead of Sentinel</li>
                <li>Monitor ingestion with <code>Usage | summarize sum(Quantity) by DataType</code></li>
                <li>Archive logs older than 90 days to cold storage</li>
            </ul>
        </div>
    `,

    rules: `
        <h3>Analytics Rule 1: Brute Force Against Azure AD</h3>
        <p>Detects multiple failed sign-ins followed by a success from the same IP. MITRE T1110.</p>
        ${codeBlock(`let threshold = 10;
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType != "0"  // Failed logins
| summarize
    FailedCount = count(),
    FailedApps = make_set(AppDisplayName),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by IPAddress, UserPrincipalName
| where FailedCount >= threshold
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType == "0"  // Successful login
    | project SuccessTime = TimeGenerated, IPAddress, UserPrincipalName, SuccessApp = AppDisplayName
) on IPAddress, UserPrincipalName
| where SuccessTime > LastFailure
| project UserPrincipalName, IPAddress, FailedCount, FailedApps, SuccessTime, SuccessApp`, 'KQL — Brute Force Detection')}

        <h3>Analytics Rule 2: Suspicious PowerShell Download Cradle</h3>
        <p>Identifies PowerShell execution with download patterns indicating a malicious download cradle. MITRE T1059.001.</p>
        ${codeBlock(`DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "DownloadString", "DownloadFile", "DownloadData",
    "WebRequest", "WebClient", "Invoke-RestMethod",
    "curl ", "wget ", "Start-BitsTransfer"
)
| where ProcessCommandLine has_any (
    "http://", "https://", "ftp://"
)
| project TimeGenerated, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| extend URL = extract("(https?://[^\\\\s'\\";]+)", 1, ProcessCommandLine)`, 'KQL — PowerShell Download Cradle')}

        <h3>Analytics Rule 3: Impossible Travel Detection</h3>
        <p>Custom rule detecting logins from geographically impossible locations within a short timeframe. MITRE T1078.</p>
        ${codeBlock(`let TimeDeltaThreshold = 60m;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| extend PrevLocation = prev(Location), PrevLat = prev(Latitude),
    PrevLon = prev(Longitude), PrevTime = prev(TimeGenerated),
    PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend TimeDelta = datetime_diff('minute', TimeGenerated, PrevTime)
| extend Distance_KM = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
| extend Speed_KMH = Distance_KM / (TimeDelta / 60.0)
| where Speed_KMH > 900 and TimeDelta < TimeDeltaThreshold
| project TimeGenerated, UserPrincipalName, Location, PrevLocation,
    Distance_KM = round(Distance_KM), Speed_KMH = round(Speed_KMH), TimeDelta`, 'KQL — Impossible Travel')}

        <h3>Analytics Rule 4: Mass File Deletion (Ransomware Indicator)</h3>
        <p>Detects a single process deleting many files in rapid succession. MITRE T1485 / T1486.</p>
        ${codeBlock(`DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileDeleted" or ActionType == "FileRenamed"
| summarize
    DeletedCount = count(),
    FileExtensions = make_set(extract("\\\\.(\\\\w+)$", 1, FileName)),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated),
    FolderPaths = make_set(FolderPath, 10)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| where DeletedCount > 100
| extend DurationMinutes = datetime_diff('minute', LastEvent, FirstEvent)
| where DurationMinutes < 10
| project DeviceName, InitiatingProcessFileName,
    InitiatingProcessAccountName, DeletedCount,
    DurationMinutes, FileExtensions, FolderPaths`, 'KQL — Ransomware File Deletion')}

        <h3>Analytics Rule 5: Privilege Escalation via Azure AD Role Assignment</h3>
        <p>Detects when a user is assigned a highly privileged Azure AD role. MITRE T1098.</p>
        ${codeBlock(`AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| where Result == "success"
| extend RoleName = tostring(TargetResources[0].displayName)
| where RoleName in (
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator"
)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, TargetUser, RoleName,
    CorrelationId, IPAddress = tostring(InitiatedBy.user.ipAddress)`, 'KQL — Privilege Escalation')}

        <h3>Logic App Playbook Example (ARM Template Snippet)</h3>
        ${codeBlock(`{
  "definition": {
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "body": { "callback_url": "@{listCallbackUrl()}" },
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Get_Incident_Entities": {
        "type": "ApiConnection",
        "inputs": { "path": "/Incidents/@{triggerBody()?['properties']?['incidentNumber']}/entities" }
      },
      "For_Each_IP": {
        "type": "Foreach",
        "foreach": "@body('Get_Incident_Entities')?['IPs']",
        "actions": {
          "Block_IP_in_Firewall": {
            "type": "Http",
            "inputs": { "method": "POST", "uri": "https://firewall-api/block", "body": { "ip": "@items('For_Each_IP')" } }
          }
        }
      }
    }
  }
}`, 'JSON — Logic App Playbook')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step">
            <div class="pc-step-num">1</div>
            <div class="pc-step-body">
                <h4>Week 1-2: KQL Fundamentals</h4>
                <p>Master KQL operators: <code>where</code>, <code>summarize</code>, <code>project</code>, <code>extend</code>, <code>join</code>, <code>union</code>. Practice at <a href="https://detective.kusto.io" style="color:var(--accent)">detective.kusto.io</a>. Understand table schemas: SecurityEvent, SigninLogs, AuditLogs, DeviceEvents.</p>
            </div>
        </div>
        <div class="pc-step">
            <div class="pc-step-num">2</div>
            <div class="pc-step-body">
                <h4>Week 3-4: Data Connectors & Ingestion</h4>
                <p>Connect Microsoft 365, Azure AD, Azure Activity, Syslog (CEF), and third-party connectors. Set up Data Collection Rules. Understand workspace design (single vs. multi-workspace).</p>
            </div>
        </div>
        <div class="pc-step">
            <div class="pc-step-num">3</div>
            <div class="pc-step-body">
                <h4>Week 5-6: Analytics Rules & Incidents</h4>
                <p>Create Scheduled, NRT, and Microsoft Security analytics rules. Understand Fusion ML detections. Configure incident grouping, severity, entity mapping, and MITRE tactic tagging.</p>
            </div>
        </div>
        <div class="pc-step">
            <div class="pc-step-num">4</div>
            <div class="pc-step-body">
                <h4>Week 7-8: Automation & SOAR</h4>
                <p>Build Logic App playbooks triggered by incidents. Create automation rules for auto-assignment, auto-tagging, and auto-response. Integrate with Teams, ServiceNow, and email for notifications.</p>
            </div>
        </div>

        <h3>Essential KQL Patterns</h3>
        ${codeBlock(`// Count events by type in last 24 hours
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Count = count() by EventID
| sort by Count desc
| take 20

// Time series anomaly detection
let baseline = SecurityEvent
| where TimeGenerated between (ago(30d) .. ago(1d))
| summarize AvgCount = avg(Count) by bin(TimeGenerated, 1h);
SecurityEvent
| where TimeGenerated > ago(1d)
| summarize Count = count() by bin(TimeGenerated, 1h)
| join kind=leftouter baseline on TimeGenerated
| extend Deviation = (Count - AvgCount) / AvgCount * 100
| where Deviation > 200

// Entity enrichment with external threat intel
ThreatIntelligenceIndicator
| where ExpirationDateTime > now()
| where Active == true
| join kind=inner (
    CommonSecurityLog | where TimeGenerated > ago(1h)
) on $left.NetworkIP == $right.DestinationIP`, 'KQL Patterns')}

        <h3>Certifications</h3>
        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>SC-200</h4><p>Microsoft Security Operations Analyst — covers Sentinel, Defender, and threat management workflows.</p></div>
            <div class="pc-info-card"><h4>AZ-500</h4><p>Azure Security Engineer — broader Azure security including Sentinel deployment architecture.</p></div>
        </div>
    `,

    bestpractices: `
        <h3>Best Practices</h3>
        <div class="pc-tip">
            <h4>KQL OPTIMIZATION</h4>
            <ul>
                <li>Always filter with <code>where TimeGenerated > ago()</code> first — this is the most impactful optimization</li>
                <li>Use <code>has</code> instead of <code>contains</code> for whole-word matches (much faster)</li>
                <li>Prefer <code>in~</code> over multiple <code>or</code> conditions for case-insensitive matching</li>
                <li>Use <code>project</code> early to reduce column count passed through the pipeline</li>
                <li>Avoid <code>search *</code> across all tables — always specify the table name</li>
            </ul>
        </div>
        <div class="pc-tip">
            <h4>WORKSPACE DESIGN</h4>
            <ul>
                <li>Use a single workspace when possible for easier cross-correlation</li>
                <li>Separate workspaces only for regulatory/sovereignty requirements</li>
                <li>Use resource-context RBAC to control who sees which logs</li>
                <li>Enable UEBA to get behavioral baselines for free</li>
                <li>Deploy Content Hub solutions for your data connectors for instant analytics rules</li>
            </ul>
        </div>
        <div class="pc-warning">
            <h4>COMMON MISTAKES TO AVOID</h4>
            <ul>
                <li>Not setting up Data Collection Rules — you ingest everything and pay for noise</li>
                <li>Ignoring ingestion anomalies — a spike in data volume can blow your budget</li>
                <li>Creating analytics rules without entity mapping — incidents lack context and are hard to triage</li>
                <li>Not using incident grouping — you get hundreds of duplicate incidents</li>
                <li>Deploying playbooks without testing — a broken Logic App run costs money and misses alerts</li>
                <li>Overlooking the free Microsoft 365 Defender data connector (no ingestion charge for M365 tables)</li>
            </ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 3. IBM QRADAR
// ─────────────────────────────────────────────────────
platformContent.qradar = {
    overview: `
        <h3>What is IBM QRadar?</h3>
        <p>IBM QRadar is an enterprise SIEM that uses Ariel Query Language (AQL) for log and flow searches. QRadar correlates events and flows to generate Offenses — prioritized incidents with magnitude scoring. It features automatic asset discovery, vulnerability integration, and an extensive app ecosystem via the IBM App Exchange.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card">
                <h4>CORE COMPONENTS</h4>
                <ul>
                    <li>Console — web UI and central management</li>
                    <li>Event Processors — normalize and correlate</li>
                    <li>Flow Processors — network flow analysis</li>
                    <li>Data Nodes — distributed storage</li>
                    <li>App Host — Docker-based apps</li>
                </ul>
            </div>
            <div class="pc-info-card">
                <h4>KEY CONCEPTS</h4>
                <ul>
                    <li><code>Offenses</code> — correlated incidents</li>
                    <li><code>Magnitude</code> — severity * relevance * credibility</li>
                    <li><code>Log Sources</code> — DSM-parsed data</li>
                    <li><code>Reference Sets</code> — dynamic watchlists</li>
                    <li><code>Custom Properties</code> — extracted fields</li>
                    <li><code>Building Blocks</code> — reusable rule components</li>
                </ul>
            </div>
            <div class="pc-info-card">
                <h4>DEPLOYMENT GUIDE</h4>
                <ul>
                    <li>Deploy QRadar Console (all-in-one or distributed)</li>
                    <li>Configure log sources with auto-detection or manual DSM</li>
                    <li>Set up WinCollect for Windows event collection</li>
                    <li>Configure network flow sources (NetFlow/sFlow/IPFIX)</li>
                    <li>Tune auto-detected log source types</li>
                    <li>Enable offense rules and set notification targets</li>
                </ul>
            </div>
        </div>
    `,

    rules: `
        <h3>AQL Rule 1: Failed Logins Followed by Success</h3>
        <p>Detects brute-force attacks by correlating failed and successful authentication events. MITRE T1110.</p>
        ${codeBlock(`SELECT
    sourceip,
    username,
    COUNT(*) AS total_events,
    SUM(CASE WHEN eventid = 4625 THEN 1 ELSE 0 END) AS failed_count,
    SUM(CASE WHEN eventid = 4624 THEN 1 ELSE 0 END) AS success_count,
    MIN(starttime) AS first_event,
    MAX(starttime) AS last_event
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
    AND eventid IN (4624, 4625)
    AND starttime > NOW() - 60 * 60 * 1000
GROUP BY sourceip, username
HAVING failed_count >= 5 AND success_count >= 1
ORDER BY failed_count DESC`, 'AQL — Brute Force Detection')}

        <h3>AQL Rule 2: Suspicious Process Execution</h3>
        <p>Identifies known attacker tools and living-off-the-land binaries. MITRE T1059, T1218.</p>
        ${codeBlock(`SELECT
    sourceip AS endpoint_ip,
    username,
    "Process Name" AS process_name,
    "Command Line" AS cmdline,
    "Parent Process" AS parent_process,
    starttime
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
    AND eventid = 4688
    AND (
        "Process Name" ILIKE '%mimikatz%'
        OR "Process Name" ILIKE '%psexec%'
        OR "Process Name" ILIKE '%cobalt%'
        OR ("Process Name" ILIKE '%certutil%' AND "Command Line" ILIKE '%urlcache%')
        OR ("Process Name" ILIKE '%mshta%' AND "Command Line" ILIKE '%http%')
        OR ("Process Name" ILIKE '%rundll32%' AND "Command Line" ILIKE '%javascript%')
    )
    AND starttime > NOW() - 24 * 60 * 60 * 1000
ORDER BY starttime DESC`, 'AQL — Suspicious Process Execution')}

        <h3>AQL Rule 3: Data Exfiltration via Large Uploads</h3>
        <p>Uses flow data to detect unusually large outbound data transfers. MITRE T1048.</p>
        ${codeBlock(`SELECT
    sourceip,
    destinationip,
    SUM(sourcebytes) AS total_bytes_sent,
    SUM(sourcebytes)/1024/1024 AS mb_sent,
    COUNT(*) AS flow_count,
    destinationport,
    MIN(starttime) AS first_flow,
    MAX(starttime) AS last_flow
FROM flows
WHERE sourcebytes > 0
    AND destinationip NOT IN (
        SELECT data FROM reference_data WHERE reference_set_name = 'Internal_Networks'
    )
    AND starttime > NOW() - 60 * 60 * 1000
GROUP BY sourceip, destinationip, destinationport
HAVING total_bytes_sent > 104857600
ORDER BY total_bytes_sent DESC`, 'AQL — Data Exfiltration via Flows')}

        <h3>AQL Rule 4: Lateral Movement Detection</h3>
        <p>Identifies a single source authenticating to multiple internal hosts. MITRE T1021.</p>
        ${codeBlock(`SELECT
    sourceip,
    username,
    COUNT(DISTINCT destinationip) AS unique_targets,
    GROUP_CONCAT(DISTINCT destinationip) AS target_hosts,
    COUNT(*) AS total_logons
FROM events
WHERE category = 'Authentication'
    AND eventid = 4624
    AND "Logon Type" IN ('3', '10')
    AND sourceip IN (
        SELECT data FROM reference_data WHERE reference_set_name = 'Internal_Networks'
    )
    AND starttime > NOW() - 60 * 60 * 1000
GROUP BY sourceip, username
HAVING unique_targets >= 5
ORDER BY unique_targets DESC`, 'AQL — Lateral Movement')}

        <h3>Reference Set Management</h3>
        ${codeBlock(`# Create reference sets via API
curl -X POST "https://qradar/api/reference_data/sets" \\
  -H "SEC: <api_token>" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Malicious_IPs","element_type":"IP","timeout_type":"FIRST_SEEN","time_to_live":"30 days"}'

# Add IOC to reference set
curl -X POST "https://qradar/api/reference_data/sets/Malicious_IPs" \\
  -H "SEC: <api_token>" \\
  -d "value=192.168.1.100"

# Use in AQL
SELECT * FROM events
WHERE sourceip IN (
    SELECT data FROM reference_data WHERE reference_set_name = 'Malicious_IPs'
)`, 'AQL/API — Reference Sets')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: AQL Fundamentals</h4><p>Learn SELECT, FROM events/flows, WHERE, GROUP BY, HAVING, ORDER BY. Practice searches in the Log Activity and Network Activity tabs. Understand event vs flow data. Study QRadar's property extraction and field normalization.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Rules & Offenses</h4><p>Create custom rules using the Rule Wizard. Understand event, flow, common, and offense rules. Configure building blocks for reusable logic. Tune offense magnitude (severity, credibility, relevance). Set up rule actions and responses.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Data Integration</h4><p>Configure log sources with DSM editors. Deploy WinCollect agents. Set up custom properties (regex, calculated, custom). Build reference sets and reference maps for enrichment. Configure network hierarchy for internal/external classification.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Operations</h4><p>Install QRadar apps from IBM App Exchange (UBA, Pulse). Use the REST API for automation. Build custom dashboards. Set up QRadar SOAR (Resilient) integration. Performance tuning: EPS licensing, event coalescing, routing rules.</p></div></div>
    `,

    bestpractices: `
        <h3>Best Practices</h3>
        <div class="pc-tip"><h4>OFFENSE TUNING</h4>
            <ul>
                <li>Tune magnitude weights: relevance (is the target important?), credibility (do we trust the source?), severity (how bad is it?)</li>
                <li>Use building blocks to create reusable conditions (e.g., "Internal Servers" building block)</li>
                <li>Set offense closing reasons that analysts must select — builds metrics for detection tuning</li>
                <li>Index custom properties used in searches to improve query performance</li>
            </ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES TO AVOID</h4>
            <ul>
                <li>Not configuring the network hierarchy — QRadar cannot distinguish internal from external traffic</li>
                <li>Leaving auto-detected log sources uncategorized — "Stored" events are not correlated</li>
                <li>Exceeding EPS license — events get dropped silently</li>
                <li>Not indexing custom properties before using them in searches — queries run orders of magnitude slower</li>
                <li>Creating rules without testing gates — a noisy rule generates thousands of offenses</li>
            </ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 4. ELASTIC SIEM
// ─────────────────────────────────────────────────────
platformContent.elastic = {
    overview: `
        <h3>What is Elastic SIEM?</h3>
        <p>Elastic Security (formerly Elastic SIEM) is built on the Elastic Stack (Elasticsearch, Kibana, Beats, Logstash). It supports both KQL (Kibana Query Language) and EQL (Event Query Language) for detections and threat hunting. Rules are defined in TOML format and can be managed as code.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE STACK</h4>
                <ul><li>Elasticsearch — search and analytics engine</li><li>Kibana — visualization and Security app</li><li>Elastic Agent / Fleet — unified data collection</li><li>Logstash — data transformation pipeline</li><li>Beats — lightweight data shippers</li></ul>
            </div>
            <div class="pc-info-card"><h4>DETECTION CAPABILITIES</h4>
                <ul><li>EQL — Event Query Language for sequences</li><li>KQL — Kibana Query Language</li><li>TOML rules — detection-as-code</li><li>Machine Learning anomaly detection</li><li>Threshold rules and indicator match</li><li>Prebuilt rules from Elastic Security Labs</li></ul>
            </div>
            <div class="pc-info-card"><h4>FLEET AGENT CONFIG</h4>
                <ul><li>Deploy Fleet Server on central host</li><li>Create Agent Policies with integrations</li><li>Enroll agents: <code>elastic-agent enroll --url=https://fleet:8220 --enrollment-token=xxx</code></li><li>Integrations: Endpoint Security, Windows, Sysmon, Auditd</li><li>Monitor agent health in Fleet UI</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>EQL Rule 1: Process Injection via CreateRemoteThread</h3>
        <p>Detects process injection using the sequence of allocating remote memory and creating a remote thread. MITRE T1055.</p>
        ${codeBlock(`sequence by host.id with maxspan=1m
  [process where event.type == "start" and
    process.name : ("rundll32.exe", "regsvr32.exe", "svchost.exe", "notepad.exe")]
  [api where event.action == "VirtualAllocEx" and
    process.Ext.api.parameters.protection : "*EXECUTE*"]
  [api where event.action == "WriteProcessMemory"]
  [api where event.action == "CreateRemoteThread"]`, 'EQL — Process Injection Sequence')}

        <h3>EQL Rule 2: Credential Access via Registry</h3>
        <p>Detects access to SAM/SECURITY/SYSTEM registry hives for credential extraction. MITRE T1003.002.</p>
        ${codeBlock(`registry where event.type == "access" and
  registry.path : (
    "HKLM\\\\SAM\\\\*",
    "HKLM\\\\SECURITY\\\\*",
    "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\LSA\\\\*"
  ) and
  not process.executable : (
    "C:\\\\Windows\\\\System32\\\\lsass.exe",
    "C:\\\\Windows\\\\System32\\\\svchost.exe",
    "C:\\\\Windows\\\\regedit.exe"
  )`, 'EQL — Registry Credential Access')}

        <h3>KQL Rule 3: Suspicious Outbound Connection</h3>
        <p>Identifies processes making connections to rare external IPs on uncommon ports. MITRE T1071.</p>
        ${codeBlock(`event.category: "network" and event.type: "connection" and
network.direction: "outbound" and
not destination.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16) and
not destination.port: (80 or 443 or 53 or 8080) and
process.name: (
  "powershell.exe" or "cmd.exe" or "mshta.exe" or
  "wscript.exe" or "cscript.exe" or "rundll32.exe"
)`, 'KQL — Suspicious Outbound Network')}

        <h3>TOML Rule 4: Persistence via Scheduled Task</h3>
        <p>Detection rule in Elastic's TOML format for scheduled task creation. MITRE T1053.005.</p>
        ${codeBlock(`[metadata]
creation_date = "2024/01/15"
maturity = "production"
updated_date = "2024/06/01"

[rule]
author = ["BlueShell"]
description = "Detects creation of scheduled tasks commonly used for persistence"
name = "Suspicious Scheduled Task Created"
risk_score = 60
severity = "medium"
type = "eql"
tags = ["Domain: Endpoint", "OS: Windows", "Use Case: Threat Detection",
        "Tactic: Persistence", "Data Source: Elastic Defend"]

[rule.threat]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1053"
name = "Scheduled Task/Job"
reference = "https://attack.mitre.org/techniques/T1053/"
[[rule.threat.technique.subtechnique]]
id = "T1053.005"
name = "Scheduled Task"

[rule.query]
query = """
process where event.type == "start" and
  process.name : "schtasks.exe" and
  process.args : ("/create", "-create") and
  process.args : ("/sc", "-sc") and
  not process.parent.executable : (
    "C:\\\\Windows\\\\System32\\\\svchost.exe",
    "C:\\\\Program Files*\\\\*.exe"
  )
"""`, 'TOML — Elastic Detection Rule')}

        <h3>EQL Rule 5: Living-off-the-Land Binary Execution Chain</h3>
        <p>Detects a chain of LOLBin executions which may indicate an attack. MITRE T1218.</p>
        ${codeBlock(`sequence by host.id with maxspan=5m
  [process where event.type == "start" and
    process.name : ("mshta.exe", "wscript.exe", "cscript.exe") and
    process.args : ("http*", "\\\\\\\\*")]
  [process where event.type == "start" and
    process.parent.name : ("mshta.exe", "wscript.exe", "cscript.exe") and
    process.name : ("powershell.exe", "cmd.exe")]
  [process where event.type == "start" and
    process.name : ("certutil.exe", "bitsadmin.exe", "curl.exe") and
    process.args : ("http*", "urlcache", "transfer")]`, 'EQL — LOLBin Execution Chain')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Elastic Stack Fundamentals</h4><p>Deploy Elasticsearch + Kibana. Learn index management, mappings, and ILM (Index Lifecycle Management). Understand ECS (Elastic Common Schema) field naming. Install Elastic Security app in Kibana.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Data Collection with Fleet</h4><p>Set up Fleet Server. Create Agent Policies. Deploy Elastic Agent to Windows and Linux endpoints. Add integrations: Endpoint Security, Windows Event Log, Sysmon, Zeek. Monitor enrollment and data ingestion.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: EQL and Detection Rules</h4><p>Master EQL sequence queries for multi-stage attack detection. Write TOML detection rules. Import prebuilt rules from Elastic Security Labs. Configure rule exceptions and actions (email, webhook, Slack).</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Hunting & ML</h4><p>Use Timeline for investigation. Enable ML anomaly detection jobs. Build custom dashboards and Lens visualizations. Implement detection-as-code with GitHub CI/CD for TOML rules.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>PERFORMANCE & ARCHITECTURE</h4>
            <ul>
                <li>Use hot-warm-cold architecture with ILM policies to manage storage costs</li>
                <li>Set appropriate shard sizes (30-50 GB per shard) — too many small shards degrade performance</li>
                <li>Use data streams and ECS-compliant field mappings for all security data</li>
                <li>Enable cross-cluster search for multi-site deployments instead of shipping all data to one cluster</li>
            </ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES TO AVOID</h4>
            <ul>
                <li>Not using ECS field names — prebuilt rules will not match your custom data</li>
                <li>Running too many ML jobs simultaneously — each job consumes significant memory</li>
                <li>Not setting up ILM policies — indices grow until disk is full</li>
                <li>Using wildcard index patterns in production rules — they scan all indices</li>
                <li>Ignoring Fleet agent health — unresponsive agents create detection blind spots</li>
            </ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 5. GOOGLE CHRONICLE
// ─────────────────────────────────────────────────────
platformContent.chronicle = {
    overview: `
        <h3>What is Google Chronicle?</h3>
        <p>Google Chronicle (now part of Google Security Operations) is a cloud-native SIEM built on Google infrastructure. It uses YARA-L 2.0 as its detection language and the Unified Data Model (UDM) to normalize all ingested data into a standard schema. Chronicle offers petabyte-scale storage with fixed-cost pricing.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE COMPONENTS</h4>
                <ul><li>UDM (Unified Data Model) — normalized schema</li><li>YARA-L 2.0 — detection rule language</li><li>Entity Analytics — risk scoring</li><li>Parsers — log normalization</li><li>Reference Lists — IOC watchlists</li><li>Chronicle SOAR — automation</li></ul>
            </div>
            <div class="pc-info-card"><h4>UDM DATA MODEL</h4>
                <ul><li><code>principal</code> — source/actor entity</li><li><code>target</code> — destination entity</li><li><code>src</code> — network source</li><li><code>observer</code> — reporting device</li><li><code>metadata.event_type</code> — categorization</li><li><code>security_result</code> — verdict/action</li></ul>
            </div>
            <div class="pc-info-card"><h4>PARSER SETUP</h4>
                <ul><li>Parsers normalize raw logs to UDM</li><li>Use CBN (Config Based Normalization) format</li><li>Test parsers with sample log lines</li><li>Validate UDM output with schema checker</li><li>Default parsers for 800+ log source types</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>YARA-L Rule 1: Brute Force Login Detection</h3>
        <p>Detects multiple failed logins to a single user within a short window. MITRE T1110.</p>
        ${codeBlock(`rule brute_force_login {
  meta:
    author = "BlueShell"
    description = "Detects brute force login attempts"
    severity = "HIGH"
    mitre_attack = "T1110"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.target.user.userid = $user
    $fail.principal.ip = $src_ip

  match:
    $user, $src_ip over 15m

  condition:
    #fail >= 10

  outcome:
    $risk_score = max(75)
    $failed_count = count_distinct($fail.metadata.id)
}`, 'YARA-L 2.0 — Brute Force')}

        <h3>YARA-L Rule 2: DNS Tunneling Detection</h3>
        <p>Identifies potential DNS exfiltration by detecting high-entropy, long subdomain queries. MITRE T1048.003.</p>
        ${codeBlock(`rule dns_tunneling_detection {
  meta:
    author = "BlueShell"
    description = "Detects potential DNS tunneling via long subdomain queries"
    severity = "HIGH"
    mitre_attack = "T1048.003"

  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name = $query
    $dns.principal.ip = $src_ip
    strings.length($query) > 50

  match:
    $src_ip over 30m

  condition:
    #dns >= 50

  outcome:
    $risk_score = max(80)
    $unique_queries = count_distinct($query)
    $sample_queries = array_distinct($query)
}`, 'YARA-L 2.0 — DNS Tunneling')}

        <h3>YARA-L Rule 3: Malware Beacon Detection</h3>
        <p>Detects periodic network connections that match C2 beacon behavior. MITRE T1071.</p>
        ${codeBlock(`rule c2_beacon_detection {
  meta:
    author = "BlueShell"
    description = "Detects periodic outbound connections indicating C2 beaconing"
    severity = "CRITICAL"
    mitre_attack = "T1071"

  events:
    $conn.metadata.event_type = "NETWORK_CONNECTION"
    $conn.principal.ip = $src_ip
    $conn.target.ip = $dst_ip
    $conn.target.port = $dst_port
    not $conn.target.ip = "10.0.0.0/8"
    not $conn.target.ip = "172.16.0.0/12"
    not $conn.target.ip = "192.168.0.0/16"

  match:
    $src_ip, $dst_ip, $dst_port over 1h

  condition:
    #conn >= 20

  outcome:
    $risk_score = max(85)
    $connection_count = count($conn.metadata.id)
}`, 'YARA-L 2.0 — C2 Beacon')}

        <h3>YARA-L Rule 4: Suspicious Process Execution</h3>
        ${codeBlock(`rule suspicious_process_execution {
  meta:
    author = "BlueShell"
    description = "Detects suspicious LOLBin usage"
    severity = "MEDIUM"
    mitre_attack = "T1218"

  events:
    $exec.metadata.event_type = "PROCESS_LAUNCH"
    $exec.principal.process.file.full_path = /.*\\\\(mshta|certutil|regsvr32|msiexec)\\.exe/
    $exec.principal.process.command_line = /.*http.*/
    $exec.principal.hostname = $hostname

  match:
    $hostname over 5m

  condition:
    $exec

  outcome:
    $risk_score = max(70)
}`, 'YARA-L 2.0 — LOLBin Detection')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: UDM & Search</h4><p>Learn the Unified Data Model schema. Practice UDM search queries in the Chronicle UI. Understand event types (USER_LOGIN, NETWORK_CONNECTION, PROCESS_LAUNCH, etc). Browse entities and asset timelines.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: YARA-L 2.0 Fundamentals</h4><p>Study rule structure: meta, events, match, condition, outcome. Write single-event and multi-event rules. Use match variables and time windows. Understand outcome scoring for risk prioritization.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Parser Development</h4><p>Build custom parsers for unsupported log sources. Use CBN parser format with Grok patterns. Test against sample logs. Deploy and validate UDM output.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Entity Analytics & SOAR</h4><p>Configure entity risk scoring. Build reference lists for IOC tracking. Set up Chronicle SOAR playbooks. Integrate with VirusTotal and Google Threat Intelligence.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul>
                <li>Always use UDM field paths in rules, not raw log fields — ensures parser-agnostic detection</li>
                <li>Use reference lists for IOCs instead of hardcoding values in rules</li>
                <li>Set appropriate time windows in match clauses — too wide generates false positives, too narrow misses slow attacks</li>
                <li>Use outcome blocks with risk_score to prioritize detections</li>
                <li>Test rules against historical data using retrohunts before enabling live</li>
            </ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul>
                <li>Writing rules against raw log fields instead of UDM — breaks when parser changes</li>
                <li>Not validating parser output — garbage in, garbage out</li>
                <li>Overly broad match windows generating excessive detections</li>
                <li>Not using the entity graph for investigation context</li>
            </ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 6. ARCSIGHT ESM
// ─────────────────────────────────────────────────────
platformContent.arcsight = {
    overview: `
        <h3>What is ArcSight ESM?</h3>
        <p>Micro Focus ArcSight ESM is a legacy enterprise SIEM that uses Common Event Format (CEF) for log normalization and XML-based correlation rules. It features Active Channels for real-time monitoring, Active Lists for state tracking, and FlexConnectors for custom log source integration.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE COMPONENTS</h4>
                <ul><li>ESM Manager — correlation engine</li><li>Logger — long-term storage</li><li>Connectors — SmartConnectors & FlexConnectors</li><li>ArcSight Console — thick client UI</li><li>ArcMC — management center</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY CONCEPTS</h4>
                <ul><li><code>CEF</code> — Common Event Format</li><li><code>Active Channels</code> — real-time views</li><li><code>Active Lists</code> — stateful key-value stores</li><li><code>Session Lists</code> — time-bounded correlations</li><li><code>Resources</code> — filters, rules, reports</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>CEF Format Reference</h3>
        ${codeBlock(`CEF:0|Security|Firewall|1.0|100|Connection Blocked|7|
  src=192.168.1.100 dst=10.0.0.50 spt=49823 dpt=443
  act=Blocked proto=TCP deviceExternalId=FW01
  msg=Outbound connection blocked by policy
  cat=Firewall cs1Label=Policy cs1=BlockMalicious`, 'CEF — Common Event Format')}

        <h3>Correlation Rule 1: Brute Force Detection (XML)</h3>
        ${codeBlock(`<Rule>
  <Name>Brute Force Authentication Attempt</Name>
  <Description>Detects 10+ failed logins from same source in 5 minutes</Description>
  <Type>Correlation</Type>
  <MatchCriteria>
    <Filter>
      <Condition field="categoryBehavior" operator="equals">Authentication</Condition>
      <Condition field="categoryOutcome" operator="equals">Failure</Condition>
    </Filter>
  </MatchCriteria>
  <Aggregation>
    <GroupBy>sourceAddress</GroupBy>
    <GroupBy>destinationUserName</GroupBy>
    <Threshold operator="greaterThan">10</Threshold>
    <TimeWindow units="minutes">5</TimeWindow>
  </Aggregation>
  <Actions>
    <Action type="generateCorrelatedEvent">
      <Severity>8</Severity>
      <Name>Brute Force Detected: $sourceAddress -> $destinationUserName</Name>
    </Action>
    <Action type="addToActiveList">
      <ListName>Suspicious_Sources</ListName>
      <KeyField>sourceAddress</KeyField>
    </Action>
  </Actions>
</Rule>`, 'XML — ArcSight Correlation Rule')}

        <h3>Correlation Rule 2: Lateral Movement</h3>
        ${codeBlock(`<Rule>
  <Name>Lateral Movement - Multiple Host Authentication</Name>
  <Type>Correlation</Type>
  <MatchCriteria>
    <Filter>
      <Condition field="categoryBehavior" operator="equals">Authentication</Condition>
      <Condition field="categoryOutcome" operator="equals">Success</Condition>
      <Condition field="deviceEventClassId" operator="equals">4624</Condition>
    </Filter>
  </MatchCriteria>
  <Aggregation>
    <GroupBy>sourceAddress</GroupBy>
    <CountDistinct field="destinationAddress" operator="greaterThan">5</CountDistinct>
    <TimeWindow units="minutes">30</TimeWindow>
  </Aggregation>
  <Actions>
    <Action type="generateCorrelatedEvent">
      <Severity>9</Severity>
    </Action>
  </Actions>
</Rule>`, 'XML — Lateral Movement Rule')}

        <h3>Correlation Rule 3: Malware Callback Detection</h3>
        ${codeBlock(`<Rule>
  <Name>Potential Malware Callback - Repeated Beaconing</Name>
  <Type>Correlation</Type>
  <MatchCriteria>
    <Filter>
      <Condition field="categoryObject" operator="equals">/Traffic</Condition>
      <Condition field="destinationAddress" operator="notInActiveList">Known_Good_Destinations</Condition>
    </Filter>
  </MatchCriteria>
  <Aggregation>
    <GroupBy>sourceAddress</GroupBy>
    <GroupBy>destinationAddress</GroupBy>
    <Threshold operator="greaterThan">30</Threshold>
    <TimeWindow units="minutes">60</TimeWindow>
  </Aggregation>
  <Actions>
    <Action type="generateCorrelatedEvent"><Severity>8</Severity></Action>
  </Actions>
</Rule>`, 'XML — Beacon Detection')}

        <h3>FlexConnector Configuration</h3>
        ${codeBlock(`# flexagent.properties - Custom log source connector
source.type=file
source.file.path=/var/log/custom_app.log
source.file.encoding=UTF-8

# Parser definition
parser.type=regex
parser.regex=^(?P<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) \\[(?P<severity>\\w+)\\] (?P<user>\\w+)@(?P<src_ip>[\\d.]+) - (?P<message>.+)$

# Field mappings to CEF
mapping.timestamp=deviceReceiptTime
mapping.severity=deviceSeverity
mapping.user=sourceUserName
mapping.src_ip=sourceAddress
mapping.message=message`, 'Properties — FlexConnector Config')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: CEF & Console Basics</h4><p>Understand CEF format fields. Navigate the ArcSight Console. Use Active Channels for real-time monitoring. Create basic filters and active channels.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Correlation Rules</h4><p>Build rules using the Rule Editor. Understand aggregation, join, and partition rules. Use Active Lists for state tracking. Configure rule actions (notify, execute command, add to list).</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Connectors & Integration</h4><p>Deploy SmartConnectors for standard sources. Build FlexConnectors for custom applications. Configure connector failover. Manage connectors with ArcMC.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Operations</h4><p>Build dashboards and reports. Optimize rule performance. Set up ESM clustering for HA. Integrate with SOAR platforms.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use Active Lists to maintain state between rule evaluations (e.g., tracking known assets)</li><li>Build a library of reusable filters as building blocks for complex rules</li><li>Test rules in simulation mode before activating in production</li><li>Use partition rules to distribute correlation load across ESM resources</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not tuning connector normalization — unmapped CEF fields reduce correlation accuracy</li><li>Creating overly complex join rules that consume excessive memory</li><li>Not archiving old events in Logger — ESM storage is limited</li><li>Ignoring connector health monitoring — silent data loss</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 7. FORTISIEM
// ─────────────────────────────────────────────────────
platformContent.fortisiem = {
    overview: `
        <h3>What is FortiSIEM?</h3>
        <p>FortiSIEM is Fortinet's SIEM/UEBA platform that combines log management, compliance, CMDB auto-discovery, and analytics. It integrates natively with the Fortinet Security Fabric (FortiGate, FortiAnalyzer, FortiEDR) and uses its own query language for event searches and rule definitions.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE COMPONENTS</h4>
                <ul><li>Supervisor — central management node</li><li>Workers — distributed processing</li><li>Collectors — remote log collection</li><li>CMDB — auto-discovered asset database</li><li>FortiGuard — threat intelligence feeds</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY FEATURES</h4>
                <ul><li>Multi-tenant architecture</li><li>Agentless discovery and monitoring</li><li>Built-in compliance reporting</li><li>FortiGuard IOC threat feeds</li><li>UEBA behavioral analytics</li><li>Business service dashboards</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>FortiSIEM Query 1: Failed Authentication Spike</h3>
        ${codeBlock(`eventType = "Win-Security-4625" AND
reportingIP IN (GROUP "All Internal Hosts") |
GROUP BY srcIpAddr, user |
HAVING COUNT(*) > 10 |
LAST 15 MINUTES`, 'FortiSIEM Query — Failed Auth')}

        <h3>FortiSIEM Query 2: FortiGate Threat Detection</h3>
        ${codeBlock(`eventType IN ("FortiGate-ips-signature", "FortiGate-virus-infected") AND
phCustId = 1 |
GROUP BY srcIpAddr, destIpAddr, attackName |
HAVING COUNT(*) >= 1 |
LAST 1 HOUR`, 'FortiSIEM Query — FortiGate Threats')}

        <h3>FortiSIEM Query 3: Suspicious DNS Queries</h3>
        ${codeBlock(`eventType = "Win-DNS-Query" AND
domainName REGEXP "^[a-z0-9]{20,}\\\\." |
GROUP BY srcIpAddr, domainName |
HAVING COUNT(*) > 5 |
LAST 30 MINUTES`, 'FortiSIEM Query — DNS Anomaly')}

        <h3>FortiSIEM Rule Definition (XML)</h3>
        ${codeBlock(`<Rule>
  <Name>Brute Force Followed by Successful Login</Name>
  <RuleType>Correlation</RuleType>
  <SubPattern>
    <Name>Failed Logins</Name>
    <Filter>eventType = "Win-Security-4625"</Filter>
    <GroupBy>srcIpAddr, user</GroupBy>
    <Aggregate>COUNT(*) >= 10</Aggregate>
    <Window>5m</Window>
  </SubPattern>
  <SubPattern>
    <Name>Successful Login</Name>
    <Filter>eventType = "Win-Security-4624"</Filter>
    <GroupBy>srcIpAddr, user</GroupBy>
    <Window>10m</Window>
  </SubPattern>
  <JoinCondition>SubPattern1.srcIpAddr = SubPattern2.srcIpAddr AND SubPattern1.user = SubPattern2.user</JoinCondition>
  <Severity>9</Severity>
  <Action>Notification</Action>
</Rule>`, 'XML — FortiSIEM Correlation Rule')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: FortiSIEM Basics</h4><p>Understand the Supervisor/Worker/Collector architecture. Navigate the web GUI. Run basic event searches. Understand the CMDB auto-discovery mechanism.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Event Collection & Parsing</h4><p>Configure log sources (syslog, WMI, SNMP, API). Map event types to FortiSIEM parsers. Set up FortiGate integration via Security Fabric. Configure Windows agent-based collection.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Rules & Correlation</h4><p>Build single-subpattern rules and multi-subpattern correlation rules. Configure notification policies. Set up FortiGuard IOC matching. Create custom dashboards and reports.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Features</h4><p>Enable UEBA behavioral analytics. Configure multi-tenant organizations. Set up compliance report templates. Integrate with FortiSOAR for automated response.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Leverage the CMDB for automatic asset-to-event correlation</li><li>Use FortiGuard IOC feeds for free threat intelligence enrichment</li><li>Set up business service groups to correlate alerts to business impact</li><li>Use multi-subpattern rules for sequential attack detection</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not tuning the CMDB discovery — generates excessive SNMP/WMI traffic</li><li>Ignoring event parsing errors — unparsed events cannot be correlated</li><li>Not sizing Workers correctly — under-provisioning causes event drops</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 8. WAZUH
// ─────────────────────────────────────────────────────
platformContent.wazuh = {
    overview: `
        <h3>What is Wazuh?</h3>
        <p>Wazuh is a free, open-source security platform that provides threat detection, integrity monitoring, incident response, and compliance. It uses XML-based rules and decoders to analyze logs, with an agent deployed on endpoints. Wazuh integrates with the Elastic Stack or its own indexer for visualization.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE COMPONENTS</h4>
                <ul><li>Wazuh Manager — analysis engine</li><li>Wazuh Agent — endpoint data collection</li><li>Wazuh Indexer — OpenSearch-based storage</li><li>Wazuh Dashboard — Kibana-fork UI</li><li>Filebeat — log shipping</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY CAPABILITIES</h4>
                <ul><li>File Integrity Monitoring (FIM)</li><li>Rootcheck — rootkit detection</li><li>SCA — Security Configuration Assessment</li><li>Vulnerability Detection</li><li>Active Response — automated blocking</li><li>Log collection & analysis</li></ul>
            </div>
            <div class="pc-info-card"><h4>OSSEC.CONF BASICS</h4>
                <ul><li><code>&lt;ossec_config&gt;</code> — main config block</li><li><code>&lt;syscheck&gt;</code> — FIM configuration</li><li><code>&lt;localfile&gt;</code> — log sources to monitor</li><li><code>&lt;active-response&gt;</code> — response actions</li><li><code>&lt;labels&gt;</code> — agent metadata tags</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Wazuh Rule 1: Brute Force SSH Detection</h3>
        ${codeBlock(`<group name="local,sshd,authentication_failures,">
  <rule id="100010" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5710</if_matched_sid>
    <description>SSH brute force attack detected (8+ failures in 2 min)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_11.4,</group>
  </rule>
</group>`, 'XML — Wazuh SSH Brute Force Rule')}

        <h3>Wazuh Rule 2: Suspicious PowerShell Execution</h3>
        ${codeBlock(`<group name="local,windows,powershell,">
  <rule id="100020" level="12">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.scriptBlockText">
      DownloadString|DownloadFile|EncodedCommand|FromBase64String|Invoke-Expression|IEX
    </field>
    <description>Suspicious PowerShell command detected: $(win.eventdata.scriptBlockText)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>attack,execution,</group>
  </rule>
</group>`, 'XML — PowerShell Detection')}

        <h3>Wazuh Rule 3: File Integrity Change on Critical Path</h3>
        ${codeBlock(`<group name="local,syscheck,">
  <rule id="100030" level="10">
    <if_sid>550</if_sid>
    <field name="syscheck.path">
      /etc/passwd|/etc/shadow|/etc/sudoers|/etc/ssh/sshd_config
    </field>
    <description>Critical file modified: $(syscheck.path) by $(syscheck.uname_after)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>syscheck,file_integrity,</group>
  </rule>
</group>`, 'XML — FIM Critical File Change')}

        <h3>Wazuh Rule 4: Web Shell Detection</h3>
        ${codeBlock(`<group name="local,web,">
  <rule id="100040" level="14">
    <if_sid>31100</if_sid>
    <url>cmd=|exec=|shell=|upload=|eval(|system(|passthru(</url>
    <description>Possible web shell activity detected in URL: $(url)</description>
    <mitre>
      <id>T1505.003</id>
    </mitre>
    <group>attack,web_attack,</group>
  </rule>
</group>`, 'XML — Web Shell Detection')}

        <h3>Custom Decoder Example</h3>
        ${codeBlock(`<decoder name="custom_app">
  <program_name>myapp</program_name>
</decoder>

<decoder name="custom_app_login">
  <parent>custom_app</parent>
  <regex>User (\\S+) login from (\\S+) status=(\\S+)</regex>
  <order>user, srcip, status</order>
</decoder>`, 'XML — Custom Decoder')}

        <h3>Active Response Script</h3>
        ${codeBlock(`#!/bin/bash
# /var/ossec/active-response/bin/block-ip.sh
# Wazuh active response script to block IP with iptables

ACTION=$1
USER=$2
IP=$3

if [ "$ACTION" = "add" ]; then
    iptables -I INPUT -s "$IP" -j DROP
    echo "$(date) Blocked IP: $IP" >> /var/ossec/logs/active-responses.log
elif [ "$ACTION" = "delete" ]; then
    iptables -D INPUT -s "$IP" -j DROP
    echo "$(date) Unblocked IP: $IP" >> /var/ossec/logs/active-responses.log
fi`, 'Bash — Active Response Script')}

        <h3>FIM Configuration (ossec.conf)</h3>
        ${codeBlock(`<syscheck>
  <frequency>600</frequency>
  <scan_on_start>yes</scan_on_start>

  <!-- Critical directories -->
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /etc,/usr/bin,/usr/sbin
  </directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">
    /var/www/html
  </directories>

  <!-- Windows critical paths -->
  <directories check_all="yes" realtime="yes">
    C:\\Windows\\System32\\drivers\\etc
  </directories>

  <!-- Ignore noisy paths -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/resolv.conf</ignore>
  <ignore type="sregex">\\.log$|\\.tmp$</ignore>
</syscheck>`, 'XML — FIM Configuration')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Installation & Agent Deployment</h4><p>Deploy Wazuh Manager, Indexer, Dashboard (all-in-one or distributed). Install agents on Windows and Linux. Verify agent enrollment and data flow. Understand <code>ossec.conf</code> structure.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Rules & Decoders</h4><p>Understand the decoder-rule pipeline. Write custom decoders for application logs. Create custom XML rules with MITRE mapping. Learn rule chaining with <code>if_sid</code> and <code>if_matched_sid</code>.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: FIM & Active Response</h4><p>Configure File Integrity Monitoring for critical directories. Set up real-time FIM vs scheduled scans. Write active response scripts for automated blocking. Configure <code>command</code> and <code>active-response</code> blocks.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Integration & Advanced</h4><p>Integrate with Shuffle SOAR for automation. Connect VirusTotal API for hash checks. Enable vulnerability detection module. Set up SCA policies for CIS benchmarks. Configure Slack/email alerts.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Always assign MITRE ATT&CK IDs to custom rules for coverage tracking</li><li>Use <code>realtime="yes"</code> for FIM on critical directories but <code>frequency</code> scans on large directories</li><li>Chain rules using <code>if_sid</code> to build composite detections from simple events</li><li>Use <code>overwrite="yes"</code> to tune noisy default rules instead of deleting them</li><li>Deploy agents with labels for environment/tier tagging</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Setting FIM <code>realtime="yes"</code> on too many directories — causes high CPU on endpoints</li><li>Not testing active response scripts — a buggy script can block legitimate traffic</li><li>Writing rules without decoders — fields won't be extracted for matching</li><li>Not sizing the Wazuh Indexer correctly — OpenSearch needs significant RAM</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 9. EXABEAM FUSION
// ─────────────────────────────────────────────────────
platformContent.exabeam = {
    overview: `
        <h3>What is Exabeam Fusion?</h3>
        <p>Exabeam Fusion combines SIEM and UEBA (User and Entity Behavior Analytics) into a single cloud platform. Its core differentiator is Smart Timelines that automatically stitch user and device activities into a chronological narrative. Exabeam uses behavioral baselines and anomaly scoring to detect insider threats and compromised accounts.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>Smart Timelines — auto-assembled activity narratives</li><li>UEBA — behavioral baselines per user/entity</li><li>Anomaly scoring — risk points for deviations</li><li>Threat Hunter — query interface</li><li>Case Manager — investigation workflow</li><li>Automation playbooks</li></ul>
            </div>
            <div class="pc-info-card"><h4>BEHAVIORAL MODELS</h4>
                <ul><li>First-time access to host/app</li><li>Abnormal login time</li><li>Unusual process execution</li><li>Peer group deviation</li><li>Impossible travel</li><li>Dormant account reactivation</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Correlation Rule 1: Multiple Failed Logins (YAML)</h3>
        ${codeBlock(`name: brute_force_authentication
description: Detects brute force login attempts
mitre_attack:
  tactics: [credential-access]
  techniques: [T1110]
severity: high
event_filter:
  event_type: authentication
  outcome: failure
correlation:
  group_by: [src_ip, user]
  time_window: 5m
  threshold:
    count: 10
    operator: ">="
actions:
  - create_notable_event:
      name: "Brute Force Detected: {{user}} from {{src_ip}}"
      severity: high
      assignee: soc-tier1
  - add_context:
      risk_score: 80`, 'YAML — Exabeam Correlation Rule')}

        <h3>Correlation Rule 2: Insider Threat - Abnormal Data Access</h3>
        ${codeBlock(`name: insider_abnormal_data_access
description: Detects user accessing abnormal volume of files
mitre_attack:
  tactics: [collection]
  techniques: [T1005]
severity: high
event_filter:
  event_type: file_access
  action: read
correlation:
  group_by: [user]
  time_window: 1h
  threshold:
    count: 100
    operator: ">="
  baseline_comparison:
    field: count
    deviation: 3x  # 3x above user's normal baseline
actions:
  - create_notable_event:
      name: "Abnormal File Access: {{user}} accessed {{count}} files"
      severity: high`, 'YAML — Insider Threat Rule')}

        <h3>Correlation Rule 3: Privilege Escalation</h3>
        ${codeBlock(`name: privilege_escalation_sequence
description: Detects privilege escalation followed by sensitive actions
mitre_attack:
  tactics: [privilege-escalation, persistence]
  techniques: [T1078, T1098]
severity: critical
sequence:
  - event:
      event_type: authentication
      outcome: success
      user_privilege: standard
  - event:
      event_type: admin_action
      action_type: [role_change, group_add, permission_modify]
      time_after_previous: 30m
  - event:
      event_type: [file_access, data_export]
      time_after_previous: 60m
correlation:
  group_by: [user]
  time_window: 2h
actions:
  - create_notable_event:
      severity: critical
      name: "Privilege Escalation Sequence: {{user}}"`, 'YAML — Privilege Escalation Sequence')}

        <h3>Smart Timeline Query Examples</h3>
        ${codeBlock(`# Find all activities for a specific user in last 24h
user = "john.doe@company.com" AND timestamp >= "24h ago"

# Find anomalous logon activities
event_type = "authentication" AND anomaly_score > 70

# Find data exfiltration indicators
event_type = "file_access" AND action = "download"
AND file_size > 10MB AND user_risk_score > 50

# Find lateral movement patterns
event_type = "authentication" AND is_first_access = true
AND dest_host != user_normal_hosts`, 'Exabeam Threat Hunter Queries')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: UEBA Concepts</h4><p>Understand behavioral baselines, peer groups, and anomaly scoring. Learn how Smart Timelines are constructed. Study the built-in behavioral models. Navigate the Exabeam UI — Threat Hunter, Case Manager, Dashboards.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Data Integration</h4><p>Connect log sources via syslog, API, cloud connectors. Map data to Exabeam's schema. Verify user/entity resolution (user IDs map to correct identities). Configure context tables for enrichment.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Custom Rules & Models</h4><p>Write YAML correlation rules. Create custom behavioral models. Tune anomaly scoring thresholds. Build investigation playbooks in Case Manager.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Analytics</h4><p>Build custom risk scoring models. Configure peer group analytics. Create executive dashboards. Integrate with SOAR for automated response. Use the API for custom reporting.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Let behavioral models build baselines for 2-4 weeks before enabling alerting on anomalies</li><li>Verify user-to-identity mapping is correct — merged identities reduce false positives</li><li>Combine rule-based detection with UEBA anomaly scoring for layered detection</li><li>Use Smart Timelines during investigations to see the full attack narrative</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Alerting on UEBA anomalies before baselines stabilize — floods SOC with false positives</li><li>Not configuring peer groups — anomaly detection without peer comparison is less effective</li><li>Ignoring identity resolution errors — "john.doe" and "jdoe" should map to the same person</li><li>Not tuning risk score thresholds for your organization's risk appetite</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 10. LOGRHYTHM
// ─────────────────────────────────────────────────────
platformContent.logrhythm = {
    overview: `
        <h3>What is LogRhythm?</h3>
        <p>LogRhythm is an enterprise SIEM platform featuring the AI Engine for advanced correlation and anomaly detection. It offers five rule types (Statistical, Behavioral, Threshold, Unique, Trend) and integrates SmartResponse for automated remediation actions.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>AI ENGINE RULE TYPES</h4>
                <ul><li><strong>Statistical</strong> — standard deviation anomalies</li><li><strong>Behavioral</strong> — pattern change detection</li><li><strong>Threshold</strong> — count-based triggers</li><li><strong>Unique</strong> — first-seen detection</li><li><strong>Trend</strong> — increasing/decreasing patterns</li></ul>
            </div>
            <div class="pc-info-card"><h4>ARCHITECTURE</h4>
                <ul><li>Platform Manager (PM) — central config</li><li>Data Processor (DP) — log processing</li><li>AI Engine (AIE) — correlation</li><li>Data Indexer (DX) — search and storage</li><li>System Monitor Agent — endpoint collection</li><li>Web Console — analyst interface</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>AI Engine Rule 1: Threshold — Brute Force</h3>
        ${codeBlock(`Rule Type: Threshold
Name: Brute Force Login Detection
Description: 10+ failed logins in 5 minutes
Log Source Type: Windows Event Log
Common Event: Authentication Failure (4625)
Group By: Origin Host (Impacted)
Threshold: Count >= 10
Window: 5 minutes
Action: Create Alarm (High Priority)
SmartResponse: Send email, Create case
MITRE: T1110 - Brute Force`, 'LogRhythm AI Engine — Threshold Rule')}

        <h3>AI Engine Rule 2: Unique — First-Time Service Account Logon</h3>
        ${codeBlock(`Rule Type: Unique Value
Name: Service Account Logon from New Host
Description: Service account authenticated from a previously unseen source
Log Source Type: Windows Event Log
Common Event: Authentication Success (4624)
Filter: Account matches "svc-*" or "service-*"
Unique Field: Origin Host
Observation Window: 30 days
Baseline Period: 30 days
Action: Create Alarm (Critical)
SmartResponse: Disable account, Notify SOC lead
MITRE: T1078.002 - Valid Accounts: Domain Accounts`, 'LogRhythm AI Engine — Unique Rule')}

        <h3>AI Engine Rule 3: Statistical — Data Exfiltration</h3>
        ${codeBlock(`Rule Type: Statistical
Name: Abnormal Outbound Data Transfer
Description: Outbound bytes exceed 3 standard deviations from baseline
Log Source Type: Firewall / Proxy
Common Event: Network Traffic
Statistical Metric: Sum of Bytes Out
Group By: Origin Host
Standard Deviations: 3.0
Baseline Window: 7 days
Evaluation Interval: 1 hour
Action: Create Alarm (High)
SmartResponse: Block IP at firewall, Create case
MITRE: T1048 - Exfiltration Over Alternative Protocol`, 'LogRhythm AI Engine — Statistical Rule')}

        <h3>AI Engine Rule 4: Behavioral — Process Anomaly</h3>
        ${codeBlock(`Rule Type: Behavioral
Name: Anomalous Process Execution Pattern
Description: New process observed on server outside of baseline behavior
Log Source Type: Sysmon / EDR
Common Event: Process Created
Filter: Host Type = "Server"
Behavioral Field: Process Name
Baseline Period: 14 days
Sensitivity: High
Action: Create Alarm (Medium)
MITRE: T1059 - Command and Scripting Interpreter`, 'LogRhythm AI Engine — Behavioral Rule')}

        <h3>SmartResponse Example</h3>
        ${codeBlock(`# SmartResponse Plugin: Disable AD Account
# Triggered automatically by AI Engine alarm

# PowerShell SmartResponse Action:
$username = $args[0]
$reason = $args[1]
Import-Module ActiveDirectory
Disable-ADAccount -Identity $username
Set-ADUser -Identity $username -Description "Disabled by LogRhythm SmartResponse: $reason"
Write-Output "Account $username disabled successfully"`, 'PowerShell — SmartResponse Action')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Log Collection & Processing</h4><p>Deploy System Monitor Agents. Configure log sources in the Platform Manager. Understand MPE (Message Processing Engine) rules for parsing. Learn the LogRhythm data schema.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: AI Engine Rules</h4><p>Build Threshold and Unique rules for basic detections. Understand Statistical baselines. Create rule chains for multi-stage attack detection. Configure alarm priorities and notifications.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Investigation & Response</h4><p>Master the Web Console investigation workflow. Use Tail and Search features. Build SmartResponse actions in PowerShell. Create case management workflows.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Analytics</h4><p>Fine-tune Behavioral and Trend rules. Enable CloudAI for ML-powered detections. Build executive dashboards. Integrate with third-party SOAR platforms.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Start with Threshold rules for quick wins, then progress to Statistical and Behavioral rules</li><li>Let Statistical and Behavioral rules build baselines for 2+ weeks before enabling alarms</li><li>Use Unique rules for high-value account monitoring (service accounts, admins)</li><li>Chain multiple AI Engine rules together for complex multi-stage detection</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Enabling Statistical rules before baselines are established</li><li>Not categorizing log sources correctly — AI Engine rules filter by log source type</li><li>Creating too many low-priority alarms — causes alert fatigue</li><li>Not testing SmartResponse actions in a lab environment first</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 11. SECURONIX
// ─────────────────────────────────────────────────────
platformContent.securonix = {
    overview: `
        <h3>What is Securonix?</h3>
        <p>Securonix is a cloud-native SIEM/UEBA platform that combines log management with advanced analytics. Its Spotter search engine provides real-time threat hunting. Securonix uses pre-built threat models, risk scoring, and peer group analytics to detect insider threats and advanced attacks.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>Spotter — search query engine</li><li>Threat Models — behavior-based detections</li><li>Risk Scoring — entity risk accumulation</li><li>Peer Group Analytics — deviation detection</li><li>Autonomous Threat Sweeper</li><li>SOAR module</li></ul>
            </div>
            <div class="pc-info-card"><h4>ANALYTICS TYPES</h4>
                <ul><li>Rule-based policies</li><li>Statistical anomaly detection</li><li>Peer group comparisons</li><li>Threat chain models</li><li>Rare event detection</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Spotter Query 1: Failed Authentication Analysis</h3>
        ${codeBlock(`index = activity AND
eventtype = "authentication" AND
result = "FAILURE" |
top accountname, sourceaddress |
where count > 10`, 'Spotter — Failed Auth Analysis')}

        <h3>Spotter Query 2: Suspicious Process Execution</h3>
        ${codeBlock(`index = activity AND
eventtype = "process-start" AND
(processname ENDS WITH "powershell.exe" OR
 processname ENDS WITH "cmd.exe") AND
(commandline CONTAINS "encodedcommand" OR
 commandline CONTAINS "downloadstring" OR
 commandline CONTAINS "bypass") |
select datetime, accountname, hostname, processname, commandline`, 'Spotter — Suspicious Process')}

        <h3>Spotter Query 3: Data Exfiltration via USB</h3>
        ${codeBlock(`index = activity AND
eventtype = "file-write" AND
devicetype = "removable" |
top accountname, filename, filesize |
where sum(filesize) > 104857600`, 'Spotter — USB Exfiltration')}

        <h3>Spotter Query 4: Impossible Travel</h3>
        ${codeBlock(`index = activity AND
eventtype = "authentication" AND
result = "SUCCESS" |
group accountname |
select accountname, sourceaddress, sourcelocation, datetime |
sort datetime asc |
where geo_distance(prev_sourcelocation, sourcelocation) > 500 AND
      timediff(prev_datetime, datetime) < 60m`, 'Spotter — Impossible Travel')}

        <h3>Threat Model Example (JSON)</h3>
        ${codeBlock(`{
  "name": "Insider Threat - Data Hoarding",
  "description": "Detects users accumulating large volumes of sensitive data",
  "mitre_tactic": "Collection",
  "mitre_technique": "T1005",
  "risk_score": 85,
  "chain": [
    {
      "stage": 1,
      "name": "Excessive File Access",
      "condition": "file_access_count > peer_avg * 3",
      "window": "24h",
      "points": 30
    },
    {
      "stage": 2,
      "name": "Sensitive Data Access",
      "condition": "classification IN ('confidential', 'restricted')",
      "window": "24h",
      "points": 40
    },
    {
      "stage": 3,
      "name": "Data Staging",
      "condition": "file_copy_to_local AND total_size > 500MB",
      "window": "48h",
      "points": 50
    }
  ]
}`, 'JSON — Securonix Threat Model')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Spotter & Navigation</h4><p>Learn Spotter query syntax. Navigate dashboards and incident views. Understand entity profiles and risk scores. Browse pre-built threat models.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Data Onboarding</h4><p>Configure data connectors. Map data to Securonix schema. Set up identity resolution. Configure peer group definitions.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Threat Models & Policies</h4><p>Create custom security policies. Build threat chain models. Configure risk scoring weights. Set up violation dashboards.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Analytics</h4><p>Tune peer group analytics. Configure Autonomous Threat Sweeper. Build executive risk dashboards. Integrate SOAR playbooks.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Define peer groups based on job function, department, and location for meaningful comparisons</li><li>Use threat chain models instead of single-event rules for reduced false positives</li><li>Combine Spotter queries with risk scoring for threat hunting prioritization</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not configuring identity resolution — "jdoe" and "john.doe@company.com" appear as separate entities</li><li>Overly broad peer groups — comparing developers to executives produces meaningless anomalies</li><li>Not baselining before enabling policies — generates flood of initial violations</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 12. MCAFEE ESM / TRELLIX
// ─────────────────────────────────────────────────────
platformContent.mcafee = {
    overview: `
        <h3>What is McAfee ESM / Trellix XDR?</h3>
        <p>McAfee Enterprise Security Manager (now part of Trellix) is an enterprise SIEM that uses XML-based correlation rules and an Advanced Correlation Engine (ACE) for risk-based threat detection. It features watchlists, data sources, and native integration with the Trellix endpoint and network security ecosystem.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE COMPONENTS</h4>
                <ul><li>ESM — central management</li><li>ERC (Event Receiver) — log collection</li><li>ACE — Advanced Correlation Engine</li><li>ELM — Enterprise Log Manager</li><li>DEM — Database Event Monitor</li><li>ADM — Application Data Monitor</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY CONCEPTS</h4>
                <ul><li>Correlation rules — XML-based logic</li><li>Watchlists — dynamic IOC lists</li><li>Data sources — configured log inputs</li><li>Views — customizable dashboards</li><li>Alarms — triggered notifications</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Correlation Rule 1: Brute Force Attack</h3>
        ${codeBlock(`<Correlation>
  <Name>Brute Force Login Attempt</Name>
  <Description>Multiple failed logins followed by success</Description>
  <Severity>8</Severity>
  <Rule>
    <Match>
      <Field name="Event_Subtype">Authentication Failure</Field>
      <Threshold count="10" timespan="300"/>
      <GroupBy>Source_IP, Destination_User</GroupBy>
    </Match>
    <FollowedBy timespan="600">
      <Field name="Event_Subtype">Authentication Success</Field>
      <GroupBy>Source_IP, Destination_User</GroupBy>
    </FollowedBy>
  </Rule>
  <Action type="alarm">
    <Priority>High</Priority>
    <Assignee>SOC-Tier2</Assignee>
  </Action>
</Correlation>`, 'XML — McAfee ESM Correlation')}

        <h3>Correlation Rule 2: Suspicious Outbound Traffic</h3>
        ${codeBlock(`<Correlation>
  <Name>Suspicious Outbound Connection to Rare Destination</Name>
  <Severity>7</Severity>
  <Rule>
    <Match>
      <Field name="Event_Subtype">Network Connection</Field>
      <Field name="Direction">Outbound</Field>
      <Not><Watchlist name="Known_Good_Destinations" field="Destination_IP"/></Not>
      <Threshold count="20" timespan="3600"/>
      <GroupBy>Source_IP, Destination_IP</GroupBy>
    </Match>
  </Rule>
  <Action type="alarm"><Priority>Medium</Priority></Action>
</Correlation>`, 'XML — Outbound Traffic Rule')}

        <h3>Correlation Rule 3: Malware Detected on Multiple Hosts</h3>
        ${codeBlock(`<Correlation>
  <Name>Malware Spreading Across Network</Name>
  <Severity>9</Severity>
  <Rule>
    <Match>
      <Field name="Event_Subtype">Malware Detected</Field>
      <Field name="Signature_Name" operator="contains">*</Field>
      <ThresholdDistinct field="Destination_Host" count="3" timespan="1800"/>
      <GroupBy>Signature_Name</GroupBy>
    </Match>
  </Rule>
  <Action type="alarm"><Priority>Critical</Priority></Action>
</Correlation>`, 'XML — Malware Spread Detection')}

        <h3>Watchlist Configuration</h3>
        ${codeBlock(`# API: Create a watchlist
POST /api/v2/watchlists
{
  "name": "Malicious_IPs",
  "type": "IPAddress",
  "dynamic": true,
  "source": "threat_feed",
  "refresh_interval": "1h",
  "values": [
    "203.0.113.50",
    "198.51.100.25",
    "192.0.2.100"
  ]
}`, 'JSON — Watchlist Configuration')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: ESM Navigation & Search</h4><p>Navigate the ESM console. Use views and filters for event searches. Understand data source configuration. Learn event normalization.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Correlation Rules</h4><p>Build XML correlation rules. Understand match conditions, thresholds, and FollowedBy sequences. Configure alarms and notification targets.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: ACE & Advanced</h4><p>Configure the Advanced Correlation Engine for risk scoring. Set up watchlists with external threat feeds. Build custom views and dashboards.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Integration</h4><p>Integrate with Trellix EDR and Network Security. Configure DEM for database monitoring. Set up compliance reporting. API automation.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use ACE risk scoring to prioritize alarms by cumulative risk instead of individual events</li><li>Maintain watchlists with automated threat feed updates</li><li>Use FollowedBy rules for sequential attack detection (e.g., recon then exploit)</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Creating too many non-specific correlation rules — leads to alarm fatigue</li><li>Not using watchlist exclusions for known-good entities</li><li>Ignoring ELM archival — long-term logs are needed for forensics</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 13. LOGPOINT
// ─────────────────────────────────────────────────────
platformContent.logpoint = {
    overview: `
        <h3>What is LogPoint?</h3>
        <p>LogPoint is a European SIEM platform that uses LPQL (LogPoint Query Language) for log search and analysis. It features built-in SOAR and UEBA modules, compliance reporting templates, and an emphasis on data privacy (GDPR-compliant by design).</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>LPQL — LogPoint Query Language</li><li>Alert Rules — detection logic</li><li>UEBA Module — behavioral analytics</li><li>SOAR Module — playbook automation</li><li>Compliance dashboards (GDPR, PCI, HIPAA)</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY CONCEPTS</h4>
                <ul><li><code>repos</code> — data repositories</li><li><code>label</code> — normalized event categories</li><li><code>norm_id</code> — normalized event ID</li><li><code>enrichment policies</code> — context addition</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>LPQL Query 1: Brute Force Detection</h3>
        ${codeBlock(`label=Login label=Fail
| chart count() as failures by source_address, user
| search failures > 10
| sort failures desc`, 'LPQL — Brute Force')}

        <h3>LPQL Query 2: Suspicious Process Execution</h3>
        ${codeBlock(`norm_id=WindowsSysmon event_id=1
process_name IN ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"]
command CONTAINS "*encodedcommand*" OR command CONTAINS "*downloadstring*"
| chart count() as hits by host, user, process_name, command
| sort hits desc`, 'LPQL — Suspicious Process')}

        <h3>LPQL Query 3: Outbound Data Transfer Anomaly</h3>
        ${codeBlock(`label=Connection label=Allow direction=outbound
| chart sum(bytes_out) as total_bytes by source_address
| search total_bytes > 1073741824
| eval mb_sent = total_bytes / 1048576
| sort mb_sent desc`, 'LPQL — Data Transfer Anomaly')}

        <h3>LPQL Query 4: DNS Query Analysis</h3>
        ${codeBlock(`label=DNS label=Query
| eval query_length = length(query)
| chart count() as queries, avg(query_length) as avg_len by domain
| search avg_len > 40 AND queries > 50
| sort queries desc`, 'LPQL — DNS Analysis')}

        <h3>Alert Rule Configuration</h3>
        ${codeBlock(`{
  "name": "Brute Force Authentication Alert",
  "query": "label=Login label=Fail | chart count() as failures by source_address, user | search failures > 10",
  "interval": "5m",
  "severity": "High",
  "suppress": "30m",
  "suppress_by": ["source_address", "user"],
  "actions": [
    { "type": "email", "to": "soc@company.com" },
    { "type": "incident", "priority": "High" }
  ],
  "mitre": { "tactic": "Credential Access", "technique": "T1110" }
}`, 'JSON — LogPoint Alert Rule')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: LPQL Fundamentals</h4><p>Learn LPQL syntax: filters, chart, search, sort, eval. Understand labels and norm_ids for normalized queries. Practice searches in the LogPoint UI.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Log Sources & Normalization</h4><p>Configure log source policies. Understand log normalization and enrichment. Set up syslog, Windows WEF, and cloud connectors.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Alert Rules & Dashboards</h4><p>Create alert rules with LPQL queries. Build investigation dashboards. Configure suppression and severity levels. Set up notification channels.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: UEBA & SOAR</h4><p>Enable the UEBA module for behavioral analytics. Build SOAR playbooks for automated response. Configure compliance reporting templates.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use <code>label</code> filters for normalized searches that work across different log source types</li><li>Enable log enrichment policies to add geo-IP, threat intel, and asset context automatically</li><li>Use <code>suppress</code> in alert rules to prevent alert fatigue from repeated triggers</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not using labels — writing source-specific queries that break when log format changes</li><li>Setting alert intervals too short without suppression — creates duplicate alerts</li><li>Not configuring log rotation in repos — disk fills up</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 14. RAPID7 INSIGHTIDR
// ─────────────────────────────────────────────────────
platformContent.insightidr = {
    overview: `
        <h3>What is Rapid7 InsightIDR?</h3>
        <p>InsightIDR is a cloud-native SIEM/XDR that uses LEQL (Log Entry Query Language) for searches and features Attacker Behavior Analytics (ABA) — pre-built detection rules based on real-world attack techniques. It includes deception technology (honeypots, honey users, honey files) for early threat detection.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>LEQL — Log Entry Query Language</li><li>ABA — Attacker Behavior Analytics</li><li>Deception Technology — honeypots/honey users</li><li>UBA — User Behavior Analytics</li><li>Custom Alerts — LEQL-based detections</li><li>Visual Investigation Timeline</li></ul>
            </div>
            <div class="pc-info-card"><h4>DECEPTION TECHNOLOGY</h4>
                <ul><li><strong>Honey Users</strong> — fake AD accounts; any login triggers alert</li><li><strong>Honeypots</strong> — fake network services; any connection triggers alert</li><li><strong>Honey Files</strong> — canary documents on file shares</li><li><strong>Honey Credentials</strong> — stored in LSASS memory traps</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>LEQL Query 1: Failed Authentication Analysis</h3>
        ${codeBlock(`where(authentication.result = FAILURE)
groupby(authentication.source_ip, authentication.account)
calculate(count)
sort(count desc)
filter(count > 10)`, 'LEQL — Failed Authentication')}

        <h3>LEQL Query 2: PowerShell Suspicious Activity</h3>
        ${codeBlock(`where(process.name = "powershell.exe" AND
  (process.cmd_line CONTAINS "encodedcommand" OR
   process.cmd_line CONTAINS "downloadstring" OR
   process.cmd_line CONTAINS "bypass" OR
   process.cmd_line CONTAINS "invoke-expression"))
groupby(host.name, process.account, process.cmd_line)`, 'LEQL — PowerShell Detection')}

        <h3>LEQL Query 3: Lateral Movement via RDP</h3>
        ${codeBlock(`where(authentication.result = SUCCESS AND
  authentication.logon_type = 10 AND
  authentication.source_ip != "127.0.0.1")
groupby(authentication.source_ip)
calculate(unique:authentication.destination_host)
filter(unique > 3)`, 'LEQL — RDP Lateral Movement')}

        <h3>LEQL Query 4: DNS Tunneling Indicators</h3>
        ${codeBlock(`where(dns.query_length > 50 AND
  dns.record_type = "TXT")
groupby(dns.query_domain, source.ip)
calculate(count)
filter(count > 20)
sort(count desc)`, 'LEQL — DNS Tunneling')}

        <h3>Custom Alert Definition</h3>
        ${codeBlock(`{
  "name": "Service Account Authentication from New Source",
  "description": "Detects service account login from previously unseen IP",
  "leql": {
    "statement": "where(authentication.result = SUCCESS AND authentication.account STARTS WITH 'svc-') groupby(authentication.account, authentication.source_ip) calculate(count)"
  },
  "detection_rules": {
    "type": "custom_alert",
    "severity": "HIGH",
    "mitre_tactic": "Valid Accounts",
    "mitre_technique": "T1078"
  },
  "alert_actions": [
    { "type": "email", "recipients": ["soc@company.com"] },
    { "type": "investigation", "auto_create": true }
  ]
}`, 'JSON — Custom Alert Definition')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: LEQL & Log Search</h4><p>Learn LEQL syntax: where, groupby, calculate, filter, sort. Explore pre-built dashboards. Understand log sets (Authentication, Endpoint, Network, Cloud).</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Data Collection</h4><p>Deploy Insight Agent on endpoints. Configure event sources (AD, DHCP, DNS, Firewall). Set up cloud integrations (AWS, Azure, O365). Install network sensors for deception.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Deception & ABA</h4><p>Deploy honey users, honeypots, and honey files. Review and tune ABA rules. Create custom alerts with LEQL. Build investigation workflows.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Hunting</h4><p>Build threat hunting LEQL queries. Create custom dashboards. Enable UBA behavioral detections. Integrate with Rapid7 InsightConnect for SOAR.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Deploy deception technology immediately — honey users are zero-effort, high-signal alerts</li><li>Use ABA detections as your baseline and layer custom LEQL alerts on top</li><li>Regularly rotate honey credentials and honeypot configurations</li><li>Use the visual investigation timeline for incident analysis</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not deploying Insight Agent on all endpoints — gaps in EDR visibility</li><li>Ignoring honey user alerts — these are high-fidelity signals that should always be investigated</li><li>Writing LEQL alerts without testing against historical data first</li><li>Not configuring proper log forwarding from network devices</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 15. CROWDSTRIKE FALCON
// ─────────────────────────────────────────────────────
platformContent.crowdstrike = {
    overview: `
        <h3>What is CrowdStrike Falcon?</h3>
        <p>CrowdStrike Falcon is a cloud-native endpoint protection platform combining EDR, threat intelligence, and managed hunting. It uses lightweight agents and processes telemetry in the cloud. Falcon Query Language (FQL) enables threat hunting, and custom IOA (Indicator of Attack) rules provide behavioral detection beyond static IOCs.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE MODULES</h4>
                <ul><li>Falcon Prevent — NGAV</li><li>Falcon Insight — EDR</li><li>Falcon OverWatch — managed hunting</li><li>Falcon Intelligence — threat intel</li><li>Falcon Discover — IT hygiene</li><li>Real Time Response (RTR)</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY CONCEPTS</h4>
                <ul><li><code>IOA</code> — Indicator of Attack (behavioral)</li><li><code>IOC</code> — Indicator of Compromise (static)</li><li><code>FQL</code> — Falcon Query Language</li><li><code>RTR</code> — Real Time Response (remote shell)</li><li><code>Process Tree</code> — execution chain view</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>FQL Query 1: Suspicious PowerShell Activity</h3>
        ${codeBlock(`event_simpleName=ProcessRollup2
FileName=powershell.exe
(CommandLine=*-enc* OR CommandLine=*downloadstring* OR CommandLine=*bypass*)
| stats count by ComputerName, UserName, CommandLine
| sort -count`, 'FQL — PowerShell Hunting')}

        <h3>FQL Query 2: LSASS Access (Credential Theft)</h3>
        ${codeBlock(`event_simpleName=ProcessRollup2
(TargetFileName=*lsass* OR CommandLine=*sekurlsa* OR CommandLine=*mimikatz*)
NOT FileName IN (csrss.exe, svchost.exe, lsass.exe)
| stats count by ComputerName, FileName, CommandLine, UserName`, 'FQL — LSASS Access Detection')}

        <h3>FQL Query 3: Lateral Movement Detection</h3>
        ${codeBlock(`event_simpleName=NetworkConnectIP4
RemotePort IN (445, 135, 5985, 3389)
NOT RemoteAddressIP4=10.0.0.*
| stats dc(RemoteAddressIP4) as unique_targets, values(RemoteAddressIP4) by ComputerName, UserName
| where unique_targets > 3`, 'FQL — Lateral Movement')}

        <h3>Custom IOA Rule Example (YAML)</h3>
        ${codeBlock(`name: "Suspicious Certutil Download"
description: "Detects certutil.exe used to download files from the internet"
severity: high
mitre_tactic: "Defense Evasion"
mitre_technique: "T1218"
platform: windows
rule_type: process_creation
conditions:
  image_filename: "certutil.exe"
  command_line_pattern: ".*(-urlcache|-split).*http.*"
  exclude_parent_image:
    - "C:\\\\Windows\\\\System32\\\\svchost.exe"
action: detect
disposition: suspicious`, 'YAML — Custom IOA Rule')}

        <h3>RTR (Real Time Response) Commands</h3>
        ${codeBlock(`# Connect to a host for live investigation
# List running processes
ps

# Check network connections
netstat

# List scheduled tasks
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

# Collect a file for analysis
get "C:\\Users\\suspect\\AppData\\Local\\Temp\\malware.exe"

# Kill a malicious process
kill <pid>

# Quarantine the host from the network
containment on`, 'RTR — Real Time Response Commands')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Falcon Console & Detection Triage</h4><p>Navigate the Falcon UI. Review detections and process trees. Understand severity levels and confidence scores. Practice triaging true positives vs false positives.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: FQL Threat Hunting</h4><p>Learn FQL syntax for Event Search. Hunt for suspicious processes, network connections, and file writes. Build saved queries for recurring hunts.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Custom IOA & IOC</h4><p>Create custom IOA rules for organization-specific threats. Upload IOC lists (hashes, IPs, domains). Configure prevention policies and response actions.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: RTR & Advanced</h4><p>Master Real Time Response for live investigation. Use Falcon Fusion for workflow automation. Integrate with SOAR platforms via API. Review OverWatch threat reports.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use IOA rules (behavioral) over IOC lists (static) — IOAs catch novel attack variants</li><li>Regularly review OverWatch advisories and adjust custom IOAs accordingly</li><li>Use process tree visualization for complete attack chain analysis</li><li>Deploy RTR responder access only to Tier 2+ analysts</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Setting prevention policies too aggressively on day one — whitelist critical apps first</li><li>Not reviewing detection suppressions periodically — threat landscape changes</li><li>Ignoring Falcon Discover findings — unmanaged assets are blind spots</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 16. MICROSOFT DEFENDER FOR ENDPOINT
// ─────────────────────────────────────────────────────
platformContent.mde = {
    overview: `
        <h3>What is Microsoft Defender for Endpoint?</h3>
        <p>Microsoft Defender for Endpoint (MDE) is an enterprise EDR platform with advanced hunting using KQL, Attack Surface Reduction (ASR) rules, automated investigation and remediation (AIR), and native integration with the Microsoft 365 security stack.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>KEY CAPABILITIES</h4>
                <ul><li>Advanced Hunting (KQL)</li><li>ASR Rules — attack surface reduction</li><li>EDR — detection and response</li><li>AIR — automated investigation</li><li>Threat & Vulnerability Management</li><li>Custom Detection Rules</li></ul>
            </div>
            <div class="pc-info-card"><h4>HUNTING TABLES</h4>
                <ul><li><code>DeviceProcessEvents</code> — process creation</li><li><code>DeviceNetworkEvents</code> — network connections</li><li><code>DeviceFileEvents</code> — file operations</li><li><code>DeviceRegistryEvents</code> — registry changes</li><li><code>DeviceLogonEvents</code> — authentication</li><li><code>DeviceImageLoadEvents</code> — DLL loads</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>KQL Hunt 1: Encoded PowerShell Execution</h3>
        ${codeBlock(`DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ")
| extend DecodedCommand = base64_decode_tostring(
    extract("[A-Za-z0-9+/]{20,}={0,2}", 0, ProcessCommandLine))
| project Timestamp, DeviceName, AccountName,
    ProcessCommandLine, DecodedCommand, InitiatingProcessFileName
| sort by Timestamp desc`, 'KQL — Encoded PowerShell')}

        <h3>KQL Hunt 2: LSASS Credential Dumping</h3>
        ${codeBlock(`DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("procdump.exe", "rundll32.exe", "comsvcs.dll", "mimikatz.exe")
   or ProcessCommandLine has_any ("sekurlsa", "lsass", "MiniDump", "comsvcs")
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc`, 'KQL — LSASS Credential Dump')}

        <h3>KQL Hunt 3: Persistence via Registry Run Key</h3>
        ${codeBlock(`DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"\\CurrentVersion\\Run",
    @"\\CurrentVersion\\RunOnce",
    @"\\Explorer\\Shell Folders",
    @"\\Winlogon\\Shell"
)
| where RegistryValueData has_any (".exe", ".dll", ".bat", ".ps1", ".vbs", "http")
| project Timestamp, DeviceName, RegistryKey,
    RegistryValueName, RegistryValueData, InitiatingProcessFileName`, 'KQL — Registry Persistence')}

        <h3>Custom Detection Rule (JSON)</h3>
        ${codeBlock(`{
  "displayName": "Suspicious Certutil File Download",
  "severity": "high",
  "category": "DefenseEvasion",
  "mitreTechniques": ["T1218"],
  "query": "DeviceProcessEvents | where FileName =~ 'certutil.exe' | where ProcessCommandLine has_any ('-urlcache', '-split', 'http')",
  "queryFrequency": "PT1H",
  "queryPeriod": "PT1H",
  "triggerOperator": "GreaterThan",
  "triggerThreshold": 0,
  "actions": {
    "isolateDevice": false,
    "collectInvestigationPackage": true,
    "runAntivirusScan": true
  }
}`, 'JSON — Custom Detection Rule')}

        <h3>ASR Rule Configuration (PowerShell)</h3>
        ${codeBlock(`# Enable Attack Surface Reduction rules via PowerShell
# Block executable content from email and webmail
Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Block Office apps from creating child processes
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled

# Block credential stealing from LSASS
Set-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled

# Block process creations from PSExec and WMI
Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions AuditMode`, 'PowerShell — ASR Rules')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: MDE Console & Alerts</h4><p>Navigate the Microsoft 365 Defender portal. Review and triage alerts. Understand the alert evidence chain. Learn device inventory and health monitoring.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Advanced Hunting KQL</h4><p>Master the Device* tables. Write hunting queries for process, network, file, and registry events. Use <code>join</code> to correlate across tables. Save queries and create custom detections.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: ASR & Prevention</h4><p>Deploy ASR rules in Audit mode first. Review ASR events and create exclusions. Transition to Block mode. Configure network protection and web content filtering.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: AIR & Advanced</h4><p>Configure Automated Investigation and Remediation levels. Use Live Response for forensics. Integrate with Sentinel for unified SIEM+EDR. Build threat & vulnerability management workflows.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Deploy ASR rules in Audit mode for 2 weeks before switching to Block</li><li>Use <code>DeviceProcessEvents</code> as your primary hunting table — process telemetry reveals the most</li><li>Create custom detection rules from successful hunting queries</li><li>Leverage AIR to auto-remediate low/medium severity incidents</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Enabling all ASR rules in Block mode immediately — breaks legitimate applications</li><li>Not reviewing AIR remediation actions — automated actions should still be audited</li><li>Ignoring Threat & Vulnerability Management recommendations</li><li>Not correlating MDE alerts with Sentinel for the full picture</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 17. SENTINELONE
// ─────────────────────────────────────────────────────
platformContent.sentinelone = {
    overview: `
        <h3>What is SentinelOne?</h3>
        <p>SentinelOne is an autonomous endpoint protection platform that uses AI-driven behavioral analysis. Its Storyline technology automatically correlates related events into attack narratives. Deep Visibility provides SQL-based threat hunting, and STAR (Storyline Active Response) rules enable custom automated detection and response.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>KEY FEATURES</h4>
                <ul><li>Storyline — automatic event correlation</li><li>Deep Visibility — SQL-based hunting</li><li>STAR Rules — custom detection + response</li><li>Ranger — network discovery</li><li>RemoteOps — remote scripting</li><li>1-click remediation and rollback</li></ul>
            </div>
            <div class="pc-info-card"><h4>RESPONSE ACTIONS</h4>
                <ul><li>Kill process</li><li>Quarantine file</li><li>Remediate (undo changes)</li><li>Rollback (restore from VSS)</li><li>Network isolate</li><li>Remote shell</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Deep Visibility SQL 1: Suspicious PowerShell</h3>
        ${codeBlock(`SELECT
    endpoint_name, src_process_user, src_process_cmdline,
    src_process_parent_name, event_time
FROM process_creation_events
WHERE src_process_image_path LIKE '%powershell%'
AND (src_process_cmdline LIKE '%EncodedCommand%'
     OR src_process_cmdline LIKE '%DownloadString%'
     OR src_process_cmdline LIKE '%Invoke-Expression%'
     OR src_process_cmdline LIKE '%-bypass%')
ORDER BY event_time DESC
LIMIT 100`, 'SQL — PowerShell Hunting')}

        <h3>Deep Visibility SQL 2: Lateral Movement</h3>
        ${codeBlock(`SELECT
    endpoint_name, src_process_user,
    dst_ip, dst_port,
    src_process_image_path,
    event_time
FROM network_events
WHERE dst_port IN (445, 135, 5985, 3389)
AND dst_ip NOT LIKE '127.%'
AND src_process_image_path NOT LIKE '%svchost%'
GROUP BY endpoint_name, dst_ip
HAVING COUNT(DISTINCT dst_ip) > 3
ORDER BY event_time DESC`, 'SQL — Lateral Movement')}

        <h3>Deep Visibility SQL 3: Ransomware Indicators</h3>
        ${codeBlock(`SELECT
    endpoint_name, src_process_image_path,
    src_process_cmdline, src_process_user,
    COUNT(*) as file_events
FROM file_modification_events
WHERE event_type = 'FILE_RENAME'
AND (file_extension IN ('.encrypted', '.locked', '.crypt', '.enc')
     OR old_file_name LIKE '%.pdf' AND file_extension != '.pdf')
GROUP BY endpoint_name, src_process_image_path
HAVING file_events > 50
ORDER BY file_events DESC`, 'SQL — Ransomware Detection')}

        <h3>STAR Rule Example (JSON)</h3>
        ${codeBlock(`{
  "name": "STAR: Suspicious LSASS Access",
  "description": "Detects non-system processes accessing LSASS memory",
  "severity": "Critical",
  "mitre": {
    "tactic": "Credential Access",
    "technique": "T1003.001"
  },
  "query": "ObjectType = 'cross_process' AND TargetProcessName = 'lsass.exe' AND SourceProcessName NOT IN ('csrss.exe', 'svchost.exe', 'MsMpEng.exe')",
  "response_actions": [
    "kill_process",
    "quarantine_file",
    "network_isolate"
  ],
  "auto_remediate": true,
  "notify": ["soc@company.com"]
}`, 'JSON — STAR Custom Rule')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Console & Storylines</h4><p>Navigate the SentinelOne management console. Review threats and Storyline visualizations. Understand automated remediation vs manual. Learn threat status: mitigated, active, resolved.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Deep Visibility Hunting</h4><p>Write SQL queries for process, file, network, and registry events. Build saved queries for common hunts. Create hunting dashboards.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: STAR Rules & Policy</h4><p>Create custom STAR rules for organization-specific threats. Configure detection and response policies per group. Test rules in detect-only mode before enabling auto-response.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Features</h4><p>Use Ranger for network discovery of unmanaged devices. Deploy RemoteOps scripts. Integrate with SOAR via API. Configure Singularity Marketplace apps.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use Storyline visualization for full attack chain analysis before making remediation decisions</li><li>Enable auto-remediate for high-confidence detections, manual for medium</li><li>Test STAR rules in detect-only mode for 1 week before enabling auto-response</li><li>Use Ranger to find unmanaged endpoints that need agent deployment</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Auto-remediating everything without exclusion lists — breaks legitimate admin tools</li><li>Not reviewing Storylines before rollback — rollback is resource-intensive</li><li>Ignoring Ranger discoveries — unmanaged devices are prime attack targets</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 18. CARBON BLACK
// ─────────────────────────────────────────────────────
platformContent.carbonblack = {
    overview: `
        <h3>What is Carbon Black?</h3>
        <p>VMware Carbon Black (Cloud or Response) is an EDR platform that records all endpoint activity for forensic analysis. It uses watchlist queries for detection, threat intelligence feeds for IOC matching, and Live Response for remote investigation and remediation.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>PRODUCTS</h4>
                <ul><li><strong>CB Cloud</strong> — cloud-native EDR + NGAV</li><li><strong>CB Response</strong> — on-prem EDR (legacy)</li><li><strong>CB Defense</strong> — NGAV</li><li><strong>CB Audit & Remediation</strong> — live queries</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY FEATURES</h4>
                <ul><li>Continuous recording of endpoint activity</li><li>Watchlist queries — automated detection</li><li>Threat feeds — external IOC matching</li><li>Live Response — remote shell</li><li>Process tree visualization</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Watchlist Query 1: PowerShell Download Cradle</h3>
        ${codeBlock(`process_name:powershell.exe AND
(cmdline:DownloadString OR cmdline:DownloadFile OR
 cmdline:WebRequest OR cmdline:WebClient OR
 cmdline:EncodedCommand OR cmdline:FromBase64String)`, 'CB Query — PowerShell Download')}

        <h3>Watchlist Query 2: Suspicious Process from Temp Directory</h3>
        ${codeBlock(`process_path:(\\\\temp\\\\ OR \\\\tmp\\\\ OR \\\\appdata\\\\local\\\\temp\\\\) AND
-process_name:(msiexec.exe OR setup.exe OR chrome_installer.exe) AND
netconn_count:[1 TO *]`, 'CB Query — Temp Directory Execution')}

        <h3>Watchlist Query 3: LSASS Access</h3>
        ${codeBlock(`crossproc_target:lsass.exe AND
-process_name:(csrss.exe OR svchost.exe OR MsMpEng.exe OR lsass.exe) AND
crossproc_type:process_access`, 'CB Query — LSASS Credential Theft')}

        <h3>Watchlist Query 4: Ransomware File Activity</h3>
        ${codeBlock(`filemod_count:[100 TO *] AND
(filemod_extension:(.encrypted OR .locked OR .crypt) OR
 process_name:(vssadmin.exe OR wmic.exe) AND
 cmdline:(shadowcopy OR delete))`, 'CB Query — Ransomware Indicators')}

        <h3>Threat Feed Configuration (JSON)</h3>
        ${codeBlock(`{
  "feedinfo": {
    "name": "Custom Threat Intel Feed",
    "display_name": "BlueShell Threat Feed",
    "provider_url": "https://blueshell.internal",
    "summary": "Internal IOC feed from threat intelligence team",
    "tech_contact": "soc@company.com",
    "icon": "",
    "category": "Partner"
  },
  "reports": [
    {
      "id": "report-001",
      "title": "Cobalt Strike C2 Infrastructure",
      "description": "Known Cobalt Strike team server IPs",
      "severity": 9,
      "iocs_v2": [
        { "id": "ioc-001", "match_type": "query", "values": ["ipaddr:203.0.113.50 OR ipaddr:198.51.100.25"] },
        { "id": "ioc-002", "match_type": "equality", "field": "process_sha256",
          "values": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] }
      ],
      "tags": ["cobalt_strike", "c2", "apt"],
      "timestamp": 1700000000
    }
  ]
}`, 'JSON — CB Threat Feed')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Console & Process Analysis</h4><p>Navigate CB Cloud or Response console. Review alerts and process trees. Understand sensor groups and policies. Learn the query syntax for process, network, and file events.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Watchlists & Threat Feeds</h4><p>Create watchlist queries for automated detection. Import external threat feeds. Configure alert severity and notification targets. Build a library of hunting queries.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Live Response & Forensics</h4><p>Use Live Response for remote investigation. Collect files, list processes, check persistence. Build remediation scripts. Use Audit & Remediation for fleet-wide queries.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Integration & Automation</h4><p>Use the CB API for automation. Integrate with SOAR platforms. Build custom reports. Configure connector integrations with SIEM.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use watchlists for automated detection — they continuously match against incoming telemetry</li><li>Curate threat feeds carefully — low-quality feeds generate excessive false positives</li><li>Use process tree analysis during investigation to understand the full attack chain</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Creating overly broad watchlist queries (e.g., <code>process_name:cmd.exe</code>) — generates thousands of alerts</li><li>Not expiring old IOCs from threat feeds — stale indicators cause false positives</li><li>Not using sensor groups to apply different policies to servers vs workstations</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 19. PALO ALTO CORTEX XDR
// ─────────────────────────────────────────────────────
platformContent.cortex = {
    overview: `
        <h3>What is Palo Alto Cortex XDR?</h3>
        <p>Cortex XDR is an extended detection and response platform that integrates endpoint, network, and cloud data for unified threat detection. It uses XQL (XDR Query Language) for hunting, BIOC (Behavioral Indicator of Compromise) rules for custom detection, and provides automated investigation with causality chains.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>DATA SOURCES</h4>
                <ul><li>Cortex XDR Agent — endpoint telemetry</li><li>Palo Alto firewalls — network logs</li><li>Prisma Cloud — cloud workload data</li><li>Third-party integrations via syslog</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY FEATURES</h4>
                <ul><li>XQL — XDR Query Language</li><li>BIOC Rules — behavioral detection</li><li>Causality View — attack chain</li><li>Analytics BIOC — ML-based detection</li><li>Automated investigation</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>XQL Query 1: Suspicious Process Execution</h3>
        ${codeBlock(`dataset = xdr_data
| filter event_type = PROCESS and
    action_process_image_name in ("certutil.exe", "mshta.exe", "regsvr32.exe") and
    action_process_image_command_line contains "http"
| fields agent_hostname, action_process_image_name,
    action_process_image_command_line, actor_primary_username,
    agent_ip_addresses, _time
| sort desc _time`, 'XQL — Suspicious Process')}

        <h3>XQL Query 2: Lateral Movement Detection</h3>
        ${codeBlock(`dataset = xdr_data
| filter event_type = NETWORK and
    dst_action_external_port in (445, 135, 5985, 3389) and
    action_local_ip != action_remote_ip
| comp count() as connection_count, count_distinct(action_remote_ip) as unique_targets
    by agent_hostname, actor_primary_username
| filter unique_targets > 3
| sort desc unique_targets`, 'XQL — Lateral Movement')}

        <h3>XQL Query 3: Data Exfiltration Indicators</h3>
        ${codeBlock(`dataset = xdr_data
| filter event_type = NETWORK and
    action_external_hostname != null and
    action_total_upload > 10485760
| comp sum(action_total_upload) as total_upload_bytes,
    count() as sessions
    by agent_hostname, action_external_hostname
| alter upload_mb = round(divide(total_upload_bytes, 1048576), 2)
| filter upload_mb > 100
| sort desc upload_mb`, 'XQL — Data Exfiltration')}

        <h3>BIOC Rule Example</h3>
        ${codeBlock(`{
  "rule_name": "Suspicious PowerShell Download Cradle",
  "rule_type": "bioc",
  "severity": "HIGH",
  "mitre_tactic": "Execution",
  "mitre_technique": "T1059.001",
  "os_type": "windows",
  "ioc_rules": [
    {
      "indicator_type": "PROCESS",
      "conditions": {
        "process_name": { "operator": "in", "value": ["powershell.exe", "pwsh.exe"] },
        "process_command_line": {
          "operator": "contains_any",
          "value": ["DownloadString", "DownloadFile", "WebRequest", "IEX", "Invoke-Expression"]
        }
      }
    }
  ],
  "action": "ALERT",
  "alert_grouping": "per_host"
}`, 'JSON — BIOC Rule')}

        <h3>Agent Deployment Commands</h3>
        ${codeBlock(`# Windows installation (silent)
msiexec /i cortex_xdr_agent.msi /qn
  DISTRIBUTION_SERVER=https://distributions.traps.paloaltonetworks.com
  DIST_ID=<distribution_id>
  DIST_SERVER_TOKEN=<token>

# Linux installation
chmod +x cortex_xdr_agent.sh
sudo ./cortex_xdr_agent.sh -- --distribution-server https://distributions.traps.paloaltonetworks.com --dist-id <distribution_id>

# Verify agent status
cytool status
cytool info`, 'Shell — Agent Deployment')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: XDR Console & Incidents</h4><p>Navigate the Cortex XDR console. Review incidents and causality chains. Understand alert scoring. Triage true/false positives.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: XQL Threat Hunting</h4><p>Learn XQL syntax. Query endpoint, network, and cloud datasets. Build saved queries. Create custom dashboards.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: BIOC Rules & Policies</h4><p>Create BIOC rules for custom detections. Configure agent policies. Deploy agents across the fleet. Test rules in alert-only mode.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Automation & Integration</h4><p>Configure automated investigation. Integrate with XSOAR for orchestration. Use the API for custom workflows. Build executive reports.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use Causality View for every investigation — it shows the complete attack chain automatically</li><li>Deploy BIOC rules in alert-only mode before enabling prevention</li><li>Integrate Cortex XDR with Palo Alto firewalls for network+endpoint correlation</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not deploying agents on all endpoints — creates detection gaps</li><li>Ignoring low-severity alerts — they may be early stages of an advanced attack</li><li>Not correlating endpoint alerts with firewall data for the full picture</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 20. MICROSOFT 365 DEFENDER
// ─────────────────────────────────────────────────────
platformContent.m365 = {
    overview: `
        <h3>What is Microsoft 365 Defender?</h3>
        <p>Microsoft 365 Defender is an XDR platform that unifies Defender for Endpoint, Defender for Office 365, Defender for Identity, and Defender for Cloud Apps into a single portal. It enables cross-workload hunting using KQL and provides unified incidents with Automated Investigation and Response (AIR).</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>WORKLOADS</h4>
                <ul><li>Defender for Endpoint — EDR</li><li>Defender for Office 365 — email security</li><li>Defender for Identity — AD threat detection</li><li>Defender for Cloud Apps — CASB/SaaS</li></ul>
            </div>
            <div class="pc-info-card"><h4>CROSS-WORKLOAD TABLES</h4>
                <ul><li><code>IdentityLogonEvents</code> — AD authentication</li><li><code>EmailEvents</code> — email metadata</li><li><code>EmailAttachmentInfo</code> — attachment details</li><li><code>CloudAppEvents</code> — SaaS activity</li><li><code>AlertEvidence</code> — unified evidence</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Cross-Workload Hunt 1: Phishing to Endpoint Compromise Chain</h3>
        ${codeBlock(`// Step 1: Find suspicious emails with attachments
let SuspiciousEmails = EmailEvents
| where Timestamp > ago(24h)
| where DeliveryAction == "Delivered"
| join EmailAttachmentInfo on NetworkMessageId
| where FileType in ("exe", "dll", "js", "vbs", "hta", "ps1", "bat", "iso", "img")
| project NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
    Subject, FileName, Timestamp;
// Step 2: Correlate with endpoint execution
SuspiciousEmails
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(24h)
    | where ActionType == "FileCreated"
) on $left.FileName == $right.FileName
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
) on $left.FileName == $right.FileName
| project SenderFromAddress, RecipientEmailAddress, Subject,
    FileName, DeviceName, ProcessCommandLine, AccountName`, 'KQL — Phishing to Endpoint Chain')}

        <h3>Cross-Workload Hunt 2: Identity Compromise to Data Exfiltration</h3>
        ${codeBlock(`// Suspicious identity events followed by cloud data access
let CompromisedAccounts = IdentityLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "Failed"
| summarize FailCount = count() by AccountUpn, IPAddress
| where FailCount > 20
| join kind=inner (
    IdentityLogonEvents | where LogonType == "Successful"
) on AccountUpn, IPAddress
| distinct AccountUpn;
// Check for cloud data exfiltration by those accounts
CompromisedAccounts
| join kind=inner (
    CloudAppEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("FileDownloaded", "FileShared", "FileSyncDownloadedFull")
) on $left.AccountUpn == $right.AccountObjectId
| summarize DownloadCount = count(), Apps = make_set(Application) by AccountUpn
| where DownloadCount > 50`, 'KQL — Identity to Exfiltration')}

        <h3>Cross-Workload Hunt 3: Lateral Movement from Identity to Endpoint</h3>
        ${codeBlock(`IdentityLogonEvents
| where Timestamp > ago(24h)
| where Application == "Active Directory"
| where LogonType == "Interactive" or LogonType == "RemoteInteractive"
| summarize
    UniqueDevices = dcount(DestinationDeviceName),
    Devices = make_set(DestinationDeviceName, 10)
    by AccountUpn, IPAddress
| where UniqueDevices >= 5
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName in~ ("psexec.exe", "wmic.exe", "powershell.exe")
) on $left.AccountUpn == $right.AccountName
| project AccountUpn, IPAddress, UniqueDevices, Devices,
    DeviceName, FileName, ProcessCommandLine`, 'KQL — Identity to Endpoint Lateral Movement')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Unified Portal Navigation</h4><p>Navigate the Microsoft 365 Defender portal. Understand unified incidents combining alerts from all workloads. Review the Secure Score. Explore each workload's dashboard.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Cross-Workload KQL Hunting</h4><p>Learn the tables from each workload. Write cross-workload queries using join. Correlate email, identity, endpoint, and cloud events. Save hunting queries as custom detections.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: AIR & Automation</h4><p>Configure AIR for each workload. Set remediation levels (full, semi, manual). Create automation rules for incident management. Integrate with Sentinel for extended SIEM.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Scenarios</h4><p>Build multi-stage attack detection queries. Configure custom detection rules. Use Threat Analytics reports. Optimize Secure Score recommendations.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Always hunt across workloads — an attack rarely stays in one domain (email -> endpoint -> identity -> cloud)</li><li>Use unified incidents to see the full attack scope before remediating</li><li>Enable AIR at "Full" level for high-confidence detections to speed up response</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Investigating alerts in isolation instead of using unified incident view</li><li>Not connecting all workloads — partial coverage means partial visibility</li><li>Not tuning Defender for Office 365 policies — either too aggressive (blocks legit email) or too lenient</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 21. TREND MICRO VISION ONE
// ─────────────────────────────────────────────────────
platformContent.visionone = {
    overview: `
        <h3>What is Trend Micro Vision One?</h3>
        <p>Vision One is Trend Micro's XDR platform that correlates data across email, endpoints, servers, cloud workloads, and networks. It uses Detection Models (YAML-based) for custom detection logic and the Workbench for collaborative investigation.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>DATA SOURCES</h4>
                <ul><li>Apex One — endpoint security</li><li>Cloud App Security — email/SaaS</li><li>Cloud One — cloud workloads</li><li>TippingPoint — network IPS</li><li>Deep Discovery — network sandbox</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY FEATURES</h4>
                <ul><li>Workbench — investigation workspace</li><li>Search queries — event hunting</li><li>Detection Models — custom YAML rules</li><li>Response actions — isolate, scan, block</li><li>Risk Insights — risk scoring</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Search Query 1: Suspicious Process Execution</h3>
        ${codeBlock(`eventId:1 AND
processFilePath:(*powershell* OR *cmd.exe* OR *mshta.exe*) AND
processCmd:(*encodedcommand* OR *downloadstring* OR *bypass*) AND
endpointHostName:*
| SELECT endpointHostName, processFilePath, processCmd,
    parentFilePath, userAccount, eventTimeDT`, 'Vision One Search — Suspicious Process')}

        <h3>Search Query 2: Network Anomaly</h3>
        ${codeBlock(`eventId:3 AND
dst:* AND NOT dst:(10.* OR 172.16.* OR 192.168.*) AND
dstPort:(4444 OR 5555 OR 8443 OR 1234) AND
endpointHostName:*
| GROUP BY endpointHostName, dst, dstPort
| HAVING count(*) > 5`, 'Vision One Search — Network Anomaly')}

        <h3>Detection Model (YAML)</h3>
        ${codeBlock(`name: "Suspicious LOLBin Execution Chain"
description: "Detects script host executing a LOLBin downloading content"
severity: high
mitre:
  tactic: execution
  technique: T1059
  subtechnique: T1059.005
data_source: endpoint
detection:
  filter_process_chain:
    parent_process_name:
      - wscript.exe
      - cscript.exe
      - mshta.exe
    process_name:
      - certutil.exe
      - bitsadmin.exe
      - curl.exe
    process_command_line|contains:
      - http
      - ftp
  condition: filter_process_chain
response:
  - alert
  - isolate_endpoint`, 'YAML — Vision One Detection Model')}

        <h3>Detection Model 2: Ransomware Behavior</h3>
        ${codeBlock(`name: "Ransomware Pre-Encryption Behavior"
description: "Detects shadow copy deletion followed by mass file modification"
severity: critical
mitre:
  tactic: impact
  technique: T1490
data_source: endpoint
detection:
  shadow_delete:
    process_name:
      - vssadmin.exe
      - wmic.exe
    process_command_line|contains:
      - "delete shadows"
      - "shadowcopy delete"
  mass_file_mod:
    event_type: file_rename
    threshold:
      count: 100
      window: 5m
  condition: shadow_delete AND mass_file_mod within 10m
response:
  - alert
  - isolate_endpoint
  - quarantine_process`, 'YAML — Ransomware Detection Model')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Vision One Console</h4><p>Navigate the Vision One console. Review Workbench alerts and investigations. Understand data sources and connected products. Explore Risk Insights.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Search & Hunting</h4><p>Learn the search query syntax. Hunt across endpoint, email, and network events. Build saved searches. Create custom detection models in YAML.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Response & Automation</h4><p>Configure response actions. Build automated response playbooks. Use the Workbench for collaborative investigation. Practice incident response workflows.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced</h4><p>Connect all Trend Micro products for full XDR visibility. Customize detection models. Build executive risk dashboards. Integrate with external SOAR via API.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Connect all Trend Micro products to Vision One for maximum correlation coverage</li><li>Use the Workbench for every investigation — it provides automatic evidence collection</li><li>Test Detection Models in alert-only mode before enabling response actions</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Only connecting one product — XDR value comes from cross-source correlation</li><li>Not reviewing Risk Insights regularly — they highlight configuration weaknesses</li><li>Creating Detection Models without sufficient testing — false positives trigger automated isolation</li></ul>
        </div>
    `
};

// ═══════════════════════════════════════════════════════
// SOAR PLATFORMS
// ═══════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────
// 22. SPLUNK SOAR (PHANTOM)
// ─────────────────────────────────────────────────────
platformContent.splunksoar = {
    overview: `
        <h3>What is Splunk SOAR?</h3>
        <p>Splunk SOAR (formerly Phantom) is a security orchestration, automation, and response platform. It uses Python-based playbooks to automate repetitive SOC tasks, integrates with 400+ security tools via pre-built apps, and provides a visual playbook editor for no-code/low-code automation.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE COMPONENTS</h4>
                <ul><li>Playbooks — Python automation workflows</li><li>Apps — integrations with security tools</li><li>Custom Functions — reusable Python code</li><li>Visual Playbook Editor — drag-and-drop</li><li>Case Management — investigation tracking</li><li>HUD — heads-up display dashboard</li></ul>
            </div>
            <div class="pc-info-card"><h4>AUTOMATION USE CASES</h4>
                <ul><li>Phishing triage and response</li><li>Threat intelligence enrichment</li><li>Endpoint isolation and remediation</li><li>Ticket creation and escalation</li><li>IOC blocking across firewalls</li><li>Vulnerability scan triggering</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Playbook Example 1: Phishing Triage (Python)</h3>
        ${codeBlock(`import phantom.rules as phantom
import json

def on_start(container):
    """Automated phishing email triage playbook"""
    # Extract indicators from email
    phantom.act("extract indicators", parameters=[{
        "input_type": "email",
        "input": container.get("data", {}).get("raw_email", "")
    }], callback=enrich_indicators)

def enrich_indicators(action, success, container, results, handle):
    """Enrich extracted IOCs with threat intelligence"""
    indicators = results.get_data()
    for indicator in indicators:
        if indicator.get("type") == "url":
            phantom.act("url reputation", target="VirusTotal",
                parameters=[{"url": indicator["value"]}],
                callback=evaluate_results)
        elif indicator.get("type") == "domain":
            phantom.act("domain reputation", target="VirusTotal",
                parameters=[{"domain": indicator["value"]}],
                callback=evaluate_results)
        elif indicator.get("type") == "hash":
            phantom.act("file reputation", target="VirusTotal",
                parameters=[{"hash": indicator["value"]}],
                callback=evaluate_results)

def evaluate_results(action, success, container, results, handle):
    """Evaluate enrichment results and take action"""
    data = results.get_data()
    if data and data[0].get("positives", 0) > 5:
        # Malicious — block and escalate
        phantom.act("block url", target="Firewall",
            parameters=[{"url": data[0]["resource"]}])
        phantom.act("create ticket", target="ServiceNow",
            parameters=[{
                "short_description": f"Malicious phishing detected: {container['name']}",
                "priority": "2 - High",
                "assignment_group": "SOC Tier 2"
            }])
        phantom.set_severity(container, "high")
        phantom.set_status(container, "open")
    else:
        # Clean — close the case
        phantom.add_note(container, "Automated analysis: No malicious indicators found")
        phantom.set_status(container, "closed")`, 'Python — Splunk SOAR Phishing Playbook')}

        <h3>Playbook Example 2: Endpoint Containment</h3>
        ${codeBlock(`import phantom.rules as phantom

def on_start(container):
    """Isolate compromised endpoint and collect forensic data"""
    hostname = container.get("data", {}).get("hostname", "")
    if not hostname:
        phantom.comment(container, "No hostname found in event")
        return

    # Step 1: Isolate the endpoint
    phantom.act("quarantine device", target="CrowdStrike",
        parameters=[{"hostname": hostname}],
        callback=collect_evidence)

def collect_evidence(action, success, container, results, handle):
    """Collect forensic artifacts from isolated host"""
    hostname = container.get("data", {}).get("hostname", "")
    # Collect running processes
    phantom.act("list processes", target="CrowdStrike",
        parameters=[{"hostname": hostname}],
        callback=analyze_processes)
    # Collect network connections
    phantom.act("list connections", target="CrowdStrike",
        parameters=[{"hostname": hostname}])
    # Get recent file changes
    phantom.act("list files", target="CrowdStrike",
        parameters=[{"hostname": hostname, "path": "C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp"}])

def analyze_processes(action, success, container, results, handle):
    """Check processes against threat intel"""
    processes = results.get_data()
    for proc in processes:
        if proc.get("sha256"):
            phantom.act("file reputation", target="VirusTotal",
                parameters=[{"hash": proc["sha256"]}])`, 'Python — Endpoint Containment Playbook')}

        <h3>Custom Function Example</h3>
        ${codeBlock(`def calculate_risk_score(indicators, **kwargs):
    """Custom function to calculate composite risk score from multiple indicators"""
    score = 0
    details = []
    for ind in indicators:
        if ind.get("vt_positives", 0) > 10:
            score += 40
            details.append(f"High VT score: {ind['value']} ({ind['vt_positives']})")
        elif ind.get("vt_positives", 0) > 3:
            score += 20
            details.append(f"Medium VT score: {ind['value']} ({ind['vt_positives']})")
        if ind.get("on_blocklist", False):
            score += 30
            details.append(f"On blocklist: {ind['value']}")
        if ind.get("first_seen_days", 999) < 7:
            score += 15
            details.append(f"Recently registered: {ind['value']}")
    return {"risk_score": min(score, 100), "details": details}`, 'Python — Custom Function')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: SOAR Concepts & Visual Editor</h4><p>Understand SOAR fundamentals: orchestration, automation, response. Navigate the Phantom UI. Build simple playbooks using the Visual Playbook Editor (no coding required). Connect your first app (e.g., VirusTotal).</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Python Playbooks</h4><p>Learn the Phantom Python API. Write playbooks that chain multiple actions. Handle callbacks and decision logic. Create custom functions for reusable code.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: App Integration</h4><p>Connect SIEM, EDR, firewall, ticketing, and email apps. Configure app assets with credentials. Test actions individually before building playbooks. Handle errors and retries.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Automation</h4><p>Build multi-stage playbooks for complex scenarios. Implement decision trees based on enrichment results. Create custom apps for unsupported tools. Measure automation ROI with metrics dashboards.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Start with high-volume, low-complexity use cases (phishing triage, IOC enrichment) for maximum ROI</li><li>Always include error handling in playbooks — a failed API call should not crash the entire workflow</li><li>Use custom functions for code reuse across playbooks</li><li>Test playbooks with synthetic events before connecting to live alert feeds</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Automating containment actions without human approval gates — accidentally isolates production servers</li><li>Not handling API rate limits — playbooks fail during high-volume events</li><li>Building overly complex playbooks — keep them modular and chain them together</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 23. SENTINEL SOAR
// ─────────────────────────────────────────────────────
platformContent.sentinelsoar = {
    overview: `
        <h3>What is Sentinel SOAR?</h3>
        <p>Microsoft Sentinel's SOAR capabilities are built on Azure Logic Apps. Playbooks are triggered by analytics rules or automation rules and can perform actions across any service with an API. Automation rules provide lightweight if/then logic for incident management without full playbook complexity.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>AUTOMATION TYPES</h4>
                <ul><li><strong>Playbooks</strong> — Logic Apps triggered by incidents/alerts</li><li><strong>Automation Rules</strong> — lightweight incident management</li><li><strong>Playbook Templates</strong> — pre-built from Content Hub</li></ul>
            </div>
            <div class="pc-info-card"><h4>COMMON TRIGGERS</h4>
                <ul><li>When a Sentinel incident is created</li><li>When a Sentinel alert is triggered</li><li>When an entity is triggered</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Playbook 1: Enrich Incident with IP Geolocation</h3>
        ${codeBlock(`{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "body": { "callback_url": "@{listCallbackUrl()}" },
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Entities_-_Get_IPs": {
        "type": "ApiConnection",
        "inputs": { "path": "/entities/ip" }
      },
      "For_each_IP": {
        "type": "Foreach",
        "foreach": "@body('Entities_-_Get_IPs')?['IPs']",
        "actions": {
          "HTTP_GeoIP_Lookup": {
            "type": "Http",
            "inputs": {
              "method": "GET",
              "uri": "https://ipapi.co/@{items('For_each_IP')?['Address']}/json/"
            }
          },
          "Add_comment_to_incident": {
            "type": "ApiConnection",
            "inputs": {
              "body": {
                "incidentArmId": "@triggerBody()?['object']?['id']",
                "message": "IP @{items('For_each_IP')?['Address']}: Country=@{body('HTTP_GeoIP_Lookup')?['country_name']}, City=@{body('HTTP_GeoIP_Lookup')?['city']}, ISP=@{body('HTTP_GeoIP_Lookup')?['org']}"
              },
              "path": "/Incidents/Comment"
            }
          }
        }
      }
    }
  }
}`, 'JSON — Logic App: IP Geolocation Enrichment')}

        <h3>Playbook 2: Block IP on Firewall and Notify Teams</h3>
        ${codeBlock(`// Automation Rule + Playbook pattern
// Step 1: Automation Rule triggers on High severity incidents
// Step 2: Playbook extracts IP entities and blocks them

// Playbook pseudo-logic:
Trigger: Sentinel Incident Created
  -> Get Incident Entities (filter: IP addresses)
  -> For Each IP:
     -> Check against allowlist (Azure Table Storage)
     -> If NOT allowlisted:
        -> Block IP on Palo Alto Firewall (API call)
        -> Block IP on Azure NSG (Azure Resource Manager)
        -> Add to Sentinel TI watchlist
     -> Post to Teams Channel:
        "Blocked IP {ip} from incident {incident_number}
         Reason: {incident_title}
         Severity: {severity}"
  -> Update incident: Add tag "auto-blocked"
  -> Change incident status to "Active"`, 'Pseudo-Logic — Block & Notify Playbook')}

        <h3>Automation Rule Example</h3>
        ${codeBlock(`{
  "displayName": "Auto-assign high severity incidents to Tier 2",
  "order": 1,
  "triggeringLogic": {
    "isEnabled": true,
    "triggersOn": "Incidents",
    "triggersWhen": "Created",
    "conditions": [
      {
        "conditionType": "Property",
        "conditionProperties": {
          "propertyName": "IncidentSeverity",
          "operator": "Equals",
          "propertyValues": ["High", "Critical"]
        }
      }
    ]
  },
  "actions": [
    {
      "actionType": "ModifyProperties",
      "actionConfiguration": {
        "owner": "soc-tier2@company.com",
        "status": "Active"
      }
    },
    {
      "actionType": "RunPlaybook",
      "actionConfiguration": {
        "playbookResourceId": "/subscriptions/.../playbooks/Enrich-Incident-IPs"
      }
    }
  ]
}`, 'JSON — Sentinel Automation Rule')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Automation Rules</h4><p>Start with automation rules for simple incident management: auto-assignment, auto-tagging, severity adjustment. No coding required. Configure incident-triggered actions.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Logic App Playbooks</h4><p>Build playbooks using the Logic App designer. Use Sentinel connectors for incident and entity operations. Connect external services (Teams, Email, ServiceNow). Test with synthetic incidents.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Content Hub Templates</h4><p>Deploy playbook templates from Content Hub solutions. Customize templates for your environment. Chain multiple playbooks together.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Automation</h4><p>Build complex Logic Apps with conditional branches, loops, and parallel actions. Use Azure Functions for custom code. Monitor playbook runs and handle failures. Measure MTTR improvement.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use automation rules for simple actions, playbooks for complex multi-step workflows</li><li>Always test playbooks with a synthetic incident before enabling on live alerts</li><li>Use managed identities for playbook authentication instead of storing credentials</li><li>Monitor Logic App run history for failures — failed playbooks mean missed responses</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not setting up error handling in Logic Apps — one failed step stops the entire playbook</li><li>Triggering expensive playbooks on low-severity incidents — wastes Logic App run costs</li><li>Not using the "Run after" setting to handle failures gracefully</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 24. PALO ALTO XSOAR
// ─────────────────────────────────────────────────────
platformContent.xsoar = {
    overview: `
        <h3>What is Palo Alto XSOAR?</h3>
        <p>Cortex XSOAR (formerly Demisto) is an enterprise SOAR platform with 700+ integrations, YAML-based playbooks, a collaborative War Room for investigations, and a marketplace for pre-built content packs. It features indicator management, case management, and machine learning-based automation recommendations.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>YAML Playbooks — automation workflows</li><li>War Room — collaborative investigation</li><li>Indicator Management — IOC lifecycle</li><li>700+ Integrations</li><li>Marketplace — content packs</li><li>ML-based automation suggestions</li></ul>
            </div>
            <div class="pc-info-card"><h4>PLAYBOOK TYPES</h4>
                <ul><li><strong>Main Playbook</strong> — entry point for incident type</li><li><strong>Sub-Playbook</strong> — reusable workflow components</li><li><strong>Task</strong> — individual action or manual step</li><li><strong>Conditional Task</strong> — decision branching</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>XSOAR Playbook Example (YAML): Phishing Investigation</h3>
        ${codeBlock(`id: Phishing-Investigation
version: 1
name: Phishing Investigation
description: Automated phishing email analysis and response
starttaskid: "0"
tasks:
  "0":
    id: "0"
    taskid: extract-indicators
    type: regular
    task:
      id: extract-indicators
      name: Extract Indicators from Email
      script: ExtractIndicatorsFromEmailBody
    nexttasks:
      '#none#':
        - "1"

  "1":
    id: "1"
    taskid: enrich-indicators
    type: playbook
    task:
      id: enrich-indicators
      name: Indicator Enrichment
      playbookId: Enrich-Indicators-Sub-Playbook
    nexttasks:
      '#none#':
        - "2"

  "2":
    id: "2"
    taskid: evaluate-severity
    type: condition
    task:
      id: evaluate-severity
      name: Is this malicious?
    conditions:
      - label: "Malicious"
        condition:
          - - operator: greaterThan
              left: { value: { simple: "VirusTotal.Score" } }
              right: { value: { simple: "5" } }
      - label: "Clean"
    nexttasks:
      "Malicious":
        - "3"
      "Clean":
        - "4"

  "3":
    id: "3"
    taskid: block-and-remediate
    type: regular
    task:
      id: block-and-remediate
      name: Block IOCs and Quarantine Email
      scriptName: BlockIndicators
    nexttasks:
      '#none#':
        - "5"

  "4":
    id: "4"
    taskid: close-clean
    type: regular
    task:
      id: close-clean
      name: Close as False Positive
      script: CloseInvestigation
      args:
        closeReason: "False Positive"

  "5":
    id: "5"
    taskid: escalate
    type: regular
    task:
      id: escalate
      name: Create Ticket and Notify SOC
      script: ServiceNow-CreateTicket
      args:
        priority: "2"
        assignment_group: "SOC Tier 2"`, 'YAML — XSOAR Phishing Playbook')}

        <h3>Integration Command Examples</h3>
        ${codeBlock(`# VirusTotal lookup
!vt-ip-report ip=8.8.8.8

# CrowdStrike host search
!cs-falcon-search-device filter="hostname:'workstation01'"

# Active Directory disable user
!ad-disable-account username=compromised.user

# Firewall block IP
!pan-os-block-ip ip=203.0.113.50 log_forwarding=default

# ServiceNow create ticket
!servicenow-create-ticket short_description="Phishing Incident" priority=2

# Slack notification
!slack-send channel=#soc-alerts message="New high-severity phishing incident detected"`, 'XSOAR CLI — Integration Commands')}

        <h3>Custom Script Example (Python)</h3>
        ${codeBlock(`def main():
    """Calculate composite threat score from multiple enrichments"""
    vt_score = demisto.get(demisto.context(), 'VirusTotal.Score') or 0
    abuseipdb_score = demisto.get(demisto.context(), 'AbuseIPDB.Confidence') or 0
    is_on_blocklist = demisto.get(demisto.context(), 'ThreatIntel.OnBlocklist') or False

    composite_score = (int(vt_score) * 0.4) + (int(abuseipdb_score) * 0.3)
    if is_on_blocklist:
        composite_score += 30

    severity = "low"
    if composite_score > 70: severity = "critical"
    elif composite_score > 50: severity = "high"
    elif composite_score > 30: severity = "medium"

    return_results(CommandResults(
        outputs_prefix='ThreatScore',
        outputs={'Score': composite_score, 'Severity': severity},
        readable_output=f"Composite Threat Score: {composite_score} ({severity})"
    ))

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()`, 'Python — XSOAR Custom Script')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: XSOAR Basics</h4><p>Navigate the XSOAR UI. Understand incidents, indicators, and the War Room. Run manual commands against integrations. Review pre-built playbooks from the marketplace.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Playbook Building</h4><p>Build playbooks using the visual editor. Create conditional branches. Use sub-playbooks for modular design. Test playbooks with the debugger.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Custom Scripts & Integrations</h4><p>Write Python automation scripts. Create custom integrations for unsupported tools. Build indicator extraction scripts. Deploy content packs.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced</h4><p>Implement ML-based automation suggestions. Build executive SOC dashboards. Integrate with CI/CD for content-as-code. Measure automation metrics (MTTR, cases/hour).</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use sub-playbooks for reusable components (enrichment, notification, containment)</li><li>Always include manual approval tasks before destructive actions (block, isolate, disable)</li><li>Use the War Room for collaborative investigation with your team</li><li>Deploy content packs from the marketplace before building custom playbooks</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Building monolithic playbooks instead of modular sub-playbooks</li><li>Not handling integration errors — a failed API call should branch to a manual task, not crash</li><li>Automating containment without human-in-the-loop for critical assets</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 25. QRADAR SOAR (RESILIENT)
// ─────────────────────────────────────────────────────
platformContent.qradarsoar = {
    overview: `
        <h3>What is QRadar SOAR (Resilient)?</h3>
        <p>IBM QRadar SOAR (formerly IBM Resilient) is an incident response and SOAR platform with dynamic playbooks that adapt based on incident data. It features custom functions (Python), data tables for structured investigation data, and deep integration with QRadar SIEM.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>Dynamic Playbooks — adaptive workflows</li><li>Custom Functions — Python automation</li><li>Data Tables — structured incident data</li><li>Rules & Conditions — trigger logic</li><li>Action Module — pre-built integrations</li><li>Breach Response Module</li></ul>
            </div>
            <div class="pc-info-card"><h4>KEY CONCEPTS</h4>
                <ul><li><code>Incident</code> — case with phases</li><li><code>Tasks</code> — actions within a phase</li><li><code>Artifacts</code> — IOCs and evidence</li><li><code>Playbooks</code> — automated task flows</li><li><code>Functions</code> — API integrations</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Custom Function: Enrich IP Address</h3>
        ${codeBlock(`# QRadar SOAR Custom Function - enrich_ip.py
from resilient_lib import ResultPayload, validate_fields
import requests

def enrich_ip_function(event, *args, **kwargs):
    """Enrich an IP address with threat intelligence"""
    validate_fields(["ip_address"], kwargs)
    ip_address = kwargs.get("ip_address")

    rp = ResultPayload("fn_enrich_ip")

    # Check VirusTotal
    vt_response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
        headers={"x-apikey": kwargs.get("vt_api_key")}
    )
    vt_data = vt_response.json() if vt_response.ok else {}

    # Check AbuseIPDB
    abuse_response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip_address},
        headers={"Key": kwargs.get("abuse_api_key"), "Accept": "application/json"}
    )
    abuse_data = abuse_response.json() if abuse_response.ok else {}

    results = {
        "ip_address": ip_address,
        "vt_malicious": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
        "abuse_score": abuse_data.get("data", {}).get("abuseConfidenceScore", 0),
        "country": abuse_data.get("data", {}).get("countryCode", "Unknown"),
        "isp": abuse_data.get("data", {}).get("isp", "Unknown")
    }

    return rp.done(True, results)`, 'Python — QRadar SOAR Custom Function')}

        <h3>Playbook Rule Example</h3>
        ${codeBlock(`{
  "name": "Auto-Enrich Artifacts on Incident Creation",
  "object_type": "incident",
  "conditions": {
    "all": [
      { "field": "incident.severity_code", "operator": "gte", "value": 2 },
      { "field": "incident.incident_type_ids", "operator": "contains", "value": "Phishing" }
    ]
  },
  "actions": [
    {
      "type": "run_function",
      "function_name": "fn_enrich_ip",
      "inputs": { "ip_address": "artifact.value" },
      "for_each": "artifact WHERE type = 'IP Address'"
    },
    {
      "type": "add_task",
      "task_name": "Review enrichment results",
      "phase": "Investigation",
      "assigned_to": "SOC Tier 2"
    }
  ]
}`, 'JSON — QRadar SOAR Rule')}

        <h3>Dynamic Playbook Structure</h3>
        ${codeBlock(`Playbook: Phishing Incident Response
├── Phase 1: Detection & Triage
│   ├── [Auto] Extract indicators from email
│   ├── [Auto] Enrich URLs with VirusTotal
│   ├── [Auto] Enrich domains with WHOIS
│   └── [Manual] Analyst reviews enrichment
├── Phase 2: Containment
│   ├── [Conditional] If malicious:
│   │   ├── [Auto] Block URLs on proxy
│   │   ├── [Auto] Quarantine email from all mailboxes
│   │   └── [Auto] Block sender domain
│   └── [Conditional] If suspicious:
│       └── [Manual] Analyst decision
├── Phase 3: Eradication
│   ├── [Auto] Search for related emails
│   ├── [Manual] Check for credential compromise
│   └── [Manual] Reset passwords if needed
└── Phase 4: Recovery & Lessons Learned
    ├── [Auto] Generate incident report
    ├── [Manual] Update detection rules
    └── [Auto] Close incident`, 'Text — Dynamic Playbook Structure')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Incident Management</h4><p>Learn the incident lifecycle. Create and manage incidents manually. Add artifacts and notes. Understand phases, tasks, and data tables.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Playbooks & Rules</h4><p>Build dynamic playbooks. Create rules with conditions. Configure automatic task creation. Set up phase transitions.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Custom Functions</h4><p>Write Python custom functions. Integrate external APIs. Deploy functions to the app host. Test with sample incidents.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: QRadar Integration</h4><p>Connect QRadar SIEM offenses to SOAR incidents. Build bi-directional workflows. Configure the Breach Response module. Build compliance reports.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use dynamic playbooks that adapt based on incident type, severity, and artifact enrichment</li><li>Structure playbooks into clear phases: Detect, Contain, Eradicate, Recover</li><li>Use data tables to track investigation findings in structured format</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Creating static playbooks that don't adapt to incident context</li><li>Not linking QRadar offenses to SOAR incidents — manual duplication wastes time</li><li>Building custom functions without error handling — API failures should be logged, not crash the function</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 26. SHUFFLE (Open-Source SOAR)
// ─────────────────────────────────────────────────────
platformContent.shuffle = {
    overview: `
        <h3>What is Shuffle?</h3>
        <p>Shuffle is an open-source SOAR platform built on Docker. It features a drag-and-drop workflow editor, automatic app generation from OpenAPI specifications, and native integration with Wazuh. Shuffle is free to self-host and provides a low-barrier entry point for SOC automation.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>Drag-and-drop workflow editor</li><li>OpenAPI-based app generation</li><li>Docker-based architecture</li><li>Webhook triggers</li><li>Wazuh native integration</li><li>App library with 100+ integrations</li></ul>
            </div>
            <div class="pc-info-card"><h4>ARCHITECTURE</h4>
                <ul><li>Frontend — React web UI</li><li>Backend — Go API server</li><li>Orborus — workflow execution engine</li><li>Apps — Docker containers</li><li>OpenSearch — data storage</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Workflow 1: Wazuh Alert Enrichment</h3>
        ${codeBlock(`Workflow: Wazuh Alert Enrichment
Trigger: Wazuh Webhook (alert level >= 10)

Steps:
1. [Trigger] Receive Wazuh alert via webhook
   Input: alert JSON with agent, rule, data fields

2. [HTTP App] Extract source IP from alert
   Action: Parse alert.data.srcip

3. [VirusTotal App] Check IP reputation
   Action: /api/v3/ip_addresses/{ip}
   Input: extracted source IP

4. [AbuseIPDB App] Check abuse reports
   Action: /api/v2/check
   Input: extracted source IP

5. [Condition] Is IP malicious?
   If VT.malicious > 3 OR AbuseIPDB.score > 50:
     -> Step 6 (Block)
   Else:
     -> Step 7 (Log only)

6. [Wazuh App] Trigger active response
   Action: PUT /active-response
   Body: {"command": "firewall-drop", "arguments": ["{ip}"], "alert": {...}}

7. [TheHive App] Create alert in TheHive
   Action: POST /api/alert
   Body: {"title": "Wazuh Alert: {rule.description}", "severity": 2}

8. [Slack App] Notify SOC channel
   Action: POST /api/chat.postMessage
   Body: {"channel": "#soc-alerts", "text": "Alert: {summary}"}`, 'Workflow — Wazuh Alert Enrichment')}

        <h3>Workflow 2: IOC Enrichment Pipeline</h3>
        ${codeBlock(`Workflow: Multi-Source IOC Enrichment
Trigger: HTTP Webhook (receives list of IOCs)

Steps:
1. [Trigger] Receive IOC list
   Input: {"iocs": [{"type": "ip", "value": "1.2.3.4"}, ...]}

2. [Loop] For each IOC:
   2a. [Condition] Check IOC type
       If type == "ip":
         -> VirusTotal IP lookup
         -> AbuseIPDB check
         -> Shodan host lookup
       If type == "domain":
         -> VirusTotal domain lookup
         -> WHOIS lookup
         -> URLhaus check
       If type == "hash":
         -> VirusTotal file lookup
         -> MalwareBazaar check
         -> Hybrid Analysis lookup

3. [HTTP App] Aggregate results
   Combine all enrichment results per IOC
   Calculate composite risk score

4. [TheHive App] Create case if high risk
   If any IOC risk_score > 70:
     Create case with all enriched IOCs

5. [Email App] Send enrichment report
   To: soc-team@company.com
   Body: Formatted enrichment summary`, 'Workflow — IOC Enrichment Pipeline')}

        <h3>Docker Deployment</h3>
        ${codeBlock(`# docker-compose.yml for Shuffle
version: '3'
services:
  frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    ports: ["3001:80"]
    environment:
      - BACKEND_HOSTNAME=shuffle-backend

  backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    ports: ["5001:5001"]
    environment:
      - SHUFFLE_OPENSEARCH_URL=http://shuffle-opensearch:9200
      - SHUFFLE_DEFAULT_USERNAME=admin
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    environment:
      - SHUFFLE_WORKER_VERSION=latest
      - BASE_URL=http://shuffle-backend:5001
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  opensearch:
    image: opensearchproject/opensearch:2.5.0
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true`, 'YAML — Docker Compose Deployment')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: Deployment & Basics</h4><p>Deploy Shuffle with Docker Compose. Navigate the UI. Build your first workflow with HTTP triggers. Connect a Wazuh instance.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: App Integration</h4><p>Install apps from the library. Generate custom apps from OpenAPI specs. Configure app authentication. Chain multiple apps in workflows.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Advanced Workflows</h4><p>Build conditional logic and loops. Use subflows for modular design. Implement webhook triggers from SIEM alerts. Handle errors and retries.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Production Hardening</h4><p>Configure HTTPS and authentication. Set up backup and recovery. Monitor workflow execution metrics. Scale with multiple Orborus workers.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Start with Wazuh alert enrichment — the native integration makes it easy</li><li>Use OpenAPI specs to auto-generate apps for tools that don't have pre-built integrations</li><li>Keep workflows simple and modular — chain subflows together for complex scenarios</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not mounting Docker socket — Orborus cannot launch app containers</li><li>Building one massive workflow instead of modular subflows</li><li>Not configuring webhook authentication — anyone can trigger your workflows</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 27. THEHIVE + CORTEX
// ─────────────────────────────────────────────────────
platformContent.thehive = {
    overview: `
        <h3>What is TheHive + Cortex?</h3>
        <p>TheHive is an open-source Security Incident Response Platform (SIRP) for case management. Cortex is its companion analysis engine that runs analyzers (enrichment) and responders (automated actions) against observables. Together they provide a complete investigation and response workflow.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>THEHIVE FEATURES</h4>
                <ul><li>Case management with tasks</li><li>Alert intake from SIEM/SOAR</li><li>Observable (IOC) management</li><li>Custom dashboards</li><li>Multi-organization support</li><li>MISP integration for threat sharing</li></ul>
            </div>
            <div class="pc-info-card"><h4>CORTEX CAPABILITIES</h4>
                <ul><li>100+ Analyzers (VirusTotal, MISP, Shodan, etc.)</li><li>Responders (block IP, disable user, etc.)</li><li>Automatic analysis on observable creation</li><li>API for custom analyzer development</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Cortex Analyzer: Custom IP Enrichment</h3>
        ${codeBlock(`#!/usr/bin/env python3
# Custom Cortex Analyzer - enrich_ip_analyzer.py
from cortexutils.analyzer import Analyzer
import requests

class IPEnrichAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.vt_api_key = self.get_param('config.vt_api_key', None, 'VT API key required')

    def run(self):
        if self.data_type != 'ip':
            self.error('Invalid data type. Expected: ip')

        ip = self.get_data()

        # VirusTotal check
        vt = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.vt_api_key}).json()

        malicious = vt.get('data', {}).get('attributes', {}).get(
            'last_analysis_stats', {}).get('malicious', 0)

        # AbuseIPDB check
        abuse = requests.get("https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip},
            headers={"Key": self.get_param('config.abuse_api_key')}).json()

        self.report({
            'ip': ip,
            'vt_malicious': malicious,
            'abuse_score': abuse.get('data', {}).get('abuseConfidenceScore', 0),
            'country': abuse.get('data', {}).get('countryCode', 'N/A'),
            'risk_level': 'high' if malicious > 5 else 'medium' if malicious > 0 else 'low'
        })

    def summary(self, raw):
        taxonomies = []
        level = 'malicious' if raw.get('vt_malicious', 0) > 5 else 'suspicious' if raw.get('vt_malicious', 0) > 0 else 'safe'
        taxonomies.append(self.build_taxonomy(level, 'VT', 'Malicious', raw.get('vt_malicious', 0)))
        return {'taxonomies': taxonomies}

if __name__ == '__main__':
    IPEnrichAnalyzer().run()`, 'Python — Custom Cortex Analyzer')}

        <h3>Cortex Responder: Block IP on Firewall</h3>
        ${codeBlock(`#!/usr/bin/env python3
# Custom Cortex Responder - block_ip_responder.py
from cortexutils.responder import Responder
import requests

class BlockIPResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.firewall_url = self.get_param('config.firewall_url')
        self.firewall_key = self.get_param('config.firewall_api_key')

    def run(self):
        if self.get_param('data.dataType') != 'ip':
            self.error('Can only block IP addresses')

        ip = self.get_param('data.data')

        response = requests.post(
            f"{self.firewall_url}/api/block",
            headers={"Authorization": f"Bearer {self.firewall_key}"},
            json={"ip": ip, "action": "block", "duration": "24h",
                  "reason": f"Blocked by TheHive case #{self.get_param('data.case.caseId')}"}
        )

        if response.ok:
            self.report({'message': f'Successfully blocked IP {ip}', 'status': 'success'})
        else:
            self.error(f'Failed to block IP: {response.text}')

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='ip-blocked')]

if __name__ == '__main__':
    BlockIPResponder().run()`, 'Python — Custom Cortex Responder')}

        <h3>TheHive Alert Creation via API</h3>
        ${codeBlock(`# Create alert in TheHive from SIEM
curl -X POST "https://thehive:9000/api/alert" \\
  -H "Authorization: Bearer <api_key>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "type": "wazuh",
    "source": "Wazuh SIEM",
    "sourceRef": "alert-12345",
    "title": "Brute Force Attack Detected",
    "description": "10+ failed SSH logins from 203.0.113.50",
    "severity": 3,
    "tags": ["brute-force", "ssh", "T1110"],
    "artifacts": [
      { "dataType": "ip", "data": "203.0.113.50", "message": "Source IP" },
      { "dataType": "hostname", "data": "web-server-01", "message": "Target host" }
    ]
  }'`, 'cURL — TheHive Alert API')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: TheHive Setup & Case Management</h4><p>Deploy TheHive (Docker or packages). Create organizations and users. Manage cases, tasks, and observables. Set up alert templates for different incident types.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Cortex Analyzers</h4><p>Deploy Cortex alongside TheHive. Enable analyzers (VirusTotal, MISP, Shodan, AbuseIPDB). Configure auto-analysis rules. Review analysis reports in TheHive.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Responders & MISP</h4><p>Enable Cortex responders for automated actions. Integrate MISP for threat intelligence sharing. Build alert-to-case promotion workflows. Configure notification channels.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Custom Development</h4><p>Write custom analyzers in Python. Build custom responders. Integrate with Wazuh/Shuffle for end-to-end automation. Deploy in production with authentication and TLS.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Use alert templates for consistent incident categorization</li><li>Enable auto-analysis for common observable types (IP, domain, hash)</li><li>Integrate MISP for bidirectional threat intelligence sharing</li><li>Use case templates with pre-defined tasks for consistent response procedures</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Not configuring analyzer rate limits — VirusTotal free tier has 4 requests/minute</li><li>Running TheHive without authentication in production — exposed case data</li><li>Not backing up Elasticsearch/Cassandra data — loss of all investigation history</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 28. FORTISOAR
// ─────────────────────────────────────────────────────
platformContent.fortisoar = {
    overview: `
        <h3>What is FortiSOAR?</h3>
        <p>FortiSOAR is Fortinet's security orchestration platform with a visual playbook designer, 300+ connectors, and solution packs for pre-built use cases. It features a recommendation engine that suggests automation actions based on historical analyst behavior, and natively integrates with the Fortinet Security Fabric.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>CORE FEATURES</h4>
                <ul><li>Visual Playbook Designer</li><li>300+ Connectors</li><li>Solution Packs — pre-built content</li><li>Recommendation Engine</li><li>Multi-Tenant Support</li><li>Role-Based Access Control</li></ul>
            </div>
            <div class="pc-info-card"><h4>FORTINET INTEGRATION</h4>
                <ul><li>FortiGate — firewall blocking</li><li>FortiSIEM — alert ingestion</li><li>FortiEDR — endpoint response</li><li>FortiMail — email security</li><li>FortiAnalyzer — log analytics</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Playbook Example: Phishing Response</h3>
        ${codeBlock(`Playbook: Phishing Email Response
Trigger: Alert created with type "Phishing"

Steps:
1. [Extract Indicators]
   - Parse email headers, body, attachments
   - Extract URLs, domains, IPs, file hashes

2. [Enrich Indicators] (parallel)
   - VirusTotal: URL/domain/hash reputation
   - FortiGuard: URL/domain categorization
   - AbuseIPDB: IP reputation
   - WHOIS: Domain registration age

3. [Calculate Risk Score]
   - Composite score from all enrichments
   - Apply organizational risk weights

4. [Decision Branch]
   If risk_score >= 70 (Malicious):
     a. Block URL on FortiGate web filter
     b. Block sender domain on FortiMail
     c. Search and quarantine matching emails
     d. Create Jira ticket for SOC Tier 2
     e. Notify via Teams/Slack
   If risk_score 30-69 (Suspicious):
     a. Add to monitoring watchlist
     b. Create ticket for analyst review
   If risk_score < 30 (Clean):
     a. Close alert as false positive
     b. Add sender to allowlist

5. [Update Records]
   - Update alert with enrichment data
   - Link related indicators to alert
   - Record actions taken in audit log`, 'Text — FortiSOAR Phishing Playbook')}

        <h3>Connector Configuration: FortiGate</h3>
        ${codeBlock(`{
  "connector": "fortigate-firewall",
  "version": "3.0.0",
  "config": {
    "server_url": "https://fortigate.company.com",
    "api_key": "{{env.FORTIGATE_API_KEY}}",
    "verify_ssl": true
  },
  "actions": [
    {
      "name": "block_ip",
      "description": "Add IP to FortiGate address object and firewall policy",
      "parameters": {
        "ip_address": "string",
        "address_group": "Blocked_IPs",
        "comment": "Blocked by FortiSOAR playbook"
      }
    },
    {
      "name": "block_url",
      "description": "Add URL to FortiGate web filter block list",
      "parameters": {
        "url": "string",
        "category": "Malicious Websites"
      }
    }
  ]
}`, 'JSON — FortiGate Connector Config')}

        <h3>Solution Pack: Incident Response</h3>
        ${codeBlock(`# FortiSOAR Solution Pack contents:
solution_pack:
  name: "SOC Incident Response"
  version: "2.1.0"
  contents:
    playbooks:
      - Phishing_Response_v2
      - Malware_Alert_Triage
      - Brute_Force_Response
      - Data_Exfiltration_Investigation
      - Ransomware_Response
    connectors:
      - fortigate-firewall
      - fortisiem
      - fortiedr
      - virustotal
      - servicenow
    dashboards:
      - SOC_Operations_Dashboard
      - Incident_Metrics
      - Automation_ROI
    record_sets:
      - alert_types
      - severity_mappings
      - escalation_matrix`, 'YAML — Solution Pack Structure')}
    `,

    training: `
        <h3>Zero-to-Hero Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Week 1-2: FortiSOAR UI & Module Navigation</h4><p>Navigate the FortiSOAR interface. Understand modules (Alerts, Incidents, Indicators, Assets). Create and manage records. Review pre-built dashboards.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Week 3-4: Playbook Designer</h4><p>Build playbooks with the visual editor. Add actions, conditions, and loops. Configure connectors for your security tools. Test playbooks with sample data.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Week 5-6: Solution Packs & Connectors</h4><p>Deploy solution packs for common use cases. Configure Fortinet Security Fabric connectors. Customize pre-built playbooks for your environment.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Week 7-8: Advanced Automation</h4><p>Use the recommendation engine. Build multi-tenant configurations. Create custom connectors. Measure automation ROI with built-in dashboards.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Start with Solution Packs — they provide tested playbooks for common use cases</li><li>Leverage the Fortinet Security Fabric integration for native blocking and enrichment</li><li>Use the recommendation engine to identify automation opportunities</li></ul>
        </div>
        <div class="pc-warning"><h4>COMMON MISTAKES</h4>
            <ul><li>Building custom playbooks when a Solution Pack already covers the use case</li><li>Not testing connector credentials before using them in production playbooks</li><li>Ignoring the recommendation engine — it learns from analyst behavior to suggest automations</li></ul>
        </div>
    `
};

// ═══════════════════════════════════════════════════════
// BLUE TEAM OPS
// ═══════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────
// 29. USE CASE LIBRARY
// ─────────────────────────────────────────────────────
platformContent.usecases = {
    overview: `
        <h3>Detection Use Case Library</h3>
        <p>A curated library of detection use cases mapped to MITRE ATT&CK, each with multi-SIEM query examples, false positive guidance, and response recommendations. These use cases form the foundation of a mature detection engineering program.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>USE CASE STRUCTURE</h4>
                <ul><li>MITRE ATT&CK mapping</li><li>Description and detection logic</li><li>Multi-SIEM queries (SPL, KQL, AQL)</li><li>False positive scenarios</li><li>Response actions</li><li>Severity rating</li></ul>
            </div>
            <div class="pc-info-card"><h4>COVERAGE AREAS</h4>
                <ul><li>Authentication attacks</li><li>Malware execution</li><li>Lateral movement</li><li>Data exfiltration</li><li>Privilege escalation</li><li>Persistence mechanisms</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Use Case 1: Brute Force Authentication (T1110)</h3>
        <p><strong>Description:</strong> Detect 10+ failed login attempts from a single source within 5 minutes, followed by a successful login.</p>
        ${codeBlock(`-- SPLUNK SPL:
index=wineventlog EventCode IN (4624,4625)
| stats count(eval(EventCode=4625)) AS fails, count(eval(EventCode=4624)) AS success by src_ip, user
| where fails >= 10 AND success > 0

-- SENTINEL KQL:
SecurityEvent
| where EventID in (4624, 4625) and TimeGenerated > ago(5m)
| summarize Fails=countif(EventID==4625), Success=countif(EventID==4624) by IpAddress, Account
| where Fails >= 10 and Success > 0

-- QRADAR AQL:
SELECT sourceip, username, COUNT(*) FROM events
WHERE eventid IN (4624,4625) AND starttime > NOW()-300000
GROUP BY sourceip, username
HAVING SUM(CASE WHEN eventid=4625 THEN 1 ELSE 0 END) >= 10
AND SUM(CASE WHEN eventid=4624 THEN 1 ELSE 0 END) >= 1`, 'Multi-SIEM — Brute Force Detection')}
        <p><strong>False Positives:</strong> Legitimate users with caps lock, password expiry prompts, service account password rotation.</p>

        <h3>Use Case 2: Suspicious PowerShell (T1059.001)</h3>
        ${codeBlock(`-- SPLUNK SPL:
index=wineventlog EventCode=4688 New_Process_Name="*powershell*"
| where match(Process_Command_Line, "(?i)(enc|downloadstring|bypass|iex|frombase64)")

-- SENTINEL KQL:
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("enc","downloadstring","bypass","iex")

-- ELASTIC EQL:
process where process.name == "powershell.exe" and
  process.command_line regex "(?i).*(enc|downloadstring|bypass).*"`, 'Multi-SIEM — PowerShell Detection')}

        <h3>Use Case 3: Kerberoasting (T1558.003)</h3>
        ${codeBlock(`-- SPLUNK SPL:
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="krbtgt"
| stats count by Service_Name, Account_Name, Client_Address
| where count > 3

-- SENTINEL KQL:
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| where ServiceName != "krbtgt"
| summarize Count=count() by ServiceName, TargetAccount, IpAddress
| where Count > 3

-- WAZUH XML:
<rule id="100100" level="12">
  <if_sid>60106</if_sid>
  <field name="win.system.eventID">4769</field>
  <field name="win.eventdata.ticketEncryptionType">0x17</field>
  <description>Potential Kerberoasting: RC4 TGS request for $(win.eventdata.serviceName)</description>
  <mitre><id>T1558.003</id></mitre>
</rule>`, 'Multi-SIEM — Kerberoasting')}

        <h3>Use Case 4: DCSync Attack (T1003.006)</h3>
        ${codeBlock(`-- SPLUNK SPL:
index=wineventlog EventCode=4662
  Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR
  Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| stats count by Account_Name, src_ip
| where NOT match(Account_Name, "(?i)(machine\\$|dc\\$)")

-- SENTINEL KQL:
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"`, 'Multi-SIEM — DCSync Detection')}

        <h3>Use Case 5: DNS Tunneling (T1048.003)</h3>
        ${codeBlock(`-- SPLUNK SPL:
index=dns | eval query_len=len(query) | stats count, avg(query_len) as avg_len by domain
| where avg_len > 40 AND count > 50

-- SENTINEL KQL:
DnsEvents
| extend QueryLen = strlen(Name)
| summarize Count=count(), AvgLen=avg(QueryLen) by DomainName=extract("([^.]+\\\\.[^.]+)$",1,Name)
| where AvgLen > 40 and Count > 50

-- CHRONICLE YARA-L:
rule dns_tunneling {
  events: $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name = $q
    strings.length($q) > 50
  match: $dns.principal.ip over 30m
  condition: #dns >= 50
}`, 'Multi-SIEM — DNS Tunneling')}

        <h3>Use Cases 6-10 (Quick Reference)</h3>
        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>UC6: LATERAL MOVEMENT VIA PSEXEC (T1021.002)</h4><p>Detect PSEXESVC service creation + type 3 logon from same source to multiple targets.</p></div>
            <div class="pc-info-card"><h4>UC7: RANSOMWARE PRE-ENCRYPTION (T1490)</h4><p>Detect shadow copy deletion (vssadmin/wmic) followed by mass file modification.</p></div>
            <div class="pc-info-card"><h4>UC8: DATA STAGING FOR EXFIL (T1074)</h4><p>Detect compression tools (7z, rar) creating large archives in temp directories.</p></div>
            <div class="pc-info-card"><h4>UC9: PRIVILEGE ESCALATION VIA GROUP CHANGE (T1098)</h4><p>Detect addition of users to Domain Admins, Enterprise Admins, or Schema Admins.</p></div>
            <div class="pc-info-card"><h4>UC10: WEB SHELL ACTIVITY (T1505.003)</h4><p>Detect IIS/Apache spawning cmd.exe or powershell.exe processes.</p></div>
        </div>
    `,

    training: `
        <h3>Building a Detection Use Case Program</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Identify Coverage Gaps</h4><p>Map existing detections to MITRE ATT&CK. Identify techniques with zero coverage. Prioritize based on threat intelligence relevant to your industry.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Design the Use Case</h4><p>Define the attack behavior, required data sources, detection logic, and false positive scenarios. Write the query in your primary SIEM language. Document thoroughly.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Test & Validate</h4><p>Run the query against historical data. Validate against known-good attack simulations (Atomic Red Team). Tune for false positive reduction. Measure detection latency.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Deploy & Maintain</h4><p>Enable the rule in production. Create response runbook. Schedule quarterly reviews. Update based on new TTPs and false positive feedback.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Every use case must have: MITRE mapping, multi-SIEM queries, FP guidance, response actions</li><li>Test with Atomic Red Team simulations before deploying to production</li><li>Review and update use cases quarterly as attack techniques evolve</li><li>Track coverage metrics: % of MITRE techniques with at least one detection</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 30. DETECTION ENGINEERING
// ─────────────────────────────────────────────────────
platformContent.detectioneng = {
    overview: `
        <h3>Detection Engineering Methodology</h3>
        <p>Detection engineering is the systematic practice of designing, building, testing, and maintaining detection rules. It treats detections as code, applies software engineering principles (version control, testing, CI/CD), and uses MITRE ATT&CK as the framework for coverage tracking.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>DETECTION LIFECYCLE</h4>
                <ul><li>1. Threat Research — study the TTP</li><li>2. Data Requirements — identify needed log sources</li><li>3. Rule Development — write detection logic</li><li>4. Testing — validate with simulations</li><li>5. Deployment — enable in production</li><li>6. Tuning — reduce false positives</li><li>7. Retirement — remove obsolete rules</li></ul>
            </div>
            <div class="pc-info-card"><h4>DETECTION-AS-CODE</h4>
                <ul><li>Store rules in Git repository</li><li>Version control all changes</li><li>CI/CD pipeline for validation</li><li>Automated testing with attack simulations</li><li>Peer review via pull requests</li><li>Automated deployment to SIEM</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>MITRE ATT&CK Mapping Guide</h3>
        ${codeBlock(`Detection Rule Metadata Template:
---
id: DET-2024-001
name: Suspicious PowerShell Download Cradle
mitre:
  tactic: Execution (TA0002)
  technique: Command and Scripting Interpreter (T1059)
  subtechnique: PowerShell (T1059.001)
data_sources:
  - Process Creation (Windows Event 4688)
  - PowerShell Script Block Logging (Event 4104)
  - Sysmon Event 1
severity: high
confidence: medium
false_positive_rate: low
detection_type: behavioral
platforms: [windows]
required_log_sources:
  - Windows Security Event Log
  - PowerShell Operational Log
last_tested: 2024-06-15
test_method: Atomic Red Team T1059.001-1`, 'YAML — Detection Rule Metadata')}

        <h3>Sigma Rule Example (Universal Detection Format)</h3>
        ${codeBlock(`title: Suspicious PowerShell Download Cradle
id: 6f8c3d5a-1b2e-4c7d-8e9f-0a1b2c3d4e5f
status: production
description: Detects PowerShell download cradles commonly used by attackers
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: BlueShell Detection Engineering
date: 2024/06/15
modified: 2024/12/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'DownloadData'
            - 'WebRequest'
            - 'WebClient'
            - 'Invoke-RestMethod'
    condition: selection_process and selection_cmdline
falsepositives:
    - Legitimate admin scripts that download updates
    - Software deployment tools
level: high`, 'YAML — Sigma Rule')}

        <h3>Detection-as-Code CI/CD Pipeline</h3>
        ${codeBlock(`# .github/workflows/detection-pipeline.yml
name: Detection Rule Pipeline
on:
  pull_request:
    paths: ['rules/**']

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate Sigma Syntax
        run: sigma check rules/**/*.yml

      - name: Validate MITRE Mapping
        run: python scripts/validate_mitre.py rules/

      - name: Run Against Test Data
        run: |
          python scripts/test_rules.py \\
            --rules rules/ \\
            --test-data tests/attack-simulations/ \\
            --expected-detections tests/expected-results.json

      - name: Check False Positive Rate
        run: python scripts/fp_analysis.py --rules rules/ --baseline-data tests/baseline/

  deploy:
    needs: validate
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Splunk
        run: python scripts/deploy_splunk.py --rules rules/ --target prod

      - name: Deploy to Sentinel
        run: python scripts/deploy_sentinel.py --rules rules/ --target prod`, 'YAML — GitHub Actions CI/CD Pipeline')}

        <h3>Coverage Gap Analysis</h3>
        ${codeBlock(`MITRE ATT&CK Coverage Summary:
═══════════════════════════════
Tactic               | Rules | Coverage
──────────────────────┼───────┼──────────
Initial Access        |   12  |  ████████░  89%
Execution             |   18  |  ██████░░░  67%
Persistence           |   15  |  █████░░░░  56%
Privilege Escalation  |    8  |  ███░░░░░░  33%
Defense Evasion       |    6  |  ██░░░░░░░  22%  ← GAP
Credential Access     |   14  |  ██████░░░  67%
Discovery             |    4  |  █░░░░░░░░  15%  ← GAP
Lateral Movement      |   11  |  █████░░░░  56%
Collection            |    5  |  ██░░░░░░░  22%  ← GAP
Exfiltration          |    9  |  ████░░░░░  44%
Command & Control     |    7  |  ███░░░░░░  33%
Impact                |    6  |  ██░░░░░░░  22%  ← GAP

Priority: Defense Evasion, Discovery, Collection, Impact`, 'Text — Coverage Gap Analysis')}
    `,

    training: `
        <h3>Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Fundamentals</h4><p>Study MITRE ATT&CK framework thoroughly. Understand data sources and log requirements per technique. Learn Sigma rule format as a universal detection language.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Rule Development</h4><p>Write rules for your primary SIEM. Convert Sigma rules to platform-specific formats. Test with Atomic Red Team. Document false positive scenarios.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Detection-as-Code</h4><p>Set up a Git repo for all detection rules. Build CI/CD pipelines for validation and deployment. Implement automated testing against attack simulations.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Continuous Improvement</h4><p>Track coverage metrics. Schedule quarterly rule reviews. Monitor detection efficacy. Retire rules with high FP rates and no true positives.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Treat detections as code — version control, peer review, automated testing</li><li>Use Sigma as a universal format, then convert to platform-specific queries</li><li>Map every rule to MITRE ATT&CK for coverage tracking</li><li>Test every rule with Atomic Red Team before production deployment</li><li>Track metrics: detection count, FP rate, mean time to detect, coverage %</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 31. INCIDENT RESPONSE PLAYBOOKS
// ─────────────────────────────────────────────────────
platformContent.ir = {
    overview: `
        <h3>Incident Response Framework</h3>
        <p>Comprehensive IR playbooks following NIST SP 800-61 and SANS incident response methodology. Each playbook covers: Preparation, Detection, Containment, Eradication, Recovery, and Lessons Learned.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>8 IR PLAYBOOKS</h4>
                <ul><li>1. Phishing Response</li><li>2. Ransomware Response</li><li>3. Data Breach Response</li><li>4. Insider Threat Response</li><li>5. DDoS Response</li><li>6. Supply Chain Compromise</li><li>7. Cloud Security Incident</li><li>8. Business Email Compromise</li></ul>
            </div>
            <div class="pc-info-card"><h4>IR PHASES (NIST)</h4>
                <ul><li><strong>Preparation</strong> — tools, training, contacts</li><li><strong>Detection & Analysis</strong> — triage, scope</li><li><strong>Containment</strong> — short-term & long-term</li><li><strong>Eradication</strong> — remove threat</li><li><strong>Recovery</strong> — restore operations</li><li><strong>Post-Incident</strong> — lessons learned</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Playbook 1: Phishing Response</h3>
        ${codeBlock(`PHISHING INCIDENT RESPONSE PLAYBOOK
════════════════════════════════════
Severity: Medium-High | SLA: 1 hour initial response

1. DETECTION & TRIAGE (15 min)
   □ Verify the phishing report (user report or automated detection)
   □ Extract indicators: sender, subject, URLs, attachments, headers
   □ Check email headers for SPF/DKIM/DMARC results
   □ Submit URLs to VirusTotal, urlscan.io
   □ Submit attachments to sandbox (Any.run, Hybrid Analysis)
   □ Classify: Credential harvesting, malware delivery, or BEC

2. CONTAINMENT (30 min)
   □ Block sender address/domain at email gateway
   □ Block malicious URLs at proxy/firewall
   □ Search and purge matching emails from all mailboxes
   □ If credentials entered: force password reset immediately
   □ If attachment opened: isolate endpoint from network

3. ERADICATION (1-2 hours)
   □ If malware delivered: run full AV scan on affected endpoints
   □ Check for persistence mechanisms (scheduled tasks, registry)
   □ Verify no lateral movement from compromised endpoint
   □ Remove any downloaded payloads

4. RECOVERY (1-2 hours)
   □ Re-enable network access for cleaned endpoints
   □ Monitor affected accounts for suspicious activity (7 days)
   □ Verify email gateway block is active
   □ Update detection rules based on new indicators

5. POST-INCIDENT
   □ Document timeline and actions taken
   □ Add IOCs to threat intelligence platform
   □ Brief affected users on what happened
   □ Update phishing training materials if needed`, 'Text — Phishing Response Playbook')}

        <h3>Playbook 2: Ransomware Response</h3>
        ${codeBlock(`RANSOMWARE INCIDENT RESPONSE PLAYBOOK
═════════════════════════════════════
Severity: CRITICAL | SLA: IMMEDIATE response

1. DETECTION & TRIAGE (5 min)
   □ Confirm ransomware (ransom note, encrypted files, file extensions)
   □ Identify patient zero (first infected host)
   □ Determine ransomware variant (ID Ransomware, ransom note analysis)
   □ Check if decryptor exists (NoMoreRansom.org)

2. CONTAINMENT (15 min) — SPEED IS CRITICAL
   □ ISOLATE infected hosts from network IMMEDIATELY
   □ Disable SMB (port 445) at network level if spreading
   □ Block known C2 IPs/domains at firewall
   □ Disable compromised accounts
   □ Snapshot/preserve affected systems for forensics
   □ DO NOT power off — volatile memory may contain encryption keys

3. ERADICATION (hours-days)
   □ Identify entry vector (phishing, RDP, vulnerability)
   □ Check for persistence: scheduled tasks, services, registry Run keys
   □ Scan all endpoints for ransomware indicators
   □ Patch the entry vector vulnerability
   □ Remove all ransomware binaries and persistence

4. RECOVERY (hours-days)
   □ Restore from clean backups (verify backup integrity first!)
   □ Rebuild compromised systems from gold images if backups unavailable
   □ Restore data in priority order: critical business systems first
   □ Monitor restored systems for re-infection
   □ Gradually re-enable network access

5. POST-INCIDENT
   □ Full timeline documentation
   □ Executive incident report
   □ Update backup strategy (3-2-1 rule: 3 copies, 2 media, 1 offsite)
   □ Implement/improve email filtering and endpoint protection
   □ Conduct tabletop exercise within 30 days`, 'Text — Ransomware Response Playbook')}

        <h3>Playbooks 3-8 (Summary)</h3>
        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>3. DATA BREACH</h4><p>Legal notification (72h GDPR), scope assessment, data classification review, forensic evidence preservation, regulatory reporting, credit monitoring for affected individuals.</p></div>
            <div class="pc-info-card"><h4>4. INSIDER THREAT</h4><p>Preserve evidence (HR/Legal coordination), review DLP alerts, audit file access logs, interview subject, disable access, forensic imaging, legal proceedings preparation.</p></div>
            <div class="pc-info-card"><h4>5. DDOS</h4><p>Activate DDoS mitigation (Cloudflare/Akamai), enable rate limiting, contact ISP upstream filtering, identify attack type (volumetric/protocol/application), document for law enforcement.</p></div>
            <div class="pc-info-card"><h4>6. SUPPLY CHAIN</h4><p>Identify compromised software/update, inventory affected systems, isolate from update server, check for backdoors, coordinate with vendor, audit all systems that received the update.</p></div>
            <div class="pc-info-card"><h4>7. CLOUD SECURITY</h4><p>Revoke compromised API keys/tokens, audit IAM permissions, review CloudTrail/audit logs, check for unauthorized resources (crypto mining), rotate all secrets, review security group changes.</p></div>
            <div class="pc-info-card"><h4>8. BEC (Business Email Compromise)</h4><p>Freeze wire transfers (contact bank within 72h), secure compromised accounts, review email forwarding rules, check for inbox rules (auto-forward, auto-delete), notify affected business partners.</p></div>
        </div>
    `,

    training: `
        <h3>IR Readiness Training</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Build Your IR Kit</h4><p>Prepare: contact list (CISO, legal, HR, PR), forensic tools (KAPE, FTK Imager, Volatility), communication templates, evidence chain-of-custody forms, and war room access.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Tabletop Exercises</h4><p>Run quarterly tabletop exercises. Simulate ransomware, phishing, and insider threat scenarios. Include business stakeholders (legal, HR, comms). Document gaps found.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Purple Team Exercises</h4><p>Conduct red team simulations with blue team awareness. Test detection rules, response playbooks, and communication procedures. Measure MTTD (mean time to detect) and MTTR (mean time to respond).</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Print playbooks and keep offline copies — during a ransomware incident, your wiki might be encrypted</li><li>Update contact lists quarterly — people change roles</li><li>Conduct tabletop exercises at least quarterly</li><li>Always preserve evidence before eradication — you may need it for legal proceedings</li><li>Establish relationships with law enforcement BEFORE an incident</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 32. ALERT TRIAGE
// ─────────────────────────────────────────────────────
platformContent.alerttriage = {
    overview: `
        <h3>Alert Triage Framework</h3>
        <p>A structured methodology for SOC analysts to efficiently analyze, classify, and prioritize security alerts. The goal is to quickly distinguish true positives from false positives and escalate genuine threats while minimizing alert fatigue.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>TRIAGE DECISION TREE</h4>
                <ul><li>1. Is this alert known false positive? → Close</li><li>2. Is the source/target internal? → Context matters</li><li>3. Is the indicator on a threat list? → Escalate</li><li>4. Is there corroborating evidence? → Investigate</li><li>5. Is the behavior normal for this entity? → UEBA check</li></ul>
            </div>
            <div class="pc-info-card"><h4>SEVERITY MATRIX</h4>
                <ul><li><strong>Critical (P1)</strong> — Active breach, ransomware, data exfil. SLA: 15 min</li><li><strong>High (P2)</strong> — Confirmed compromise, malware. SLA: 1 hour</li><li><strong>Medium (P3)</strong> — Suspicious activity, policy violation. SLA: 4 hours</li><li><strong>Low (P4)</strong> — Informational, recon. SLA: 24 hours</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Triage Checklist</h3>
        ${codeBlock(`ALERT TRIAGE CHECKLIST
═════════════════════
For every alert, answer these questions:

□ WHAT triggered the alert?
  - Which rule/detection fired?
  - What is the MITRE ATT&CK technique?
  - What is the raw event data?

□ WHO is involved?
  - Source entity (user, IP, host)
  - Target entity (user, IP, host, application)
  - Is this a privileged account?
  - Is this a critical asset?

□ WHEN did it happen?
  - Is this during business hours?
  - Is this a first-time occurrence?
  - What was happening before/after this event?

□ WHERE in the kill chain?
  - Reconnaissance, Initial Access, Execution,
    Persistence, Lateral Movement, Exfiltration?
  - How far along is the attack?

□ HOW confident are we?
  - Single indicator or multiple corroborating?
  - Has this rule had high FP rate historically?
  - Is there threat intel context?

DECISION:
  True Positive → Escalate to incident
  Benign True Positive → Document and tune rule
  False Positive → Close with reason, request rule tuning
  Needs Investigation → Assign to Tier 2 with context`, 'Text — Alert Triage Checklist')}

        <h3>Escalation Matrix</h3>
        ${codeBlock(`ESCALATION MATRIX
═════════════════
Severity │ Assignee    │ SLA      │ Notification
─────────┼─────────────┼──────────┼─────────────────
CRIT (P1)│ SOC Lead    │ 15 min   │ Page + Phone + Email + Slack
HIGH (P2)│ SOC Tier 2  │ 1 hour   │ Slack + Email
MED  (P3)│ SOC Tier 1  │ 4 hours  │ Email + Ticket
LOW  (P4)│ SOC Tier 1  │ 24 hours │ Ticket only

Auto-Escalation Rules:
- No response within SLA → escalate to next tier
- 3+ related alerts → auto-merge into incident
- Known APT IOC match → immediate P1
- Honey user/honeypot trigger → immediate P1
- Active data exfiltration → immediate P1`, 'Text — Escalation Matrix')}
    `,

    training: `
        <h3>Triage Training Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Learn the Environment</h4><p>Study your organization's network topology, critical assets, service accounts, and normal business patterns. The best triagers know what "normal" looks like.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Master the Triage Checklist</h4><p>For every alert: What, Who, When, Where in kill chain, How confident. Practice with historical alerts. Build muscle memory for the decision tree.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Speed Without Sacrifice</h4><p>Target: 5-10 minutes per alert for initial triage. Use enrichment tools (SIEM lookups, threat intel, UEBA) to speed up context gathering. Document your reasoning.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Spend no more than 10 minutes on initial triage — if you need more, escalate to Tier 2</li><li>Always check for corroborating alerts from other sources (SIEM + EDR + Network)</li><li>Document your triage reasoning — even for false positives</li><li>Track false positive rates per rule to drive detection tuning</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 33. SOC RUNBOOKS
// ─────────────────────────────────────────────────────
platformContent.socrunbooks = {
    overview: `
        <h3>SOC Runbooks</h3>
        <p>Operational procedures for Security Operations Center analysts, covering shift operations, tool access, escalation procedures, communication protocols, and performance metrics.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>RUNBOOK CATEGORIES</h4>
                <ul><li>Shift Operations — handoff, daily checks</li><li>Tool Access — SIEM, EDR, SOAR procedures</li><li>Escalation Paths — when and how to escalate</li><li>Communication — stakeholder notification</li><li>Metrics & KPIs — what to measure</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Shift Handoff Runbook</h3>
        ${codeBlock(`SOC SHIFT HANDOFF PROCEDURE
═══════════════════════════
Outgoing Analyst Responsibilities:
1. Update all open incidents with current status and next steps
2. Complete the Shift Handoff Log:
   - Open incidents and their status
   - Pending investigations
   - Any unusual activity observed
   - Tool issues or outages
   - Upcoming maintenance windows
3. Verbally brief incoming analyst on critical items
4. Transfer ownership of active investigations in SOAR

Incoming Analyst Responsibilities:
1. Review Shift Handoff Log
2. Check all monitoring dashboards for anomalies
3. Review overnight alert queue
4. Verify all tools are operational:
   □ SIEM — search working, ingestion normal
   □ EDR — agent health dashboard green
   □ SOAR — playbooks executing
   □ Threat Intel — feeds updating
5. Acknowledge receipt of handoff in log`, 'Text — Shift Handoff Runbook')}

        <h3>SOC KPIs & Metrics</h3>
        ${codeBlock(`SOC PERFORMANCE METRICS
═══════════════════════
Detection Metrics:
- MTTD (Mean Time to Detect): Target < 1 hour
- Detection Coverage: % of MITRE techniques covered
- True Positive Rate: Target > 80%
- False Positive Rate: Target < 20%

Response Metrics:
- MTTR (Mean Time to Respond): Target < 4 hours
- MTTC (Mean Time to Contain): Target < 2 hours
- Incident Resolution Time: P1 < 24h, P2 < 72h
- Escalation Rate: % of Tier 1 alerts escalated

Operational Metrics:
- Alerts per Analyst per Shift: Target < 50
- Alert Queue Depth: Target < 20 at shift change
- Playbook Automation Rate: Target > 60%
- SLA Compliance: Target > 95%

Improvement Metrics:
- New detection rules per quarter: Target 10+
- Detection tuning requests completed: Target 90%
- Tabletop exercises per quarter: Target 1+`, 'Text — SOC KPIs')}
    `,

    training: `
        <h3>SOC Analyst Development Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Tier 1: Alert Monitoring</h4><p>Master alert triage. Follow runbooks precisely. Learn all SOC tools. Consistently meet SLA targets. Duration: 6-12 months.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Tier 2: Investigation</h4><p>Deep investigation skills. Write hunting queries. Create new detection rules. Mentor Tier 1 analysts. Handle escalations. Duration: 1-2 years.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Tier 3: Expert</h4><p>Threat hunting, malware analysis, detection engineering, incident commander role. Build automation playbooks. Interface with threat intel team.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Keep runbooks up to date — review monthly</li><li>Shift handoffs should be verbal AND written — critical context gets lost otherwise</li><li>Track metrics consistently — what gets measured gets improved</li><li>Rotate analysts through different roles to prevent burnout and build skills</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 34. THREAT HUNTING
// ─────────────────────────────────────────────────────
platformContent.hunting = {
    overview: `
        <h3>Threat Hunting Methodology</h3>
        <p>Proactive, hypothesis-driven search for threats that have evaded existing detection rules. Unlike alert triage (reactive), threat hunting assumes a breach and actively searches for evidence of compromise using data analysis, behavioral patterns, and threat intelligence.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>HUNTING METHODOLOGY</h4>
                <ul><li>1. Form hypothesis based on threat intel or gap analysis</li><li>2. Identify required data sources</li><li>3. Write hunting queries</li><li>4. Analyze results for anomalies</li><li>5. Investigate findings</li><li>6. Convert to detection rule if valid</li></ul>
            </div>
            <div class="pc-info-card"><h4>HYPOTHESIS SOURCES</h4>
                <ul><li>Threat intelligence reports (APT campaigns)</li><li>MITRE ATT&CK gap analysis</li><li>Industry breach reports</li><li>Red team/pentest findings</li><li>Anomalies in baseline data</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Hunt 1: Living-off-the-Land Binaries (LOLBins)</h3>
        <p><strong>Hypothesis:</strong> Attackers are using legitimate Windows binaries to download and execute payloads.</p>
        ${codeBlock(`-- SPLUNK:
index=wineventlog EventCode=4688
(New_Process_Name="*certutil*" OR New_Process_Name="*mshta*" OR
 New_Process_Name="*regsvr32*" OR New_Process_Name="*bitsadmin*")
(Process_Command_Line="*http*" OR Process_Command_Line="*ftp*")
| stats count by host, user, New_Process_Name, Process_Command_Line
| sort -count

-- SENTINEL KQL:
DeviceProcessEvents
| where FileName in~ ("certutil.exe","mshta.exe","regsvr32.exe","bitsadmin.exe")
| where ProcessCommandLine has_any ("http","ftp","\\\\\\\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`, 'Multi-SIEM — LOLBin Hunt')}

        <h3>Hunt 2: DNS Beaconing</h3>
        <p><strong>Hypothesis:</strong> Compromised hosts are beaconing to C2 via DNS at regular intervals.</p>
        ${codeBlock(`-- SPLUNK:
index=dns | stats count, stdev(eval(relative_time(_time, "@m"))) as time_stdev by src_ip, query
| where count > 50 AND time_stdev < 120
| sort time_stdev

-- SENTINEL KQL:
DnsEvents
| where TimeGenerated > ago(24h)
| summarize RequestCount=count(), Times=make_list(TimeGenerated) by ClientIP, Name
| where RequestCount > 50
| extend Intervals = array_sort_asc(Times)
| mv-apply Intervals on (
    extend NextTime = next(Intervals)
    | extend IntervalSec = datetime_diff('second', NextTime, Intervals)
    | summarize StdDev = stdev(IntervalSec)
)
| where StdDev < 60  // Very regular intervals = likely beaconing`, 'Multi-SIEM — DNS Beaconing Hunt')}

        <h3>Hunt 3: Unusual Parent-Child Process Relationships</h3>
        <p><strong>Hypothesis:</strong> Attackers spawn unexpected child processes from applications (e.g., Word spawning PowerShell).</p>
        ${codeBlock(`-- SPLUNK:
index=wineventlog EventCode=4688
| eval parent=lower(Creator_Process_Name), child=lower(New_Process_Name)
| search (parent="*winword*" OR parent="*excel*" OR parent="*outlook*")
        (child="*powershell*" OR child="*cmd.exe" OR child="*wscript*" OR child="*mshta*")
| table _time, host, user, parent, child, Process_Command_Line

-- SENTINEL KQL:
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`, 'Multi-SIEM — Suspicious Parent-Child')}

        <h3>Hunt 4: Anomalous Service Account Behavior</h3>
        <p><strong>Hypothesis:</strong> A compromised service account is being used interactively or from unexpected hosts.</p>
        ${codeBlock(`-- SPLUNK:
index=wineventlog EventCode=4624 Account_Name="svc-*"
| stats dc(Workstation_Name) as unique_hosts, values(Workstation_Name) as hosts,
        values(Logon_Type) as logon_types by Account_Name
| where unique_hosts > 3 OR logon_types="2" OR logon_types="10"

-- SENTINEL KQL:
SecurityEvent
| where EventID == 4624 and TargetUserName startswith "svc-"
| summarize UniqueHosts=dcount(Computer), Hosts=make_set(Computer),
    LogonTypes=make_set(LogonType) by TargetUserName
| where UniqueHosts > 3 or LogonTypes has "2" or LogonTypes has "10"`, 'Multi-SIEM — Service Account Anomaly')}
    `,

    training: `
        <h3>Threat Hunting Training Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Foundation: Know Your Environment</h4><p>Baseline normal behavior: what processes run on servers vs workstations, what network patterns are normal, which service accounts exist and where they authenticate. You cannot find abnormal without knowing normal.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Hypothesis-Driven Hunting</h4><p>Start each hunt with a specific hypothesis. Use MITRE ATT&CK, threat reports, and breach case studies as inspiration. Document hypothesis, data sources needed, queries used, and findings.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Convert Hunts to Detections</h4><p>Every successful hunt finding should become a permanent detection rule. This is how threat hunting directly improves your detection coverage over time.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Always start with a hypothesis — aimless searching is not hunting</li><li>Document everything: hypothesis, data sources, queries, findings, and outcome</li><li>Convert successful hunts into automated detection rules</li><li>Hunt on a regular cadence (weekly/biweekly) — not just after incidents</li><li>Share hunt findings with your team — collective knowledge multiplies effectiveness</li></ul>
        </div>
    `
};

// ═══════════════════════════════════════════════════════
// TOOLS
// ═══════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────
// 35. THREAT INTEL FETCHER
// ─────────────────────────────────────────────────────
platformContent.fetcher = {
    overview: `
        <h3>Threat Intel Auto-Fetcher</h3>
        <p>A Python CLI tool that automatically collects IOCs (Indicators of Compromise) from multiple OSINT threat intelligence feeds and converts them into detection rules for 14+ SIEM platforms.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>SUPPORTED FEEDS</h4>
                <ul><li>abuse.ch URLhaus — malicious URLs</li><li>abuse.ch MalwareBazaar — malware samples</li><li>abuse.ch FeodoTracker — botnet C2 servers</li><li>abuse.ch ThreatFox — general IOCs</li><li>AlienVault OTX — pulses and IOCs</li><li>MITRE ATT&CK — techniques/software</li><li>NIST NVD — vulnerabilities</li><li>CISA KEV — exploited vulnerabilities</li></ul>
            </div>
            <div class="pc-info-card"><h4>OUTPUT FORMATS</h4>
                <ul><li>JSON — structured IOC data</li><li>CSV — spreadsheet-friendly</li><li>STIX2 — standard threat intel format</li><li>SIEM Rules — platform-specific queries</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Usage Examples</h3>
        ${codeBlock(`# Fetch all IOCs from all feeds
python threat-intel-fetcher.py --all

# Fetch from specific feeds
python threat-intel-fetcher.py --feeds urlhaus,malwarebazaar,feodotracker

# Output in STIX2 format
python threat-intel-fetcher.py --all --format stix2 --output iocs.json

# Generate Splunk SPL rules from fetched IOCs
python threat-intel-fetcher.py --all --generate-rules splunk

# Generate rules for multiple SIEMs
python threat-intel-fetcher.py --all --generate-rules splunk,sentinel,qradar

# Scheduled fetch (cron-friendly)
python threat-intel-fetcher.py --all --format json --output /opt/iocs/daily.json --quiet`, 'Bash — Fetcher CLI Usage')}

        <h3>Configuration</h3>
        ${codeBlock(`# config.yaml
feeds:
  urlhaus:
    enabled: true
    url: "https://urlhaus-api.abuse.ch/v1/"
    interval: 3600  # seconds

  malwarebazaar:
    enabled: true
    url: "https://mb-api.abuse.ch/api/v1/"
    interval: 3600

  feodotracker:
    enabled: true
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    interval: 7200

  threatfox:
    enabled: true
    url: "https://threatfox-api.abuse.ch/api/v1/"
    interval: 3600

  otx:
    enabled: true
    api_key: "${OTX_API_KEY}"
    interval: 3600

output:
  directory: "./output"
  formats: ["json", "csv", "stix2"]
  max_age_days: 30  # expire IOCs older than this`, 'YAML — Fetcher Configuration')}

        <h3>Sample Output</h3>
        ${codeBlock(`{
  "fetch_timestamp": "2024-12-15T10:30:00Z",
  "feed": "urlhaus",
  "total_indicators": 245,
  "indicators": [
    {
      "type": "url",
      "value": "http://malicious-site.example/payload.exe",
      "threat_type": "malware_download",
      "malware": "Emotet",
      "first_seen": "2024-12-14T22:15:00Z",
      "confidence": 95,
      "tags": ["emotet", "banking-trojan", "maldoc"]
    },
    {
      "type": "ip",
      "value": "203.0.113.50",
      "threat_type": "c2_server",
      "malware": "QakBot",
      "first_seen": "2024-12-15T01:00:00Z",
      "confidence": 90,
      "tags": ["qakbot", "c2", "botnet"]
    }
  ]
}`, 'JSON — Sample Fetcher Output')}
    `,

    training: `
        <h3>Getting Started</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Install Dependencies</h4><p><code>pip install requests pyyaml stix2</code>. Python 3.8+ required. Set API keys for OTX and any authenticated feeds in environment variables.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Configure Feeds</h4><p>Edit config.yaml to enable/disable feeds and set fetch intervals. Most abuse.ch feeds require no authentication. OTX requires a free API key.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Schedule Fetching</h4><p>Add to crontab: <code>0 */4 * * * python /opt/tools/threat-intel-fetcher.py --all --quiet</code>. This fetches every 4 hours.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">4</div><div class="pc-step-body"><h4>Integrate with SIEM</h4><p>Use <code>--generate-rules</code> to create platform-specific detection rules. Import into your SIEM via API or file upload.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Set IOC expiration — stale IOCs generate false positives</li><li>Use confidence scores to filter low-quality indicators</li><li>Automate the fetch-to-SIEM pipeline for real-time threat intel integration</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 36. SIEM RULE GENERATOR
// ─────────────────────────────────────────────────────
platformContent.rulegen = {
    overview: `
        <h3>SIEM Rule Generator</h3>
        <p>A Python tool that converts IOCs (IP addresses, domains, URLs, file hashes) into platform-specific detection rules for 14 SIEM platforms. Input IOCs in any format and get ready-to-deploy rules for your SIEM.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>SUPPORTED OUTPUTS</h4>
                <ul><li>Splunk SPL</li><li>Microsoft Sentinel KQL</li><li>IBM QRadar AQL</li><li>Elastic EQL/KQL</li><li>Wazuh XML</li><li>Chronicle YARA-L</li><li>ArcSight CEF</li><li>Sigma (universal)</li><li>...and 6 more</li></ul>
            </div>
            <div class="pc-info-card"><h4>INPUT FORMATS</h4>
                <ul><li>Plain text (one IOC per line)</li><li>CSV with type column</li><li>STIX2 bundles</li><li>JSON IOC lists</li><li>MISP event export</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Usage</h3>
        ${codeBlock(`# Generate Splunk rule from IOC file
python siem-rule-generator.py --input iocs.txt --platform splunk --output rules.spl

# Generate rules for multiple platforms
python siem-rule-generator.py --input iocs.csv --platform splunk,sentinel,qradar

# Generate from STIX2 bundle
python siem-rule-generator.py --input threat-intel.json --format stix2 --platform all

# Pipe from threat-intel-fetcher
python threat-intel-fetcher.py --feeds urlhaus --format json | \\
python siem-rule-generator.py --stdin --platform splunk`, 'Bash — Rule Generator Usage')}

        <h3>Sample Output: Splunk SPL</h3>
        ${codeBlock(`| Generated by BlueShell SIEM Rule Generator
| Source: URLhaus feed, 2024-12-15
| IOCs: 15 malicious URLs

index=proxy OR index=web
  (url="http://malicious1.example.com/payload" OR
   url="http://malicious2.example.com/dropper" OR
   url="http://malicious3.example.com/c2")
| stats count by src_ip, url, user
| lookup threat_intel_iocs url AS url OUTPUT threat_type, confidence
| where isnotnull(threat_type)
| table _time, src_ip, user, url, threat_type, confidence`, 'SPL — Generated Rule')}

        <h3>Sample Output: Sentinel KQL</h3>
        ${codeBlock(`// Generated by BlueShell SIEM Rule Generator
// Source: FeodoTracker, 2024-12-15
// IOCs: 25 C2 IP addresses
let MaliciousIPs = dynamic([
    "203.0.113.50", "198.51.100.25", "192.0.2.100"
    // ... 22 more
]);
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DestinationIP in (MaliciousIPs)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
    DeviceAction, Activity`, 'KQL — Generated Rule')}
    `,

    training: `
        <h3>Getting Started</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Prepare IOC Input</h4><p>Collect IOCs in a text file (one per line) or CSV with columns: type, value, description. Supported types: ip, domain, url, hash_md5, hash_sha256.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Generate Rules</h4><p>Run the generator with your target platform. Review the output for accuracy. Test the generated rule against historical data in your SIEM.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Automate the Pipeline</h4><p>Chain fetcher + generator in a cron job for continuous IOC-to-rule conversion. Deploy rules automatically via SIEM API.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Always review generated rules before deploying to production</li><li>Set expiration dates on IOC-based rules — stale IOCs cause false positives</li><li>Use the batch mode for large IOC sets to generate optimized queries</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 37. IOC MANAGEMENT
// ─────────────────────────────────────────────────────
platformContent.iocmgmt = {
    overview: `
        <h3>IOC Management</h3>
        <p>Lifecycle management for Indicators of Compromise (IOCs) — from collection and enrichment through sharing and expiration. Covers STIX2/TAXII standards, IOC types, enrichment workflows, and sharing communities.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>IOC TYPES</h4>
                <ul><li><strong>Network</strong> — IP, domain, URL</li><li><strong>File</strong> — MD5, SHA1, SHA256, filename</li><li><strong>Email</strong> — sender, subject, attachment hash</li><li><strong>Host</strong> — registry key, process name, service</li><li><strong>Behavioral</strong> — MITRE technique pattern</li></ul>
            </div>
            <div class="pc-info-card"><h4>LIFECYCLE</h4>
                <ul><li>1. Collection — feeds, reports, incidents</li><li>2. Enrichment — context, confidence, severity</li><li>3. Storage — TIP, SIEM reference sets</li><li>4. Distribution — STIX2/TAXII, MISP</li><li>5. Consumption — detection rules, blocks</li><li>6. Expiration — age out stale indicators</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>STIX2 Bundle Example</h3>
        ${codeBlock(`{
  "type": "bundle",
  "id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--12345678-abcd-efgh-ijkl-123456789012",
      "created": "2024-12-15T10:00:00Z",
      "modified": "2024-12-15T10:00:00Z",
      "name": "Emotet C2 Server",
      "description": "Known Emotet command and control server",
      "pattern": "[ipv4-addr:value = '203.0.113.50']",
      "pattern_type": "stix",
      "valid_from": "2024-12-15T10:00:00Z",
      "valid_until": "2025-01-15T10:00:00Z",
      "confidence": 90,
      "labels": ["malicious-activity", "c2"],
      "kill_chain_phases": [
        { "kill_chain_name": "mitre-attack", "phase_name": "command-and-control" }
      ]
    },
    {
      "type": "malware",
      "id": "malware--abcdef12-3456-7890-abcd-ef1234567890",
      "name": "Emotet",
      "is_family": true,
      "malware_types": ["bot", "trojan"]
    },
    {
      "type": "relationship",
      "relationship_type": "indicates",
      "source_ref": "indicator--12345678-abcd-efgh-ijkl-123456789012",
      "target_ref": "malware--abcdef12-3456-7890-abcd-ef1234567890"
    }
  ]
}`, 'JSON — STIX2 Bundle')}

        <h3>IOC Enrichment Workflow</h3>
        ${codeBlock(`IOC ENRICHMENT PIPELINE
══════════════════════
Input: Raw IOC (e.g., IP address 203.0.113.50)

Step 1: Reputation Check
  → VirusTotal: 15/90 engines flagged
  → AbuseIPDB: 95% confidence malicious
  → Shodan: Port 443 open, self-signed cert

Step 2: Context Addition
  → GeoIP: Country=RU, City=Moscow, ISP=Bullet-proof-hosting
  → WHOIS: Registered 2 days ago (newly registered = suspicious)
  → Passive DNS: Resolves to malware-c2.example.com

Step 3: Scoring
  → Composite Score: 92/100 (HIGH CONFIDENCE MALICIOUS)
  → Factors: VT positive + AbuseIPDB high + new registration + bullet-proof hosting

Step 4: Classification
  → Type: C2 Server
  → Associated Malware: Emotet
  → MITRE Technique: T1071 (Application Layer Protocol)
  → Recommended Action: BLOCK at firewall + Add to SIEM watchlist

Step 5: Distribution
  → Push to SIEM reference set
  → Push to firewall block list
  → Share via TAXII to ISAC partners
  → Set expiration: 30 days`, 'Text — Enrichment Pipeline')}
    `,

    training: `
        <h3>Learning Path</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Understand IOC Types</h4><p>Learn the pyramid of pain: hash (easy to change) -> IP (harder) -> domain (harder) -> TTPs (hardest to change). Focus enrichment effort on higher-value indicators.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>STIX2 & TAXII</h4><p>Learn STIX2 object types (indicator, malware, threat-actor, relationship). Understand TAXII servers for automated IOC distribution.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Automation</h4><p>Build automated pipelines: collect -> enrich -> score -> distribute -> expire. Use MISP or a TIP for centralized management.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>Always set expiration dates on IOCs — stale indicators cause false positives</li><li>Enrich before consuming — an IP address without context is noise</li><li>Focus on TTPs over atomic indicators — behaviors are harder for attackers to change</li><li>Share with ISACs and trusted communities — collective defense works</li></ul>
        </div>
    `
};

// ─────────────────────────────────────────────────────
// 38. MITRE ATT&CK MAP
// ─────────────────────────────────────────────────────
platformContent.mitremap = {
    overview: `
        <h3>MITRE ATT&CK Interactive Map</h3>
        <p>Browse the MITRE ATT&CK framework, track your detection coverage, identify gaps, and plan detection engineering priorities. Use the Navigator layer format to visualize and share your coverage map.</p>

        <div class="pc-info-grid">
            <div class="pc-info-card"><h4>FRAMEWORK STRUCTURE</h4>
                <ul><li>14 Tactics (columns) — the "why"</li><li>200+ Techniques — the "how"</li><li>Sub-techniques — specific implementations</li><li>Mitigations — preventive controls</li><li>Data Sources — log requirements</li><li>Software — tools used by adversaries</li></ul>
            </div>
            <div class="pc-info-card"><h4>COVERAGE TRACKING</h4>
                <ul><li>Green — detection rule exists and tested</li><li>Yellow — rule exists, not tested</li><li>Red — no detection coverage</li><li>Blue — prevention control in place</li></ul>
            </div>
        </div>
    `,

    rules: `
        <h3>Navigator Layer Export Format</h3>
        ${codeBlock(`{
  "name": "BlueShell Detection Coverage",
  "version": "4.5",
  "domain": "enterprise-attack",
  "description": "Current detection rule coverage",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "tactic": "execution",
      "score": 90,
      "color": "#00ff41",
      "comment": "Covered by: SPL-001, KQL-015, WAZ-022",
      "metadata": [
        { "name": "rules", "value": "3 active rules" },
        { "name": "last_tested", "value": "2024-12-01" }
      ]
    },
    {
      "techniqueID": "T1110",
      "tactic": "credential-access",
      "score": 85,
      "color": "#00ff41",
      "comment": "Covered by: SPL-005, KQL-008, AQL-003"
    },
    {
      "techniqueID": "T1055",
      "tactic": "defense-evasion",
      "score": 0,
      "color": "#ff3333",
      "comment": "GAP: No detection coverage for process injection"
    }
  ],
  "gradient": {
    "colors": ["#ff3333", "#ffcc00", "#00ff41"],
    "minValue": 0,
    "maxValue": 100
  }
}`, 'JSON — ATT&CK Navigator Layer')}

        <h3>Top Priority Techniques for Detection</h3>
        ${codeBlock(`PRIORITY DETECTION COVERAGE TARGETS
════════════════════════════════════
Based on: frequency in real attacks + impact + data source availability

HIGH PRIORITY (implement first):
  T1059.001 - PowerShell                  [Execution]
  T1110     - Brute Force                 [Credential Access]
  T1078     - Valid Accounts              [Multiple]
  T1021.002 - SMB/Windows Admin Shares    [Lateral Movement]
  T1053.005 - Scheduled Task              [Persistence]
  T1003.001 - LSASS Memory               [Credential Access]
  T1486     - Data Encrypted for Impact   [Impact]
  T1071.001 - Web Protocols C2            [C2]
  T1566.001 - Spearphishing Attachment    [Initial Access]
  T1048     - Exfiltration Over Alt Proto [Exfiltration]

MEDIUM PRIORITY (implement next):
  T1218     - System Binary Proxy Exec    [Defense Evasion]
  T1055     - Process Injection           [Defense Evasion]
  T1558.003 - Kerberoasting              [Credential Access]
  T1505.003 - Web Shell                  [Persistence]
  T1098     - Account Manipulation       [Persistence]`, 'Text — Priority Techniques')}
    `,

    training: `
        <h3>Using MITRE ATT&CK Effectively</h3>
        <div class="pc-step"><div class="pc-step-num">1</div><div class="pc-step-body"><h4>Map Your Current Coverage</h4><p>List all your existing detection rules. Map each one to its ATT&CK technique. Import into ATT&CK Navigator to visualize coverage. Identify red (uncovered) areas.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">2</div><div class="pc-step-body"><h4>Prioritize Gaps</h4><p>Not all gaps are equal. Prioritize based on: prevalence in real attacks (check threat intel), impact if exploited, and whether you have the required data sources.</p></div></div>
        <div class="pc-step"><div class="pc-step-num">3</div><div class="pc-step-body"><h4>Build Detection Roadmap</h4><p>Create a quarterly plan: target 5-10 new technique coverages per quarter. Track progress in Navigator layers. Report to leadership as coverage percentage improvement.</p></div></div>
    `,

    bestpractices: `
        <div class="pc-tip"><h4>BEST PRACTICES</h4>
            <ul><li>100% coverage is not realistic or necessary — prioritize based on your threat landscape</li><li>Update your Navigator layer monthly as you add new rules</li><li>Use ATT&CK for communication — it gives you a common language with your team and leadership</li><li>Cross-reference with threat intelligence — cover techniques used by threat actors targeting your industry</li></ul>
        </div>
    `
};

// Also map rulebuilder if it exists in pageData
platformContent.rulebuilder = {
    overview: `<h3>Visual Rule Builder</h3><p>The Rule Builder is an interactive drag-and-drop tool loaded directly in the platform. Click "Rule Builder" in the sidebar under Tools to launch the visual editor. It supports 7 SIEM output formats and MITRE ATT&CK tactic mapping.</p>`,
    rules: `<h3>Supported Output Formats</h3><p>Splunk SPL, Sentinel KQL, QRadar AQL, Elastic EQL, Wazuh XML, Chronicle YARA-L, and Sigma. Drag data sources, conditions, fields, and actions onto the canvas, then click "Generate" to produce detection rules.</p>`,
    training: `<p>The Rule Builder is self-guided. Drag components from the left palette onto the canvas lanes. The tool automatically generates syntactically correct queries for your selected SIEM platform.</p>`,
    bestpractices: `<div class="pc-tip"><h4>TIPS</h4><ul><li>Start with a Data Source and MITRE Tactic, then add Conditions and Fields</li><li>Use the "Export" button to save generated rules</li><li>Copy the output directly into your SIEM for testing</li></ul></div>`
};


// ═══════════════════════════════════════════════════════
// OVERRIDE loadPage() — Rich Tabbed Content
// ═══════════════════════════════════════════════════════

(function overrideLoadPage() {
    // Save original loadPage in case we need it
    const _originalLoadPage = (typeof loadPage === 'function') ? loadPage : null;

    window.loadPage = function(pageId) {
        // Special case: rule builder has its own loader
        if (pageId === 'rulebuilder' && typeof loadRuleBuilder === 'function') {
            loadRuleBuilder();
            return;
        }

        const page = (typeof pageData !== 'undefined') ? pageData[pageId] : null;
        if (!page) return;

        const content = platformContent[pageId];

        document.getElementById('dashboard').classList.add('hidden');
        const pageEl = document.getElementById('page-content');
        pageEl.classList.remove('hidden');

        // Build header
        let html = `
            <div style="margin-bottom:20px">
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                    <h1 style="margin:0;border:none;padding:0">${page.title}</h1>
                    <span class="card-tag" style="position:static">${page.type}</span>
                </div>
                <p style="color:var(--text-secondary);font-size:13px">${page.desc}</p>
            </div>
        `;

        // If we have rich content, show tabbed interface
        if (content) {
            const tabs = [
                { label: 'Overview & Setup', content: content.overview || '' },
                { label: 'Rules & Queries', content: content.rules || '' },
                { label: 'Training', content: content.training || '' },
                { label: 'Best Practices', content: content.bestpractices || '' }
            ].filter(t => t.content.trim().length > 0);

            html += buildTabs(pageId, tabs);
        } else {
            // Fallback to feature list for pages without rich content
            const featuresHtml = page.features ? page.features.map(f => `<tr><td>&#9656; ${f}</td></tr>`).join('') : '';
            html += `
                <div class="section-title">&#10214; AVAILABLE CONTENT &#10215;</div>
                <table><tbody>${featuresHtml}</tbody></table>
                <div class="section-title" style="margin-top:24px">&#10214; FILE LOCATION &#10215;</div>
                <pre><code>${page.path || ''}</code></pre>
            `;
        }

        // Add navigation buttons
        html += `
            <div style="margin-top:24px;display:flex;gap:8px;flex-wrap:wrap">
                <button class="btn-hack" onclick="loadPage('${pageId}')">&#8635; REFRESH</button>
                <button class="btn-hack" onclick="goHome()">&#9666; BACK TO DASHBOARD</button>
            </div>
        `;

        pageEl.innerHTML = html;

        // Update active nav
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        if (event && event.target) {
            event.target.classList.add('active');
        }

        // Scroll to top
        pageEl.scrollTop = 0;
    };

    // Add aliases for sidebar IDs that differ from platformContent keys
    // Sidebar uses 'ioc' but we defined as 'iocmgmt', etc.
    const pageAliases = {
        ioc: 'iocmgmt',
        mitre: 'mitremap',
        detection: 'detectioneng',
        triage: 'alerttriage',
        runbooks: 'socrunbooks'
    };

    // Add aliased pageData entries so loadPage can find them
    if (typeof pageData !== 'undefined') {
        for (const [alias, real] of Object.entries(pageAliases)) {
            if (!pageData[alias] && pageData[real]) {
                pageData[alias] = pageData[real];
            }
            // Also ensure platformContent has the alias
            if (!platformContent[alias] && platformContent[real]) {
                platformContent[alias] = platformContent[real];
            }
        }
        // If pageData still lacks these entries, add minimal ones
        if (!pageData.ioc) {
            pageData.ioc = { title: "IOC MANAGEMENT", type: "BLUE TEAM", desc: "IOC lifecycle and threat intelligence sharing", features: ["IOC Types & Lifecycle", "STIX2 / TAXII Format", "Sharing Communities", "Enrichment Workflows"], path: "../tools/" };
        }
        if (!pageData.mitre) {
            pageData.mitre = { title: "MITRE ATT&CK MAP", type: "TOOL", desc: "Interactive technique browser and coverage mapper", features: ["Technique Browser", "Coverage Heatmap", "Gap Analysis", "Navigator Export"], path: "../tools/" };
        }
        if (!pageData.detection) {
            pageData.detection = { title: "DETECTION ENGINEERING", type: "BLUE TEAM", desc: "Systematic approach to building detection rules", features: ["Rule Creation Methodology", "MITRE Mapping Guide", "Detection-as-Code", "Coverage Analysis"], path: "../blue-team-resources/detection-engineering/" };
        }
        if (!pageData.triage) {
            pageData.triage = { title: "ALERT TRIAGE FRAMEWORK", type: "BLUE TEAM", desc: "Structured alert analysis and prioritization", features: ["Severity Matrix", "Triage Decision Tree", "Escalation Criteria"], path: "../blue-team-resources/alert-triage/" };
        }
        if (!pageData.runbooks) {
            pageData.runbooks = { title: "SOC RUNBOOKS", type: "BLUE TEAM", desc: "Operational procedures for SOC analysts", features: ["Shift Handoff", "Escalation Paths", "KPIs & Metrics"], path: "../blue-team-resources/soc-runbooks/" };
        }
    }
})();
