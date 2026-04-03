// ═══════════════════════════════════════════════════════════════════════════
// BLUESHELL - AI Detection Rule Generator v2.0
// Generates complete SIEM/EDR/SOAR/XDR detection & response solutions
// Master Prompt: {{RULE_NAME}} + {{CONTEXT_DATA}} → Full Detection Rule
// ═══════════════════════════════════════════════════════════════════════════

// ── Master Prompt Builder ──────────────────────────────────────────────
// This builds the prompt that gets sent to Claude API backend.
// Template uses {{RULE_NAME}} and {{CONTEXT_DATA}} replacement pattern.

function buildDetectionPrompt(ruleName, platformFocus) {
    const context = getDetectionContext(ruleName);
    const platformCtx = platformFocus && platformFocus !== 'ALL'
        ? 'Focus more on: ' + platformFocus
        : '';

    // Master prompt template — same as server.js MASTER_PROMPT_TEMPLATE
    const PROMPT_TEMPLATE = `You are a senior SOC analyst, detection engineer, and security automation expert.

Your task is to generate a complete security detection and response solution.

Rule Name: {{RULE_NAME}}

Context:
{{CONTEXT_DATA}}

Instructions:
- Think like a real SOC (Detection + Response + Endpoint + Correlation)
- Cover SIEM, EDR, SOAR, and XDR aspects
- Use MITRE ATT&CK framework
- Avoid generic answers
- Be technical and concise

{{PLATFORM_FOCUS}}

Return output as valid JSON only.`;

    return PROMPT_TEMPLATE
        .replace('{{RULE_NAME}}', ruleName)
        .replace('{{CONTEXT_DATA}}', context.trim())
        .replace('{{PLATFORM_FOCUS}}', platformCtx);
}

// ── Smart Context Injection Engine ──────────────────────────────────────
// Automatically injects relevant context based on attack keywords in rule name

function getDetectionContext(ruleName) {
    const r = ruleName.toLowerCase();
    let ctx = '';

    if (r.includes('powershell') || r.includes('ps1') || r.includes('script')) {
        ctx += `
- powershell.exe suspicious usage patterns
- Flags: -enc, -nop, -w hidden, -ep bypass, -sta, -EncodedCommand
- Parent processes: winword.exe, excel.exe, wscript.exe, mshta.exe, cmd.exe
- Event ID 4104 (Script Block Logging), 4103 (Module Logging)
- Sysmon Event ID 1 (Process Create)
- MITRE T1059.001 (PowerShell)
- MITRE T1059 (Command and Scripting Interpreter)
- AMSI bypass detection, constrained language mode evasion`;
    }

    if (r.includes('rdp') || r.includes('remote desktop') || r.includes('lateral')) {
        ctx += `
- Event ID 4624 Logon Type 10 (Remote Interactive / RDP)
- Event ID 4625 (Failed Logon)
- Event ID 4672 (Special Privileges Assigned)
- Event ID 5140 (Network Share Access)
- Multiple host login attempts (velocity anomaly)
- MITRE T1021.001 (Remote Desktop Protocol)
- MITRE T1021.002 (SMB/Windows Admin Shares)
- MITRE T1078 (Valid Accounts)
- Process: mstsc.exe, rdpclip.exe, tstheme.exe`;
    }

    if (r.includes('mimikatz') || r.includes('credential') || r.includes('lsass') || r.includes('dump')) {
        ctx += `
- LSASS.exe memory access / cross-process read
- Process: mimikatz.exe, procdump.exe, rundll32.exe (comsvcs.dll MiniDump)
- reg save HKLM\\SAM, reg save HKLM\\SYSTEM
- sekurlsa::logonpasswords, sekurlsa::wdigest
- MITRE T1003.001 (LSASS Memory)
- MITRE T1003.002 (SAM)
- MITRE T1003.003 (NTDS)
- Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe
- Event ID 4656 (Handle to Object Requested)`;
    }

    if (r.includes('brute') || r.includes('password') || r.includes('spray')) {
        ctx += `
- Event ID 4625 (Failed Logon) - high volume from single source
- Event ID 4624 (Successful Logon) following failures
- Event ID 4771 (Kerberos Pre-Auth Failed)
- Event ID 4776 (Credential Validation)
- Status codes: 0xC000006A (bad password), 0xC0000072 (disabled), 0xC000006D (bad username)
- MITRE T1110.001 (Brute Force: Password Guessing)
- MITRE T1110.003 (Password Spraying)
- MITRE T1110.004 (Credential Stuffing)`;
    }

    if (r.includes('phish') || r.includes('email') || r.includes('bec')) {
        ctx += `
- Office macro execution: winword.exe / excel.exe spawning cmd.exe or powershell.exe
- Outlook rule manipulation (T1137.005)
- Email forwarding rules (New-InboxRule)
- MITRE T1566.001 (Spearphishing Attachment)
- MITRE T1566.002 (Spearphishing Link)
- MITRE T1534 (Internal Spearphishing)
- Event ID 4104 for decoded script content
- Sysmon Event ID 1 for suspicious child processes`;
    }

    if (r.includes('ransom') || r.includes('encrypt') || r.includes('lockbit') || r.includes('blackcat')) {
        ctx += `
- Mass file rename operations (.encrypted, .locked, .crypt extensions)
- Volume Shadow Copy deletion (vssadmin delete shadows, wmic shadowcopy delete)
- bcdedit /set {default} recoveryenabled no
- Event ID 4663 (File Access Audit) - high volume writes
- MITRE T1486 (Data Encrypted for Impact)
- MITRE T1490 (Inhibit System Recovery)
- MITRE T1489 (Service Stop) - stopping security services
- Sysmon Event ID 11 (FileCreate) - ransom notes`;
    }

    if (r.includes('persist') || r.includes('registry') || r.includes('scheduled task') || r.includes('startup')) {
        ctx += `
- Registry Run/RunOnce key modifications (HKLM/HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)
- Scheduled task creation (schtasks /create, Event ID 4698)
- New service installation (Event ID 7045, sc create)
- WMI event subscriptions (__EventConsumer)
- MITRE T1547.001 (Registry Run Keys)
- MITRE T1053.005 (Scheduled Task)
- MITRE T1543.003 (Windows Service)
- MITRE T1546.003 (WMI Event Subscription)`;
    }

    if (r.includes('exfil') || r.includes('data loss') || r.includes('dlp') || r.includes('staging')) {
        ctx += `
- Large outbound data transfers (>100MB to single destination)
- DNS tunneling (high volume TXT/CNAME queries, long subdomains)
- Cloud storage uploads (OneDrive, Dropbox, Google Drive, Mega)
- Archive creation before transfer (7z, rar, zip of sensitive directories)
- MITRE T1041 (Exfiltration Over C2 Channel)
- MITRE T1048 (Exfiltration Over Alternative Protocol)
- MITRE T1567 (Exfiltration Over Web Service)
- Event ID 5156 (Windows Filtering Platform) for outbound connections`;
    }

    if (r.includes('priv') || r.includes('escalat') || r.includes('uac') || r.includes('token')) {
        ctx += `
- Event ID 4672 (Special Privileges Assigned to New Logon)
- Event ID 4673 (Sensitive Privilege Use)
- UAC bypass techniques (fodhelper.exe, eventvwr.exe, sdclt.exe)
- Token impersonation / theft (SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege)
- MITRE T1548.002 (Bypass UAC)
- MITRE T1134 (Access Token Manipulation)
- MITRE T1068 (Exploitation for Privilege Escalation)
- Named pipe impersonation (PrintSpoofer, JuicyPotato)`;
    }

    if (r.includes('c2') || r.includes('beacon') || r.includes('cobalt') || r.includes('command and control')) {
        ctx += `
- Periodic beaconing patterns (consistent time intervals)
- DNS beaconing (high frequency DNS queries to single domain)
- HTTP/HTTPS C2 with jitter patterns
- Named pipe communication (Cobalt Strike default: \\.\pipe\msagent_*)
- MITRE T1071 (Application Layer Protocol)
- MITRE T1573 (Encrypted Channel)
- MITRE T1572 (Protocol Tunneling)
- MITRE T1095 (Non-Application Layer Protocol)
- Process injection into svchost.exe, rundll32.exe, dllhost.exe`;
    }

    if (r.includes('kerberos') || r.includes('golden') || r.includes('silver') || r.includes('ticket') || r.includes('roast')) {
        ctx += `
- Event ID 4768 (TGT Request), 4769 (Service Ticket Request)
- Event ID 4771 (Kerberos Pre-Auth Failed)
- Kerberoasting: mass TGS requests for SPNs (T1558.003)
- AS-REP Roasting: accounts without pre-auth (T1558.004)
- Golden Ticket: TGT with abnormal lifetime
- Silver Ticket: forged service ticket
- MITRE T1558 (Steal or Forge Kerberos Tickets)
- Tools: Rubeus, Impacket GetUserSPNs, Mimikatz kerberos::`;
    }

    if (r.includes('dns') || r.includes('tunnel')) {
        ctx += `
- DNS query volume anomaly (>500 queries/min to single domain)
- Long subdomain labels (>50 chars) indicating data encoding
- TXT record queries with base64/hex encoded data
- MITRE T1071.004 (Application Layer Protocol: DNS)
- MITRE T1568 (Dynamic Resolution)
- Sysmon Event ID 22 (DNSEvent)
- DNS server logs (Event ID 256-280)`;
    }

    if (r.includes('wmi') || r.includes('windows management')) {
        ctx += `
- WMI process creation: wmic process call create
- WMI remote execution: /node:<target>
- WMI event subscription persistence (__EventFilter, __EventConsumer)
- Event ID 5861 (WMI Activity)
- Sysmon Event ID 19/20/21 (WMI Events)
- MITRE T1047 (Windows Management Instrumentation)
- Process: wmiprvse.exe spawning suspicious children`;
    }

    // Default context always included
    ctx += `
- Windows Event ID 4624 = Successful login
- Logon Type 10 = Remote Interactive (RDP)
- Event ID 4625 = Failed login
- Event ID 4672 = Privileged login
- Event ID 5140 = SMB share access
- PowerShell Event ID 4104 = Script execution
- MITRE ATT&CK T1021 = Remote Services
- MITRE ATT&CK T1059 = Command Execution`;

    return ctx.trim();
}

// ── MITRE ATT&CK Mapping Database ──────────────────────────────────────

const MITRE_DB = {
    powershell: [
        { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
        { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
        { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' }
    ],
    rdp: [
        { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement' },
        { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
        { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' }
    ],
    mimikatz: [
        { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' },
        { id: 'T1003.002', name: 'Security Account Manager', tactic: 'Credential Access' },
        { id: 'T1003.003', name: 'NTDS', tactic: 'Credential Access' }
    ],
    brute: [
        { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access' },
        { id: 'T1110.003', name: 'Password Spraying', tactic: 'Credential Access' },
        { id: 'T1110.004', name: 'Credential Stuffing', tactic: 'Credential Access' }
    ],
    phishing: [
        { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access' },
        { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
        { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution' }
    ],
    ransomware: [
        { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
        { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
        { id: 'T1489', name: 'Service Stop', tactic: 'Impact' }
    ],
    persistence: [
        { id: 'T1547.001', name: 'Registry Run Keys', tactic: 'Persistence' },
        { id: 'T1053.005', name: 'Scheduled Task', tactic: 'Persistence' },
        { id: 'T1543.003', name: 'Windows Service', tactic: 'Persistence' }
    ],
    exfiltration: [
        { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
        { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
        { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' }
    ],
    privilege: [
        { id: 'T1548.002', name: 'Bypass UAC', tactic: 'Privilege Escalation' },
        { id: 'T1134', name: 'Access Token Manipulation', tactic: 'Privilege Escalation' },
        { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' }
    ],
    c2: [
        { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
        { id: 'T1573', name: 'Encrypted Channel', tactic: 'Command and Control' },
        { id: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control' }
    ],
    kerberos: [
        { id: 'T1558.003', name: 'Kerberoasting', tactic: 'Credential Access' },
        { id: 'T1558.004', name: 'AS-REP Roasting', tactic: 'Credential Access' },
        { id: 'T1558.001', name: 'Golden Ticket', tactic: 'Credential Access' }
    ],
    dns: [
        { id: 'T1071.004', name: 'DNS', tactic: 'Command and Control' },
        { id: 'T1568', name: 'Dynamic Resolution', tactic: 'Command and Control' },
        { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Protocol', tactic: 'Exfiltration' }
    ],
    wmi: [
        { id: 'T1047', name: 'Windows Management Instrumentation', tactic: 'Execution' },
        { id: 'T1546.003', name: 'WMI Event Subscription', tactic: 'Persistence' }
    ],
    default: [
        { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
        { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
        { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' }
    ]
};

// ── Detection Rule Templates ───────────────────────────────────────────

const DETECTION_TEMPLATES = {

    powershell: {
        severity: 'High',
        severityReason: 'PowerShell is the most abused living-off-the-land binary; encoded/obfuscated execution bypasses basic AV and indicates active adversary tooling.',
        logSources: [
            { source: 'PowerShell Operational', eventId: '4104', purpose: 'Script Block Logging — decoded script content' },
            { source: 'PowerShell Operational', eventId: '4103', purpose: 'Module Logging — cmdlet execution' },
            { source: 'Windows Security', eventId: '4688', purpose: 'Process Creation with command-line' },
            { source: 'Sysmon', eventId: '1', purpose: 'Process Create with full command-line and parent' }
        ],
        splunk: `index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval script=lower(ScriptBlockText)
| where match(script, "(?i)(Invoke-(Mimikatz|Expression|Command|WebRequest|Shellcode)|IEX|DownloadString|DownloadFile|Start-BitsTransfer|Net\\.WebClient|FromBase64String|EncodedCommand|Bypass|Hidden|Reflection\\.Assembly|Add-Type.*DllImport|GetProcAddress|VirtualAlloc|AmsiUtils|Set-MpPreference\\s+-Disable)")
| stats count values(ScriptBlockText) AS scripts values(ComputerName) AS hosts BY Account_Name
| where count >= 1
| table _time, Account_Name, hosts, count, scripts`,
        kql: `Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| extend ScriptBlock = tostring(parse_json(EventData).ScriptBlockText)
| where ScriptBlock matches regex @"(?i)(Invoke-(Mimikatz|Expression|Command|WebRequest|Shellcode)|IEX|DownloadString|DownloadFile|FromBase64String|EncodedCommand|Bypass|Hidden|Reflection\\.Assembly|AmsiUtils|Set-MpPreference\\s+-Disable)"
| project TimeGenerated, Computer, ScriptBlock, UserId = tostring(parse_json(EventData).UserId)
| sort by TimeGenerated desc`,
        edrProcess: 'powershell.exe or pwsh.exe with suspicious flags (-enc, -nop, -w hidden, -ep bypass, -sta)',
        edrParentChild: `winword.exe / excel.exe / mshta.exe / wscript.exe
  └─ cmd.exe (optional)
       └─ powershell.exe -enc <base64> -nop -w hidden
            ├─ net.exe (recon)
            ├─ whoami.exe
            └─ [in-memory: Invoke-Mimikatz / SharpHound]`,
        edrCmdIndicators: [
            'powershell.exe -enc <base64_string>',
            'powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://...\')"',
            'powershell.exe -ep bypass -file C:\\Users\\Public\\payload.ps1',
            'powershell.exe -c "[Reflection.Assembly]::LoadWithPartialName(\'Microsoft.CSharp\')"',
            'powershell.exe -c "Add-Type -TypeDefinition $code -Language CSharp"'
        ],
        ioa: [
            'PowerShell launched with -EncodedCommand flag (any variation: -enc, -e, -en)',
            'PowerShell spawned by Office process (winword.exe, excel.exe, outlook.exe)',
            'PowerShell with -WindowStyle Hidden or -w hidden flag',
            'PowerShell invoking Net.WebClient or Invoke-WebRequest to external URL',
            'AMSI bypass attempt detected in script block (AmsiUtils, amsiInitFailed)',
            'PowerShell loading .NET assembly via reflection (Reflection.Assembly)'
        ],
        falsePositives: [
            'SCCM/Intune software deployment scripts using encoded commands',
            'IT automation tools (Ansible, Puppet, Chef) executing PowerShell remotely',
            'Azure AD Connect / Hybrid Join scripts with encoded parameters',
            'Legitimate admin scripts with -WindowStyle Hidden for background tasks',
            'SCOM monitoring agent executing health check scripts'
        ],
        soarTrigger: 'PowerShell script block contains known attack pattern AND parent process is non-standard (not explorer.exe, not scheduled task)',
        soarActions: [
            'Query EDR: Full process tree for the PowerShell PID',
            'Decode: If -enc flag present, base64 decode and analyze payload content',
            'Isolate: Host network isolation via EDR API (if parent is Office process)',
            'Disable: User account in AD if credential access patterns detected',
            'Block: Add decoded URLs/IPs to proxy blocklist',
            'Ticket: Create incident with decoded script content attached'
        ],
        thresholds: { events: 1, window: '5 minutes', note: 'Single event sufficient — encoded/obfuscated PowerShell is high-fidelity' },
        investigationSteps: [
            'Decode the full ScriptBlockText — identify what the script actually does',
            'Check parent process — was PowerShell spawned by Office, browser, or wscript?',
            'Review user account — is this a standard user or admin? Expected behavior?',
            'Check if script downloads external content — extract URLs/IPs',
            'Look for AMSI bypass attempts in the script content',
            'Check for subsequent process creation — did PowerShell spawn recon tools?',
            'Review network connections from the PowerShell process (outbound C2)',
            'Check for persistence — did the script create scheduled tasks or registry keys?'
        ],
        tuning: [
            'Whitelist known SCCM/Intune deployment script hashes',
            'Exclude specific service accounts used for automation (svc_sccm, svc_ansible)',
            'Baseline which admin accounts regularly use encoded PowerShell and exclude',
            'Narrow regex if FP rate >15% — remove generic terms, keep attack-specific',
            'Add scoring: encoded command (+4), Office parent (+5), AMSI bypass (+5), download (+3)'
        ]
    },

    rdp: {
        severity: 'High',
        severityReason: 'RDP from non-baselined source + post-auth execution + SMB pivot = confirmed lateral movement chain.',
        logSources: [
            { source: 'Windows Security', eventId: '4624 (Type 10)', purpose: 'RDP successful authentication' },
            { source: 'Windows Security', eventId: '4625', purpose: 'Failed login attempts (brute-force precursor)' },
            { source: 'Windows Security', eventId: '4672', purpose: 'Privileged token assigned to session' },
            { source: 'Windows Security', eventId: '5140', purpose: 'SMB network share access' },
            { source: 'Sysmon', eventId: '1', purpose: 'Process creation under RDP session' },
            { source: 'Sysmon', eventId: '3', purpose: 'Network connection (outbound RDP/SMB)' }
        ],
        splunk: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| eval rdp_time=_time
| rename src_ip AS attacker_ip, Account_Name AS user, ComputerName AS target_host
| search NOT [| inputlookup approved_jump_servers.csv | fields attacker_ip]
| join type=inner target_host, user
    [search index=wineventlog
     (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
     OR (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
    | eval exec_time=_time
    | rename ComputerName AS target_host, AccountName AS user
    | where match(ScriptBlockText, "(?i)(Invoke-Mimikatz|Net\\s+(user|group)|nltest|whoami|SharpHound|Rubeus|sekurlsa)")
      OR match(CommandLine, "(?i)(whoami|net\\s+(view|use)|qwinsta|wmic|schtasks\\s+/create)")
    | table exec_time, target_host, user, ScriptBlockText, CommandLine, ParentImage]
| where exec_time >= rdp_time AND exec_time <= (rdp_time + 600)
| join type=left user
    [search index=wineventlog sourcetype="WinEventLog:Security" EventCode=5140
    | eval smb_time=_time | rename Account_Name AS user, ComputerName AS smb_target
    | table smb_time, user, smb_target, Share_Name]
| where smb_target != target_host AND smb_time >= rdp_time AND smb_time <= (rdp_time + 1800)
| table rdp_time, attacker_ip, user, target_host, exec_time, CommandLine, smb_target, smb_time`,
        kql: `let jump_servers = dynamic(["10.0.1.50","10.0.1.51"]);
let rdp = SecurityEvent
    | where EventID == 4624 and LogonType == 10
    | where IpAddress !in (jump_servers)
    | project RdpTime=TimeGenerated, AttackerIP=IpAddress, User=TargetUserName, RdpTarget=Computer;
let exec = union
    (Event | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
     | extend SB = tostring(parse_json(EventData).ScriptBlockText)
     | where SB matches regex @"(?i)(Invoke-Mimikatz|SharpHound|Rubeus|Net\\s+(user|group)|whoami)"
     | project ExecTime=TimeGenerated, ExecHost=Computer, ExecUser=tostring(parse_json(EventData).UserId), Indicator=SB),
    (SecurityEvent | where EventID == 4688
     | where CommandLine matches regex @"(?i)(whoami|net\\s+(view|use)|qwinsta|wmic|schtasks)"
     | project ExecTime=TimeGenerated, ExecHost=Computer, ExecUser=TargetUserName, Indicator=CommandLine);
let smb = SecurityEvent | where EventID == 5140
    | project SmbTime=TimeGenerated, SmbUser=TargetUserName, SmbTarget=Computer, Share=ShareName;
rdp
| join kind=inner exec on $left.RdpTarget == $right.ExecHost, $left.User == $right.ExecUser
| where ExecTime between (RdpTime .. (RdpTime + 10m))
| join kind=inner smb on $left.User == $right.SmbUser
| where SmbTarget != RdpTarget and SmbTime between (RdpTime .. (RdpTime + 30m))
| project RdpTime, AttackerIP, User, RdpTarget, ExecTime, Indicator, SmbTarget, Share, SmbTime`,
        edrProcess: 'mstsc.exe (outbound RDP), rdpclip.exe/tstheme.exe (session init on target)',
        edrParentChild: `svchost.exe (TermService)
  └─ rdpinit.exe → explorer.exe
       ├─ cmd.exe → whoami.exe, net.exe, nltest.exe
       ├─ powershell.exe → [Invoke-Mimikatz / SharpHound]
       ├─ rundll32.exe (comsvcs.dll MiniDump)
       └─ mstsc.exe (outbound RDP to next target)`,
        edrCmdIndicators: [
            'whoami /priv',
            'net group "Domain Admins" /domain',
            'net view /domain',
            'nltest /dclist:<domain>',
            'qwinsta /server:<target>',
            'psexec.exe \\\\<target> -accepteula -s cmd.exe',
            'wmic /node:<target> process call create "cmd /c ..."',
            'net use \\\\<target>\\C$ /user:<domain>\\<user> <password>'
        ],
        ioa: [
            'RDP session spawns cmd.exe or powershell.exe within 120s of logon',
            'Encoded PowerShell under LogonType 10 session',
            'Same account authenticates via RDP to 3+ distinct hosts in 30 minutes',
            'ADMIN$ or C$ share access to a host with zero prior history for that user',
            'LSASS cross-process read by non-SYSTEM process under RDP session'
        ],
        falsePositives: [
            'IT admin RDP + legitimate management scripts from approved jump servers',
            'SCCM/Intune software push over SMB (machine account, LogonType 3)',
            'Vulnerability scanner IPs triggering 4624 + 5140 in sequence',
            'Help desk remote support via approved tools (BeyondTrust, SCCM Remote)',
            'Service accounts with cross-host authentication (svc_* naming convention)'
        ],
        soarTrigger: 'Correlation rule fires: RDP Login (non-whitelisted IP) + Suspicious Execution + SMB Pivot within 30 minutes',
        soarActions: [
            'Enrich: Query AD for user privilege level (adminCount, group membership)',
            'Enrich: Query CMDB for target host asset tier (Tier 0/1/2)',
            'Enrich: Check threat intel feeds for attacker IP reputation',
            'Isolate: Network contain target host via CrowdStrike/MDE API',
            'Disable: User account in AD (Disable-ADAccount)',
            'Kill: Suspicious processes via EDR Real-Time Response',
            'Block: Source IP at perimeter firewall (if external)',
            'Collect: EDR timeline + PowerShell transcripts for forensics'
        ],
        thresholds: { events: 3, window: '30 minutes', note: 'Stage 1 (RDP) + Stage 2 (Execution within 10m) + Stage 3 (SMB pivot within 30m)' },
        investigationSteps: [
            'Validate the RDP source IP — jump server, VPN, or unknown endpoint?',
            'Validate the user — normal hours? First time RDP to this host?',
            'Review full command-line and script content — recon, cred theft, or admin?',
            'Check for Event ID 4672 — privileged token in this session?',
            'Check for preceding 4625 events — brute-force before success?',
            'Pull EDR timeline on target — full process tree under RDP session',
            'Investigate SMB target — which share accessed? Files written?',
            'Query all DCs — 4624 events for this user in last 24 hours'
        ],
        tuning: [
            'Maintain jump server IP whitelist — highest-impact tuning action',
            'Exclude machine accounts (ending in $) from correlation stages',
            'Integrate UEBA baseline — only alert on first-seen (user → host) RDP pairs',
            'Whitelist scanner and SCCM source IPs',
            'Tighten command-line regex monthly based on FP review',
            'Add GeoIP enrichment — auto-escalate if source IP is from unexpected country'
        ]
    },

    mimikatz: {
        severity: 'Critical',
        severityReason: 'LSASS memory access is a direct credential theft indicator — this is always malicious in production environments.',
        logSources: [
            { source: 'Sysmon', eventId: '10', purpose: 'ProcessAccess — LSASS cross-process read' },
            { source: 'Sysmon', eventId: '1', purpose: 'Process Create — tool execution' },
            { source: 'Windows Security', eventId: '4656', purpose: 'Handle to sensitive object requested' },
            { source: 'Windows Security', eventId: '4663', purpose: 'Object access attempt' },
            { source: 'PowerShell Operational', eventId: '4104', purpose: 'In-memory Mimikatz detection via script block' }
        ],
        splunk: `index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
    TargetImage="*\\\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csfalconservice|csagent|MsSense|SentinelAgent|CylanceSvc|cb\\.exe|svchost)")
| eval access_mask=GrantedAccess
| where access_mask IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| stats count values(SourceImage) AS source_procs values(access_mask) AS access_masks BY ComputerName, SourceUser
| where count >= 1
| table _time, ComputerName, SourceUser, source_procs, access_masks, count`,
        kql: `DeviceProcessEvents
| where FileName =~ "lsass.exe"
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName !in~ ("MsMpEng.exe","csfalconservice.exe","SentinelAgent.exe","svchost.exe")
    | project Timestamp, DeviceName, AccessingProcess=InitiatingProcessFileName,
              AccountName=InitiatingProcessAccountName, CommandLine=InitiatingProcessCommandLine
) on DeviceName
| where Timestamp between (Timestamp1 .. (Timestamp1 + 1s))
| project Timestamp, DeviceName, AccessingProcess, AccountName, CommandLine
// Alternative using Sysmon data in Sentinel:
// Event | where Source == "Microsoft-Windows-Sysmon" and EventID == 10
// | extend TargetImage = tostring(parse_json(EventData).TargetImage)
// | where TargetImage endswith "lsass.exe"
// | extend SourceImage = tostring(parse_json(EventData).SourceImage)
// | where SourceImage !endswith "MsMpEng.exe" and SourceImage !endswith "csfalconservice.exe"`,
        edrProcess: 'Any non-SYSTEM, non-AV process reading lsass.exe memory space (GrantedAccess 0x1010, 0x1410, 0x1fffff)',
        edrParentChild: `explorer.exe (user session)
  └─ cmd.exe / powershell.exe
       ├─ mimikatz.exe → lsass.exe (memory read)
       ├─ procdump.exe -ma lsass.exe out.dmp
       ├─ rundll32.exe comsvcs.dll,MiniDump <PID> dump.bin full
       └─ reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam`,
        edrCmdIndicators: [
            'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
            'procdump.exe -ma lsass.exe C:\\Windows\\Temp\\l.dmp',
            'rundll32.exe comsvcs.dll,MiniDump <lsass_pid> C:\\Temp\\d.bin full',
            'reg save HKLM\\SAM C:\\Windows\\Temp\\sam',
            'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys',
            'ntdsutil "ac i ntds" "ifm" "create full c:\\temp" q q',
            'powershell.exe -c "Invoke-Mimikatz -DumpCreds"'
        ],
        ioa: [
            'Non-SYSTEM process opens handle to lsass.exe with read access (0x1010, 0x1410)',
            'Process creates minidump of lsass.exe via comsvcs.dll MiniDump',
            'reg.exe saves SAM or SYSTEM hive to disk',
            'ntdsutil.exe creates IFM snapshot (NTDS.dit extraction)',
            'PowerShell script block contains sekurlsa, kerberos::, or lsadump:: commands'
        ],
        falsePositives: [
            'EDR/AV agents that legitimately read LSASS for credential guard (whitelisted by hash)',
            'Windows Defender ATP sensor (MsSense.exe) accessing LSASS',
            'Crash dump utilities triggered by LSASS failure (WerFault.exe)',
            'Credential Guard Hyper-V operations (securityhealthservice.exe)'
        ],
        soarTrigger: 'Sysmon Event ID 10 with TargetImage=lsass.exe AND SourceImage not in AV/EDR whitelist',
        soarActions: [
            'IMMEDIATE: Isolate host via EDR API — no approval needed (Critical severity)',
            'Kill: Terminate the accessing process via EDR RTR',
            'Disable: User account in AD + revoke all Kerberos tickets',
            'Collect: Memory dump of the accessing process for analysis',
            'Hunt: Search for same tool hash/process across all endpoints',
            'Reset: Force password reset for all accounts logged into the host',
            'Notify: Page IR lead + CISO immediately for Tier 0 hosts'
        ],
        thresholds: { events: 1, window: 'Immediate', note: 'Single event — LSASS access by non-system process is always critical' },
        investigationSteps: [
            'Identify the SourceImage/AccessingProcess — what tool accessed LSASS?',
            'Check if the tool is known (mimikatz, procdump, rundll32 comsvcs) or custom',
            'Review GrantedAccess mask — 0x1fffff = full access, 0x1010 = read-only',
            'Check process ancestry — how was the tool launched?',
            'Identify all accounts with active sessions on the host (all are compromised)',
            'Check for credential dump files on disk (*.dmp, *.bin in Temp directories)',
            'Query for the same tool hash across all endpoints (lateral spread)',
            'Determine if dumped credentials were used (check 4624 events for those accounts)'
        ],
        tuning: [
            'Whitelist EDR/AV processes by SHA256 hash, NOT by filename (easily spoofed)',
            'Exclude GrantedAccess=0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) — too noisy',
            'Add allowlist for WerFault.exe crash dump operations',
            'Enable Credential Guard + LSA Protection to prevent the attack entirely',
            'Alert on reg.exe saving SAM/SYSTEM hives as separate high-fidelity rule'
        ]
    },

    brute: {
        severity: 'Medium',
        severityReason: 'Failed login volume is common in large environments; escalate to High if followed by successful authentication.',
        logSources: [
            { source: 'Windows Security', eventId: '4625', purpose: 'Failed logon attempt' },
            { source: 'Windows Security', eventId: '4624', purpose: 'Successful logon (post-brute confirmation)' },
            { source: 'Windows Security', eventId: '4771', purpose: 'Kerberos Pre-Auth Failed' },
            { source: 'Windows Security', eventId: '4776', purpose: 'NTLM Credential Validation' }
        ],
        splunk: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count dc(Account_Name) AS unique_users values(Account_Name) AS targeted_users BY src_ip, _time
| where count >= 10 OR unique_users >= 5
| join type=left src_ip
    [search index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624
    | eval success_time=_time
    | rename Account_Name AS success_user
    | table src_ip, success_time, success_user, Logon_Type]
| where isnotnull(success_user) AND success_time >= _time AND success_time <= (_time + 1800)
| eval attack_type=if(unique_users >= 5, "Password Spray", "Brute Force")
| table _time, src_ip, attack_type, count, unique_users, targeted_users, success_user, success_time`,
        kql: `let failures = SecurityEvent
    | where EventID == 4625
    | summarize FailCount=count(), UniqueUsers=dcount(TargetUserName),
                TargetUsers=make_set(TargetUserName, 20)
                by IpAddress, bin(TimeGenerated, 10m)
    | where FailCount >= 10 or UniqueUsers >= 5;
let successes = SecurityEvent
    | where EventID == 4624
    | project SuccessTime=TimeGenerated, IpAddress, SuccessUser=TargetUserName, LogonType;
failures
| join kind=leftouter successes on IpAddress
| where SuccessTime between (TimeGenerated .. (TimeGenerated + 30m))
| extend AttackType = iff(UniqueUsers >= 5, "Password Spray", "Brute Force")
| project TimeGenerated, IpAddress, AttackType, FailCount, UniqueUsers, TargetUsers, SuccessUser, SuccessTime`,
        edrProcess: 'N/A — brute force is authentication-layer; EDR monitors post-authentication behavior',
        edrParentChild: `Post-successful-brute-force:
  explorer.exe (interactive session)
  └─ cmd.exe / powershell.exe (immediate recon)
       ├─ whoami.exe /priv
       ├─ net.exe user /domain
       └─ nltest.exe /dclist`,
        edrCmdIndicators: [
            'Post-auth recon: whoami /priv, net group "Domain Admins" /domain',
            'Immediate tool download: certutil -urlcache -split -f http://...',
            'Lateral movement attempt within minutes of successful brute-force login'
        ],
        ioa: [
            '10+ failed logins from single IP within 10 minutes',
            '5+ distinct usernames targeted from single IP (password spray)',
            'Successful login immediately following burst of failures from same IP',
            'Failed Kerberos pre-auth (4771) targeting multiple SPNs'
        ],
        falsePositives: [
            'Expired service account passwords causing automated retry loops',
            'Users with cached/stale credentials on multiple devices',
            'Password rotation scripts testing old credentials before updating',
            'VPN clients retrying with old credentials after password change',
            'Monitoring tools with misconfigured credentials'
        ],
        soarTrigger: '10+ Event 4625 from same IP in 10 minutes, OR 5+ unique users targeted from same IP',
        soarActions: [
            'Enrich: GeoIP lookup on source IP — expected country?',
            'Enrich: Check if source IP is VPN endpoint or external',
            'Block: Add source IP to firewall deny list (if external)',
            'Lock: Temporarily lock targeted accounts (if spray, lock all targeted)',
            'Alert: If success follows failures, escalate to High — trigger lateral movement playbook',
            'Ticket: Create IR ticket with full timeline and targeted account list'
        ],
        thresholds: { events: 10, window: '10 minutes', note: '10+ failures from same IP OR 5+ unique users targeted (spray)' },
        investigationSteps: [
            'Identify source IP — internal or external? Known VPN/proxy?',
            'Check SubStatus codes — 0xC000006A (bad password) vs 0xC0000072 (disabled account)',
            'Determine if attack is brute force (single user) or spray (many users, few attempts each)',
            'Check if any targeted accounts have admin privileges',
            'Verify if successful login occurred after the failure burst',
            'If success occurred — immediately pivot to lateral movement investigation',
            'Check source IP across all log sources for prior/subsequent activity'
        ],
        tuning: [
            'Exclude known VPN concentrator IPs that aggregate multiple users',
            'Exclude monitoring/health-check service accounts with known retry patterns',
            'Adjust threshold based on environment size (larger environments = higher threshold)',
            'Create separate rules for external vs internal brute force',
            'Weight by SubStatus code — 0xC000006A is higher fidelity than 0xC0000234 (lockout)'
        ]
    },

    // Default template for unmatched rule names
    default: {
        severity: 'Medium',
        severityReason: 'General detection rule — severity depends on environmental context and correlated signals.',
        logSources: [
            { source: 'Windows Security', eventId: '4624', purpose: 'Successful authentication' },
            { source: 'Windows Security', eventId: '4625', purpose: 'Failed authentication' },
            { source: 'Windows Security', eventId: '4688', purpose: 'Process creation' },
            { source: 'Sysmon', eventId: '1', purpose: 'Process creation with command-line' },
            { source: 'Sysmon', eventId: '3', purpose: 'Network connections' },
            { source: 'PowerShell Operational', eventId: '4104', purpose: 'Script block logging' }
        ],
        splunk: `index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4688 OR EventCode=4104)
| eval event_type=case(
    EventCode=4624, "Authentication",
    EventCode=4625, "Failed Auth",
    EventCode=4688, "Process Create",
    EventCode=4104, "Script Execution")
| stats count BY event_type, Account_Name, ComputerName, src_ip
| where count >= 5
| sort -count
| table _time, event_type, Account_Name, ComputerName, src_ip, count`,
        kql: `union
    (SecurityEvent | where EventID in (4624, 4625, 4688)),
    (Event | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104)
| extend EventType = case(
    EventID == 4624, "Authentication",
    EventID == 4625, "Failed Auth",
    EventID == 4688, "Process Create",
    EventID == 4104, "Script Execution",
    "Other")
| summarize Count=count() by EventType, TargetUserName, Computer, IpAddress, bin(TimeGenerated, 10m)
| where Count >= 5
| sort by Count desc`,
        edrProcess: 'Monitor process creation events for suspicious binaries and command-line arguments',
        edrParentChild: `Suspicious parent-child patterns:
  explorer.exe → cmd.exe/powershell.exe (user-initiated)
  svchost.exe → cmd.exe (service execution)
  winword.exe → powershell.exe (macro execution)
  wscript.exe → cmd.exe (script execution)`,
        edrCmdIndicators: [
            'whoami /priv',
            'net user /domain',
            'net group "Domain Admins" /domain',
            'nltest /dclist:<domain>',
            'certutil -urlcache -split -f http://...'
        ],
        ioa: [
            'Suspicious process spawned from non-standard parent',
            'Encoded command-line arguments (base64, hex)',
            'Process accessing sensitive system files or registry keys',
            'Outbound connection to non-standard port from user process'
        ],
        falsePositives: [
            'Legitimate administrative activity during maintenance windows',
            'Automated monitoring and health check tools',
            'Software deployment and patch management systems',
            'Security scanning and vulnerability assessment tools'
        ],
        soarTrigger: 'Detection rule fires with severity Medium or higher',
        soarActions: [
            'Enrich: Query AD for user context and privilege level',
            'Enrich: Check asset tier and business criticality',
            'Analyze: Review full process tree and command-line history',
            'Contain: Isolate host if confirmed malicious (approval required)',
            'Disable: User account if credential compromise confirmed',
            'Ticket: Create incident with enrichment data attached'
        ],
        thresholds: { events: 5, window: '10 minutes', note: 'Adjust based on environmental baseline' },
        investigationSteps: [
            'Review the alert details — which events triggered and in what sequence?',
            'Validate the user account — expected activity for this role?',
            'Check the source system — is this a known endpoint?',
            'Review process tree — suspicious parent-child relationships?',
            'Check for lateral movement indicators (new host authentication)',
            'Look for persistence mechanisms (scheduled tasks, services, registry)',
            'Review network connections for C2 indicators',
            'Determine blast radius — which other systems/accounts are affected?'
        ],
        tuning: [
            'Establish baseline for normal activity volume per host/user',
            'Whitelist known administrative and automation accounts',
            'Adjust thresholds based on 30-day FP analysis',
            'Add environmental context (business hours, maintenance windows)',
            'Implement confidence scoring across correlated signals'
        ]
    }
};

// ── Template Matching Engine ───────────────────────────────────────────

function matchTemplate(ruleName) {
    const r = ruleName.toLowerCase();
    if (r.includes('powershell') || r.includes('ps1') || r.includes('script exec') || r.includes('encoded command')) return 'powershell';
    if (r.includes('rdp') || r.includes('remote desktop') || r.includes('lateral mov') || r.includes('pivot') || r.includes('smb')) return 'rdp';
    if (r.includes('mimikatz') || r.includes('credential dump') || r.includes('lsass') || r.includes('cred theft') || r.includes('hashdump') || r.includes('sam dump')) return 'mimikatz';
    if (r.includes('brute') || r.includes('password spray') || r.includes('login fail') || r.includes('authentication attack') || r.includes('credential stuff')) return 'brute';
    return 'default';
}

function matchMitre(ruleName) {
    const r = ruleName.toLowerCase();
    for (const key of Object.keys(MITRE_DB)) {
        if (key === 'default') continue;
        if (r.includes(key)) return MITRE_DB[key];
    }
    // Try broader matching
    if (r.includes('powershell') || r.includes('script') || r.includes('encoded')) return MITRE_DB.powershell;
    if (r.includes('rdp') || r.includes('lateral') || r.includes('pivot')) return MITRE_DB.rdp;
    if (r.includes('mimikatz') || r.includes('lsass') || r.includes('credential dump') || r.includes('cred')) return MITRE_DB.mimikatz;
    if (r.includes('brute') || r.includes('spray') || r.includes('password')) return MITRE_DB.brute;
    if (r.includes('phish') || r.includes('email')) return MITRE_DB.phishing;
    if (r.includes('ransom') || r.includes('encrypt')) return MITRE_DB.ransomware;
    if (r.includes('persist') || r.includes('registry') || r.includes('scheduled')) return MITRE_DB.persistence;
    if (r.includes('exfil') || r.includes('data loss') || r.includes('dlp')) return MITRE_DB.exfiltration;
    if (r.includes('priv') || r.includes('escalat') || r.includes('uac')) return MITRE_DB.privilege;
    if (r.includes('c2') || r.includes('beacon') || r.includes('cobalt')) return MITRE_DB.c2;
    if (r.includes('kerberos') || r.includes('golden') || r.includes('roast')) return MITRE_DB.kerberos;
    if (r.includes('dns') || r.includes('tunnel')) return MITRE_DB.dns;
    if (r.includes('wmi')) return MITRE_DB.wmi;
    return MITRE_DB.default;
}

// ── Rule Generation Engine ─────────────────────────────────────────────

function generateDetectionRule(ruleName) {
    const templateKey = matchTemplate(ruleName);
    const template = DETECTION_TEMPLATES[templateKey];
    const mitre = matchMitre(ruleName);
    const context = getDetectionContext(ruleName);
    const timestamp = new Date().toISOString().split('T')[0];

    return {
        ruleName: ruleName,
        templateKey: templateKey,
        mitre: mitre,
        context: context,
        template: template,
        generatedAt: timestamp
    };
}

// ── CrowdStrike-Specific Templates ─────────────────────────────────────

const CROWDSTRIKE_TEMPLATES = {
    powershell: {
        ioa: [
            { name: 'Encoded PowerShell Execution', severity: 'High', desc: 'powershell.exe launched with -EncodedCommand, -enc, or -e flag', action: 'Detect + Prevent' },
            { name: 'Office Spawns PowerShell', severity: 'Critical', desc: 'winword.exe / excel.exe / outlook.exe spawns powershell.exe', action: 'Detect + Prevent' },
            { name: 'PowerShell AMSI Bypass', severity: 'Critical', desc: 'Script block contains AmsiUtils, amsiInitFailed, or AMSI patch patterns', action: 'Detect + Kill' },
            { name: 'PowerShell Download Cradle', severity: 'High', desc: 'Net.WebClient.DownloadString or Invoke-WebRequest to external URL', action: 'Detect + Block' },
            { name: 'PowerShell Reflection Assembly Load', severity: 'High', desc: 'Reflection.Assembly.Load or Add-Type with DllImport in script block', action: 'Detect + Prevent' }
        ],
        ioc: [
            { type: 'Domain', value: 'pastebin.com/raw/*', context: 'Common PowerShell payload hosting' },
            { type: 'Domain', value: '*.ngrok.io', context: 'Reverse shell tunnel endpoint' },
            { type: 'Hash (SHA256)', value: '[SharpHound.exe hash]', context: 'BloodHound AD collector' },
            { type: 'Hash (SHA256)', value: '[Rubeus.exe hash]', context: 'Kerberos abuse tool' },
            { type: 'File Path', value: 'C:\\Users\\Public\\*.ps1', context: 'Common payload drop location' }
        ],
        policy: [
            { name: 'Script-Based Execution Monitoring', setting: 'ENABLED', desc: 'Monitor all PowerShell, VBScript, JScript execution' },
            { name: 'Interpreter-Only Mode', setting: 'CAUTIOUS', desc: 'Block unsigned scripts running via PowerShell' },
            { name: 'AMSI Integration', setting: 'ENABLED', desc: 'Falcon AMSI scanning for in-memory script content' },
            { name: 'Suspicious Script Behavior', setting: 'AGGRESSIVE', desc: 'Kill process on encoded command + download pattern' }
        ],
        response: [
            { step: 1, action: 'RTR: Get process tree', cmd: 'ps -tree' },
            { step: 2, action: 'RTR: Get script content', cmd: 'get "C:\\Users\\Public\\payload.ps1"' },
            { step: 3, action: 'RTR: Kill malicious process', cmd: 'kill <PID>' },
            { step: 4, action: 'RTR: Check persistence', cmd: 'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
            { step: 5, action: 'API: Network contain host', cmd: 'POST /devices/entities/devices-actions/v2?action_name=contain' },
            { step: 6, action: 'API: Add IOC to blocklist', cmd: 'POST /indicators/entities/iocs/v1' }
        ]
    },
    rdp: {
        ioa: [
            { name: 'RDP Session Spawns Shell', severity: 'High', desc: 'cmd.exe or powershell.exe spawned under RDP session within 120s of logon', action: 'Detect' },
            { name: 'RDP Velocity Anomaly', severity: 'Critical', desc: 'Same account authenticates via RDP to 3+ distinct hosts in 30 minutes', action: 'Detect + Alert' },
            { name: 'Post-RDP Credential Access', severity: 'Critical', desc: 'LSASS access by non-system process under RDP session', action: 'Detect + Prevent' },
            { name: 'RDP + SMB Lateral Pivot', severity: 'High', desc: 'RDP login followed by ADMIN$ or C$ share access to different host', action: 'Detect' }
        ],
        ioc: [
            { type: 'Named Pipe', value: '\\\\.\\pipe\\atsvc', context: 'PsExec lateral movement indicator' },
            { type: 'Named Pipe', value: '\\\\.\\pipe\\svcctl', context: 'Remote service creation' },
            { type: 'File Path', value: 'C:\\Windows\\Temp\\debug.bin', context: 'Mimikatz dump output path' },
            { type: 'Network', value: 'Internal:3389 > 3 unique destinations/30m', context: 'RDP sweep detection' }
        ],
        policy: [
            { name: 'Lateral Movement Detection', setting: 'AGGRESSIVE', desc: 'Detect credential abuse across multiple hosts' },
            { name: 'Credential Theft Prevention', setting: 'ENABLED', desc: 'Block LSASS access by non-approved processes' },
            { name: 'Remote Service Monitoring', setting: 'ENABLED', desc: 'Monitor PsExec, WMI, WinRM lateral movement' }
        ],
        response: [
            { step: 1, action: 'RTR: List active sessions', cmd: 'qwinsta' },
            { step: 2, action: 'RTR: Check recent processes', cmd: 'ps -tree' },
            { step: 3, action: 'RTR: Kill attacker session', cmd: 'logoff <session_id>' },
            { step: 4, action: 'API: Network contain both hosts', cmd: 'POST /devices/entities/devices-actions/v2?action_name=contain' },
            { step: 5, action: 'API: Disable user in AD', cmd: 'Disable-ADAccount -Identity $user' }
        ]
    },
    mimikatz: {
        ioa: [
            { name: 'LSASS Memory Read', severity: 'Critical', desc: 'Non-SYSTEM, non-AV process opens handle to lsass.exe with 0x1010/0x1410 access', action: 'Detect + Prevent' },
            { name: 'Comsvcs MiniDump', severity: 'Critical', desc: 'rundll32.exe loads comsvcs.dll with MiniDump export targeting lsass PID', action: 'Detect + Kill' },
            { name: 'SAM/SYSTEM Hive Export', severity: 'Critical', desc: 'reg.exe save targeting HKLM\\SAM or HKLM\\SYSTEM', action: 'Detect + Prevent' },
            { name: 'NTDS.dit Extraction', severity: 'Critical', desc: 'ntdsutil.exe creating IFM snapshot for domain credential dump', action: 'Detect + Kill' }
        ],
        ioc: [
            { type: 'Hash (SHA256)', value: '[mimikatz.exe hash]', context: 'Mimikatz credential dumper' },
            { type: 'Hash (SHA256)', value: '[procdump.exe hash]', context: 'Sysinternals — used for LSASS dumping' },
            { type: 'File Path', value: 'C:\\Windows\\Temp\\*.dmp', context: 'LSASS memory dump files' },
            { type: 'File Path', value: 'C:\\Windows\\Temp\\sam', context: 'Extracted SAM database' },
            { type: 'File Path', value: 'C:\\ProgramData\\*.kirbi', context: 'Kerberos ticket exports' }
        ],
        policy: [
            { name: 'Credential Theft Prevention', setting: 'MAXIMUM', desc: 'Block all non-approved LSASS access attempts' },
            { name: 'Memory Scanning', setting: 'AGGRESSIVE', desc: 'Scan process memory for Mimikatz signatures' },
            { name: 'Sensor Tamper Protection', setting: 'ENABLED', desc: 'Prevent attackers from disabling Falcon sensor' }
        ],
        response: [
            { step: 1, action: 'API: Immediate host isolation', cmd: 'POST /devices/entities/devices-actions/v2?action_name=contain' },
            { step: 2, action: 'RTR: Kill credential dump process', cmd: 'kill <PID>' },
            { step: 3, action: 'RTR: Collect dump files', cmd: 'get "C:\\Windows\\Temp\\*.dmp"' },
            { step: 4, action: 'RTR: Check persistence', cmd: 'runscript -CloudFile="GetPersistence"' },
            { step: 5, action: 'API: Reset all logged-in user passwords', cmd: 'Force password reset via AD API' },
            { step: 6, action: 'Hunt: Search hash across all endpoints', cmd: 'POST /indicators/queries/iocs/v1' }
        ]
    },
    brute: {
        ioa: [
            { name: 'Authentication Brute Force', severity: 'Medium', desc: '10+ failed login attempts from single IP within 10 minutes', action: 'Detect + Alert' },
            { name: 'Password Spray Pattern', severity: 'High', desc: '5+ unique users targeted from single IP with 1-2 attempts each', action: 'Detect + Block IP' },
            { name: 'Brute Force Success', severity: 'Critical', desc: 'Successful login immediately following burst of failures from same source', action: 'Detect + Isolate' }
        ],
        ioc: [
            { type: 'IP Range', value: '[Attacker source IPs from threat feeds]', context: 'Known brute force infrastructure' },
            { type: 'User-Agent', value: 'python-requests/*', context: 'Automated credential testing tool' },
            { type: 'Network', value: '>10 auth failures from single IP in 10m', context: 'Brute force threshold' }
        ],
        policy: [
            { name: 'Identity Protection', setting: 'ENABLED', desc: 'Falcon Identity Threat Detection for auth anomalies' },
            { name: 'Suspicious Authentication', setting: 'CAUTIOUS', desc: 'Alert on brute force patterns, block on spray' }
        ],
        response: [
            { step: 1, action: 'API: Check source IP reputation', cmd: 'GET /intel/combined/indicators/v1?filter=indicator:$IP' },
            { step: 2, action: 'Firewall: Block source IP', cmd: 'Add to perimeter blocklist' },
            { step: 3, action: 'AD: Lock targeted accounts', cmd: 'Lock-ADAccount -Identity $users' },
            { step: 4, action: 'API: Investigate post-auth activity', cmd: 'GET /detects/queries/detects/v1?filter=device.hostname:$host' }
        ]
    },
    default: {
        ioa: [
            { name: 'Suspicious Process Execution', severity: 'Medium', desc: 'Process spawned from non-standard parent with suspicious command-line', action: 'Detect' },
            { name: 'Encoded Command Line', severity: 'High', desc: 'Base64 or hex encoded arguments in process command line', action: 'Detect + Alert' }
        ],
        ioc: [
            { type: 'Hash', value: '[Suspicious binary hash]', context: 'Unknown binary execution' },
            { type: 'Domain', value: '[C2 domain from threat intel]', context: 'Command and control endpoint' }
        ],
        policy: [
            { name: 'Next-Gen AV', setting: 'AGGRESSIVE', desc: 'Machine learning + behavioral detection' },
            { name: 'Script Monitoring', setting: 'ENABLED', desc: 'Monitor all scripting engine execution' }
        ],
        response: [
            { step: 1, action: 'RTR: Investigate process tree', cmd: 'ps -tree' },
            { step: 2, action: 'RTR: Collect suspicious files', cmd: 'get <file_path>' },
            { step: 3, action: 'API: Contain if confirmed malicious', cmd: 'POST /devices/entities/devices-actions/v2?action_name=contain' }
        ]
    }
};

// ── Active Tab State ──────────────────────────────────────────────────

let _activeDetTab = 'detection';

function _switchDetTab(tabId) {
    _activeDetTab = tabId;
    document.querySelectorAll('.det-tab-btn').forEach(b => {
        b.classList.toggle('det-tab-active', b.dataset.tab === tabId);
    });
    document.querySelectorAll('.det-tab-panel').forEach(p => {
        p.style.display = p.id === ('det-panel-' + tabId) ? 'block' : 'none';
    });
}

// ── UI Renderer ────────────────────────────────────────────────────────

function loadDetectionGenerator() {
    document.getElementById('dashboard').classList.add('hidden');
    const content = document.getElementById('page-content');
    content.classList.remove('hidden');
    content.scrollTop = 0;

    content.innerHTML = `
    <div style="max-width:1200px;margin:0 auto;padding:24px">
        <!-- Header -->
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
            <div style="display:flex;align-items:center;gap:12px">
                <button class="btn-hack" onclick="goHome()" style="padding:6px 14px;font-size:12px">&#9664; Back</button>
                <div>
                    <h1 style="font-size:22px;font-weight:700;color:var(--text-primary);margin:0;border:none;padding:0">AI DETECTION GENERATOR</h1>
                    <p style="font-size:12px;color:var(--text-muted);margin:2px 0 0">Enter attack name — get SIEM + EDR + SOAR + XDR detection & response instantly</p>
                </div>
            </div>
            <button onclick="_runDemo()" id="det-demo-btn"
                style="padding:10px 24px;font-size:13px;font-weight:700;font-family:var(--font-sans);background:linear-gradient(135deg,var(--green),#059669);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;white-space:nowrap;transition:all 0.2s;letter-spacing:0.5px;box-shadow:0 2px 12px rgba(34,197,94,0.3)"
                onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                &#9654; TRY DEMO
            </button>
        </div>

        <!-- Input Section -->
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;margin-bottom:24px;box-shadow:var(--shadow)">
            <label style="font-size:11px;font-weight:700;color:var(--text-dim);display:block;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase">Enter Attack / Rule Name</label>
            <div style="display:flex;gap:10px;align-items:stretch">
                <input type="text" id="det-gen-input" placeholder="e.g. Credential dumping via Mimikatz, Suspicious PowerShell, RDP Lateral Movement..."
                    style="flex:1;padding:14px 18px;font-size:15px;font-family:var(--font-sans);border:2px solid var(--border);border-radius:var(--radius);background:var(--bg-primary);color:var(--text-primary);outline:none;transition:border-color 0.2s"
                    onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'"
                    onkeydown="if(event.key==='Enter')runDetectionGenerator()">
                <select id="det-gen-platform" onchange="_onPlatformChange()"
                    style="padding:14px 14px;font-size:13px;font-family:var(--font-sans);border:2px solid var(--border);border-radius:var(--radius);background:var(--bg-primary);color:var(--text-primary);cursor:pointer;outline:none;min-width:180px">
                    <option value="ALL">All Platforms</option>
                    <option value="CrowdStrike">CrowdStrike Falcon</option>
                    <option value="Splunk">Splunk SIEM</option>
                    <option value="Microsoft Sentinel">Microsoft Sentinel</option>
                    <option value="Elastic SIEM">Elastic SIEM</option>
                    <option value="Palo Alto Cortex XDR">Cortex XDR</option>
                    <option value="QRadar">IBM QRadar</option>
                    <option value="Wazuh">Wazuh</option>
                </select>
                <button onclick="runDetectionGenerator()" id="det-gen-btn"
                    style="padding:14px 32px;font-size:14px;font-weight:700;font-family:var(--font-sans);background:var(--accent);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;white-space:nowrap;transition:all 0.2s;letter-spacing:0.5px"
                    onmouseover="this.style.boxShadow='0 4px 20px rgba(59,130,246,0.4)'" onmouseout="this.style.boxShadow='none'">
                    GENERATE DETECTION
                </button>
            </div>
            <!-- Platform Badge -->
            <div id="det-platform-badge" style="margin-top:10px;font-size:12px;color:var(--text-dim)"></div>
            <!-- Quick Picks -->
            <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center">
                <span style="font-size:11px;color:var(--text-muted);padding:4px 0">Quick picks:</span>
                ${['Suspicious PowerShell Execution', 'RDP Lateral Movement', 'Credential Dumping (Mimikatz)', 'Brute Force / Password Spray', 'Ransomware Encryption', 'Kerberoasting Attack', 'DNS Tunneling', 'WMI Remote Execution'].map(q =>
                    `<button onclick="document.getElementById('det-gen-input').value='${q}';runDetectionGenerator()"
                        style="padding:4px 12px;font-size:11px;font-family:var(--font-mono);background:var(--bg-tertiary);border:1px solid var(--border);border-radius:20px;cursor:pointer;color:var(--text-secondary);transition:all 0.2s"
                        onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--accent)'" onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--text-secondary)'">${q}</button>`
                ).join('')}
            </div>
        </div>

        <!-- Output Container -->
        <div id="det-gen-output"></div>
    </div>`;

    _onPlatformChange();
}

function _onPlatformChange() {
    const p = document.getElementById('det-gen-platform');
    const badge = document.getElementById('det-platform-badge');
    if (!p || !badge) return;
    if (p.value === 'CrowdStrike') {
        badge.innerHTML = '<span style="color:var(--orange);font-weight:600">CROWDSTRIKE MODE</span> — Output will include IOA, IOC, Prevention Policy, RTR Response';
    } else if (p.value === 'ALL') {
        badge.innerHTML = '';
    } else {
        badge.innerHTML = '<span style="color:var(--accent);font-weight:600">' + _esc(p.value).toUpperCase() + ' FOCUS</span> — Prioritized queries and platform-specific detection format';
    }
}

function _runDemo() {
    const input = document.getElementById('det-gen-input');
    const platform = document.getElementById('det-gen-platform');
    if (input) input.value = 'Credential dumping via Mimikatz';
    if (platform) { platform.value = 'CrowdStrike'; _onPlatformChange(); }
    runDetectionGenerator();
}

function runDetectionGenerator() {
    const input = document.getElementById('det-gen-input');
    const platformSelect = document.getElementById('det-gen-platform');
    const btn = document.getElementById('det-gen-btn');
    const output = document.getElementById('det-gen-output');
    const ruleName = input.value.trim();
    const platformFocus = platformSelect.value;

    if (!ruleName) {
        input.style.borderColor = 'var(--red)';
        setTimeout(() => { input.style.borderColor = 'var(--border)'; }, 1500);
        return;
    }

    btn.textContent = 'GENERATING...';
    btn.style.opacity = '0.6';
    btn.disabled = true;
    output.innerHTML = `
    <div style="text-align:center;padding:60px 20px">
        <div style="display:inline-block;width:44px;height:44px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:detspin 0.8s linear infinite"></div>
        <p style="margin-top:16px;font-size:14px;color:var(--text-secondary)">Generating detection for: <strong style="color:var(--text-primary)">${_esc(ruleName)}</strong></p>
        <p style="font-size:12px;color:var(--text-muted);margin-top:4px">Platform: ${_esc(platformFocus)} | Analyzing attack patterns...</p>
    </div>
    <style>@keyframes detspin{to{transform:rotate(360deg)}}</style>`;

    // Try API first, fall back to local
    generateDetectionViaAPI(ruleName).then(apiResult => {
        let result;
        if (apiResult && apiResult.source === 'claude-api') {
            result = { ruleName, templateKey: 'api', mitre: apiResult.data.mitre || matchMitre(ruleName), context: getDetectionContext(ruleName), template: apiResult.data, generatedAt: new Date().toISOString().split('T')[0] };
        } else {
            result = generateDetectionRule(ruleName);
        }
        result.platformFocus = platformFocus;
        renderDetectionOutput(result);
        btn.textContent = 'GENERATE DETECTION';
        btn.style.opacity = '1';
        btn.disabled = false;
    }).catch(() => {
        const result = generateDetectionRule(ruleName);
        result.platformFocus = platformFocus;
        renderDetectionOutput(result);
        btn.textContent = 'GENERATE DETECTION';
        btn.style.opacity = '1';
        btn.disabled = false;
    });
}

// ── Tabbed Card Output Renderer ────────────────────────────────────────

function renderDetectionOutput(result) {
    const output = document.getElementById('det-gen-output');
    const t = result.template;
    const mitre = result.mitre;
    const pf = result.platformFocus;
    const isCrowdStrike = pf === 'CrowdStrike';

    // Get CrowdStrike template
    const csKey = matchTemplate(result.ruleName);
    const cs = CROWDSTRIKE_TEMPLATES[csKey] || CROWDSTRIKE_TEMPLATES.default;

    const severityColors = { 'Critical': 'var(--red)', 'High': 'var(--orange)', 'Medium': 'var(--yellow)', 'Low': 'var(--green)' };
    const severityBg = { 'Critical': 'var(--red-dim)', 'High': 'var(--orange-dim)', 'Medium': 'var(--yellow-dim)', 'Low': 'var(--green-dim)' };

    // Define tabs based on platform
    const tabs = isCrowdStrike
        ? [
            { id: 'ioa', label: 'IOA', icon: '&#128065;' },
            { id: 'ioc', label: 'IOC', icon: '&#128270;' },
            { id: 'policy', label: 'Policy', icon: '&#128736;' },
            { id: 'response', label: 'Response', icon: '&#128680;' },
            { id: 'detection', label: 'SIEM', icon: '&#128202;' },
            { id: 'mitre', label: 'MITRE', icon: '&#127919;' }
          ]
        : [
            { id: 'detection', label: 'Detection (SIEM)', icon: '&#128202;' },
            { id: 'endpoint', label: 'Endpoint (EDR)', icon: '&#128187;' },
            { id: 'correlation', label: 'Correlation (XDR)', icon: '&#128279;' },
            { id: 'response', label: 'Response (SOAR)', icon: '&#128680;' },
            { id: 'mitre', label: 'MITRE', icon: '&#127919;' }
          ];

    const defaultTab = isCrowdStrike ? 'ioa' : 'detection';
    _activeDetTab = defaultTab;

    output.innerHTML = `
    <!-- Rule Header Card -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px 24px;margin-bottom:20px;box-shadow:var(--shadow);position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--cyan),var(--purple))"></div>
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
            <div style="flex:1;min-width:300px">
                <div style="font-size:10px;font-weight:700;color:var(--text-muted);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">DETECTION RULE</div>
                <div style="font-size:20px;font-weight:800;color:var(--text-primary);line-height:1.3">${_esc(result.ruleName)}</div>
                <div style="font-size:12px;color:var(--text-dim);margin-top:6px">
                    ${result.generatedAt} &nbsp;|&nbsp; ${isCrowdStrike ? '<span style="color:var(--orange);font-weight:700">CROWDSTRIKE FALCON</span>' : '<span style="color:var(--accent);font-weight:600">' + _esc(pf) + '</span>'} &nbsp;|&nbsp; Template: ${result.templateKey.toUpperCase()}
                </div>
            </div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                <div style="text-align:center;padding:10px 18px;background:${severityBg[t.severity]};border:1px solid ${severityColors[t.severity]};border-radius:var(--radius)">
                    <div style="font-size:18px;font-weight:800;color:${severityColors[t.severity]}">${t.severity.toUpperCase()}</div>
                    <div style="font-size:9px;color:var(--text-dim);margin-top:2px;letter-spacing:1px">SEVERITY</div>
                </div>
                <div style="text-align:center;padding:10px 18px;background:var(--accent-dim);border:1px solid var(--accent);border-radius:var(--radius)">
                    <div style="font-size:18px;font-weight:800;color:var(--accent)">${t.thresholds.events}</div>
                    <div style="font-size:9px;color:var(--text-dim);margin-top:2px;letter-spacing:1px">EVENTS</div>
                </div>
                <div style="text-align:center;padding:10px 18px;background:var(--cyan-dim);border:1px solid var(--cyan);border-radius:var(--radius)">
                    <div style="font-size:14px;font-weight:800;color:var(--cyan)">${t.thresholds.window}</div>
                    <div style="font-size:9px;color:var(--text-dim);margin-top:2px;letter-spacing:1px">WINDOW</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Tab Navigation -->
    <div style="display:flex;gap:4px;margin-bottom:0;overflow-x:auto;padding-bottom:0">
        ${tabs.map(tab => `
        <button class="det-tab-btn${tab.id === defaultTab ? ' det-tab-active' : ''}" data-tab="${tab.id}" onclick="_switchDetTab('${tab.id}')"
            style="padding:12px 20px;font-size:13px;font-weight:600;font-family:var(--font-sans);background:${tab.id === defaultTab ? 'var(--bg-card)' : 'var(--bg-tertiary)'};color:${tab.id === defaultTab ? 'var(--accent)' : 'var(--text-dim)'};border:1px solid ${tab.id === defaultTab ? 'var(--accent)' : 'var(--border)'};border-bottom:${tab.id === defaultTab ? '2px solid var(--accent)' : '1px solid var(--border)'};border-radius:var(--radius) var(--radius) 0 0;cursor:pointer;white-space:nowrap;transition:all 0.15s;display:flex;align-items:center;gap:6px">
            <span>${tab.icon}</span> ${tab.label}
        </button>`).join('')}
    </div>

    <!-- Tab Panels Container -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius-lg) var(--radius-lg);padding:24px;margin-bottom:20px;box-shadow:var(--shadow);min-height:400px">

        ${isCrowdStrike ? `
        <!-- IOA Panel (CrowdStrike) -->
        <div class="det-tab-panel" id="det-panel-ioa" style="display:block">
            <div style="font-size:16px;font-weight:700;color:var(--orange);margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <span>&#128065;</span> Indicators of Attack (IOA) — Behavioral Detection
            </div>
            <div style="display:grid;gap:12px">
                ${cs.ioa.map(ioa => `
                <div style="background:var(--bg-primary);border:1px solid var(--border);border-left:4px solid ${severityColors[ioa.severity]};border-radius:var(--radius);padding:16px;display:flex;justify-content:space-between;align-items:flex-start;gap:16px">
                    <div style="flex:1">
                        <div style="font-size:14px;font-weight:700;color:var(--text-primary);margin-bottom:4px">${_esc(ioa.name)}</div>
                        <div style="font-size:12px;color:var(--text-secondary);line-height:1.6">${_esc(ioa.desc)}</div>
                    </div>
                    <div style="display:flex;gap:8px;flex-shrink:0;align-items:center">
                        <span style="padding:3px 10px;font-size:10px;font-weight:700;border-radius:20px;background:${severityBg[ioa.severity]};color:${severityColors[ioa.severity]}">${ioa.severity}</span>
                        <span style="padding:3px 10px;font-size:10px;font-weight:600;border-radius:20px;background:var(--accent-dim);color:var(--accent)">${_esc(ioa.action)}</span>
                    </div>
                </div>`).join('')}
            </div>
        </div>

        <!-- IOC Panel (CrowdStrike) -->
        <div class="det-tab-panel" id="det-panel-ioc" style="display:none">
            <div style="font-size:16px;font-weight:700;color:var(--red);margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <span>&#128270;</span> Indicators of Compromise (IOC) — Blocklist
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:13px">
                <tr style="background:var(--bg-tertiary)">
                    <th style="text-align:left;padding:10px 14px;border:1px solid var(--border);font-weight:600;font-size:11px;letter-spacing:0.5px">Type</th>
                    <th style="text-align:left;padding:10px 14px;border:1px solid var(--border);font-weight:600;font-size:11px;letter-spacing:0.5px">Value</th>
                    <th style="text-align:left;padding:10px 14px;border:1px solid var(--border);font-weight:600;font-size:11px;letter-spacing:0.5px">Context</th>
                </tr>
                ${cs.ioc.map(ioc => `
                <tr>
                    <td style="padding:10px 14px;border:1px solid var(--border)"><span style="padding:2px 8px;font-size:10px;font-weight:600;border-radius:20px;background:var(--red-dim);color:var(--red)">${_esc(ioc.type)}</span></td>
                    <td style="padding:10px 14px;border:1px solid var(--border);font-family:var(--font-mono);font-size:12px;color:var(--text-primary)">${_esc(ioc.value)}</td>
                    <td style="padding:10px 14px;border:1px solid var(--border);color:var(--text-secondary)">${_esc(ioc.context)}</td>
                </tr>`).join('')}
            </table>
            <div style="margin-top:16px;padding:12px 16px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-dim)">
                <strong style="color:var(--text-secondary)">API Endpoint:</strong> <code style="color:var(--cyan);font-family:var(--font-mono)">POST /indicators/entities/iocs/v1</code> — Add IOCs to Falcon blocklist with detect/prevent action
            </div>
        </div>

        <!-- Policy Panel (CrowdStrike) -->
        <div class="det-tab-panel" id="det-panel-policy" style="display:none">
            <div style="font-size:16px;font-weight:700;color:var(--purple);margin-bottom:16px;display:flex;align-items:center;gap:8px">
                <span>&#128736;</span> Falcon Prevention Policy Configuration
            </div>
            <div style="display:grid;gap:10px">
                ${cs.policy.map(p => `
                <div style="background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);padding:16px;display:flex;justify-content:space-between;align-items:center;gap:16px">
                    <div style="flex:1">
                        <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:2px">${_esc(p.name)}</div>
                        <div style="font-size:12px;color:var(--text-secondary)">${_esc(p.desc)}</div>
                    </div>
                    <span style="padding:4px 14px;font-size:11px;font-weight:700;border-radius:20px;background:var(--green-dim);color:var(--green);white-space:nowrap;letter-spacing:0.5px">${_esc(p.setting)}</span>
                </div>`).join('')}
            </div>
        </div>
        ` : `
        <!-- Endpoint/EDR Panel (non-CrowdStrike) -->
        <div class="det-tab-panel" id="det-panel-endpoint" style="display:none">
            <div style="font-size:16px;font-weight:700;color:var(--accent);margin-bottom:16px">Endpoint Detection (EDR)</div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Process Behavior</div>
            <div style="padding:12px 16px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;color:var(--text-secondary);margin-bottom:16px">${_esc(t.edrProcess)}</div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Parent-Child Process Tree</div>
            ${_codeBlock(t.edrParentChild, 'text')}

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin:16px 0 8px">Command-Line Indicators</div>
            <div style="display:flex;flex-direction:column;gap:4px;margin-bottom:16px">
                ${t.edrCmdIndicators.map(c => `
                <div style="padding:8px 14px;background:var(--bg-primary);border:1px solid var(--border);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--text-primary);word-break:break-all">${_esc(c)}</div>`).join('')}
            </div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">IOA (Behavioral Indicators)</div>
            <div style="display:grid;gap:8px">
                ${t.ioa.map(i => `
                <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:var(--bg-primary);border:1px solid var(--border);border-left:3px solid var(--orange);border-radius:var(--radius)">
                    <span style="color:var(--orange);font-weight:bold;flex-shrink:0">&#9670;</span>
                    <span style="font-size:13px;color:var(--text-secondary)">${_esc(i)}</span>
                </div>`).join('')}
            </div>
        </div>

        <!-- XDR Correlation Panel -->
        <div class="det-tab-panel" id="det-panel-correlation" style="display:none">
            <div style="font-size:16px;font-weight:700;color:var(--cyan);margin-bottom:16px">XDR Cross-Signal Correlation</div>

            <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
                ${[
                    ['&#128100;','Identity Layer','var(--accent)','Authentication events (4624, 4625, 4672)','Source IP, user, logon type, privilege'],
                    ['&#128187;','Endpoint Layer','var(--orange)','Process creation, script execution, file/registry','Process tree, command-line, IOA matches'],
                    ['&#127760;','Network Layer','var(--cyan)','SMB (445), RDP (3389), DNS, HTTP/S','Connection volume, destination, data size']
                ].map(([icon,title,color,desc,details]) => `
                <div style="background:var(--bg-primary);border:1px solid var(--border);border-top:3px solid ${color};border-radius:var(--radius);padding:16px">
                    <div style="font-size:20px;margin-bottom:8px">${icon}</div>
                    <div style="font-size:13px;font-weight:700;color:${color};margin-bottom:6px">${title}</div>
                    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;line-height:1.5">${desc}</div>
                    <div style="font-size:11px;color:var(--text-muted)">${details}</div>
                </div>`).join('')}
            </div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Attack Chain Timeline</div>
            <div style="display:flex;gap:0;overflow-x:auto;margin-bottom:16px">
                ${['Initial Access|T+0|RDP / Phish / Exploit|var(--red)', 'Execution|T+2m|PowerShell / cmd|var(--orange)', 'Credential Access|T+5m|LSASS / SAM dump|var(--yellow)', 'Lateral Movement|T+15m|SMB / RDP pivot|var(--purple)'].map((s,i) => {
                    const [phase,time,action,color] = s.split('|');
                    return `<div style="flex:1;min-width:140px;text-align:center;padding:14px 10px;background:var(--bg-primary);border:1px solid var(--border);${i===0?'border-radius:var(--radius) 0 0 var(--radius)':i===3?'border-radius:0 var(--radius) var(--radius) 0':''}">
                        <div style="font-size:10px;font-weight:700;color:${color};letter-spacing:1px;text-transform:uppercase">${phase}</div>
                        <div style="font-size:16px;font-weight:800;color:var(--text-primary);margin:6px 0">${time}</div>
                        <div style="font-size:11px;color:var(--text-dim)">${action}</div>
                    </div>`;
                }).join('')}
            </div>

            <div style="padding:14px 16px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-secondary);line-height:1.7">
                Alert fires when signals from <strong style="color:var(--text-primary)">2+ layers</strong> correlate within the detection window for the same user/host. XDR unifies identity + endpoint + network into a single incident timeline.
            </div>
        </div>
        `}

        <!-- Detection/SIEM Panel -->
        <div class="det-tab-panel" id="det-panel-detection" style="${defaultTab === 'detection' ? 'display:block' : 'display:none'}">
            <div style="font-size:16px;font-weight:700;color:var(--accent);margin-bottom:16px">SIEM Detection Queries</div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Log Sources</div>
            <table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px">
                <tr style="background:var(--bg-tertiary)">
                    <th style="text-align:left;padding:8px 12px;border:1px solid var(--border);font-weight:600">Source</th>
                    <th style="text-align:left;padding:8px 12px;border:1px solid var(--border);font-weight:600">Event ID</th>
                    <th style="text-align:left;padding:8px 12px;border:1px solid var(--border);font-weight:600">Purpose</th>
                </tr>
                ${t.logSources.map(l => `
                <tr>
                    <td style="padding:8px 12px;border:1px solid var(--border);font-weight:500">${l.source}</td>
                    <td style="padding:8px 12px;border:1px solid var(--border);font-family:var(--font-mono);color:var(--accent)">${l.eventId}</td>
                    <td style="padding:8px 12px;border:1px solid var(--border);color:var(--text-secondary)">${l.purpose}</td>
                </tr>`).join('')}
            </table>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">SPLUNK SPL</div>
            ${_codeBlock(t.splunk, 'spl')}

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin:16px 0 8px">MICROSOFT SENTINEL KQL</div>
            ${_codeBlock(t.kql, 'kql')}
        </div>

        <!-- Response/SOAR Panel -->
        <div class="det-tab-panel" id="det-panel-response" style="display:none">
            <div style="font-size:16px;font-weight:700;color:var(--red);margin-bottom:16px">${isCrowdStrike ? 'CrowdStrike RTR + API Response' : 'SOAR Automated Response'}</div>

            ${isCrowdStrike ? `
            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:10px">RTR + API Response Steps</div>
            <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px">
                ${cs.response.map(r => `
                <div style="display:flex;align-items:flex-start;gap:12px;padding:12px 16px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius)">
                    <div style="width:28px;height:28px;background:var(--accent-dim);border:1px solid var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;color:var(--accent);flex-shrink:0">${r.step}</div>
                    <div style="flex:1">
                        <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:2px">${_esc(r.action)}</div>
                        <code style="font-size:11px;font-family:var(--font-mono);color:var(--cyan);background:var(--bg-tertiary);padding:2px 8px;border-radius:4px">${_esc(r.cmd)}</code>
                    </div>
                </div>`).join('')}
            </div>
            ` : `
            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Trigger Condition</div>
            <div style="padding:12px 16px;background:var(--bg-primary);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:var(--radius);font-size:13px;color:var(--text-primary);margin-bottom:16px">${_esc(t.soarTrigger)}</div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Automated Actions</div>
            <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:16px">
                ${t.soarActions.map((a, i) => {
                    const [action, ...rest] = a.split(': ');
                    const detail = rest.join(': ');
                    const colors = ['var(--cyan)', 'var(--accent)', 'var(--red)', 'var(--orange)', 'var(--purple)', 'var(--green)', 'var(--yellow)', 'var(--cyan)'];
                    return `<div style="display:flex;align-items:flex-start;gap:12px;padding:10px 14px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius)">
                        <span style="font-size:11px;font-weight:700;color:${colors[i % colors.length]};min-width:70px;text-transform:uppercase">${_esc(action)}</span>
                        <span style="font-size:12px;color:var(--text-secondary)">${_esc(detail)}</span>
                    </div>`;
                }).join('')}
            </div>
            `}

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin:16px 0 8px">Investigation Checklist</div>
            <div style="display:flex;flex-direction:column;gap:4px">
                ${t.investigationSteps.map((step, i) => `
                <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 12px;${i % 2 === 0 ? 'background:var(--bg-primary);' : ''}border-radius:var(--radius)">
                    <span style="font-size:12px;font-weight:700;color:var(--accent);min-width:24px;text-align:center">${i + 1}</span>
                    <span style="font-size:13px;color:var(--text-secondary);line-height:1.5">${_esc(step)}</span>
                </div>`).join('')}
            </div>
        </div>

        <!-- MITRE Panel -->
        <div class="det-tab-panel" id="det-panel-mitre" style="display:none">
            <div style="font-size:16px;font-weight:700;color:var(--purple);margin-bottom:16px">MITRE ATT&CK Mapping</div>

            <div style="display:grid;gap:10px;margin-bottom:20px">
                ${mitre.map(m => `
                <div style="display:flex;align-items:center;gap:16px;padding:14px 18px;background:var(--bg-primary);border:1px solid var(--border);border-left:4px solid var(--purple);border-radius:var(--radius)">
                    <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:var(--accent);min-width:100px">${m.id}</div>
                    <div style="flex:1;font-size:14px;font-weight:500;color:var(--text-primary)">${m.name}</div>
                    <span style="padding:4px 12px;font-size:11px;font-weight:600;border-radius:20px;background:var(--purple-dim);color:var(--purple)">${m.tactic}</span>
                </div>`).join('')}
            </div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">False Positives</div>
            <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:16px">
                ${t.falsePositives.map(fp => `
                <div style="display:flex;align-items:flex-start;gap:8px;padding:8px 14px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius)">
                    <span style="color:var(--yellow);font-weight:bold;flex-shrink:0">!</span>
                    <span style="font-size:13px;color:var(--text-secondary)">${_esc(fp)}</span>
                </div>`).join('')}
            </div>

            <div style="font-size:12px;font-weight:600;color:var(--text-dim);letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Tuning Recommendations</div>
            <div style="display:flex;flex-direction:column;gap:6px">
                ${t.tuning.map(tune => `
                <div style="display:flex;align-items:flex-start;gap:8px;padding:8px 14px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius)">
                    <span style="color:var(--green);font-weight:bold;flex-shrink:0">&#10003;</span>
                    <span style="font-size:13px;color:var(--text-secondary)">${_esc(tune)}</span>
                </div>`).join('')}
            </div>
        </div>

    </div>

    <!-- Export Bar -->
    <div style="display:flex;gap:10px;margin-bottom:40px;flex-wrap:wrap">
        <button onclick="_exportDetectionJSON('${_esc(result.ruleName).replace(/'/g, "\\'")}')" class="btn-hack" style="padding:10px 20px">Export JSON</button>
        <button onclick="_copyFullDetection()" class="btn-hack" style="padding:10px 20px">Copy All</button>
        <button onclick="window.print()" class="btn-hack" style="padding:10px 20px">Print / PDF</button>
    </div>
    `;

    // Apply active tab styles
    _applyTabStyles();

    output.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function _applyTabStyles() {
    document.querySelectorAll('.det-tab-btn').forEach(b => {
        const isActive = b.classList.contains('det-tab-active');
        b.style.background = isActive ? 'var(--bg-card)' : 'var(--bg-tertiary)';
        b.style.color = isActive ? 'var(--accent)' : 'var(--text-dim)';
        b.style.borderColor = isActive ? 'var(--accent)' : 'var(--border)';
        b.style.borderBottomWidth = isActive ? '2px' : '1px';
        b.style.borderBottomColor = isActive ? 'var(--accent)' : 'var(--border)';
    });
}

// Override _switchDetTab to also update styles
const _origSwitchDetTab = _switchDetTab;
_switchDetTab = function(tabId) {
    _activeDetTab = tabId;
    document.querySelectorAll('.det-tab-btn').forEach(b => {
        b.classList.toggle('det-tab-active', b.dataset.tab === tabId);
    });
    document.querySelectorAll('.det-tab-panel').forEach(p => {
        p.style.display = p.id === ('det-panel-' + tabId) ? 'block' : 'none';
    });
    _applyTabStyles();
};

// ── Export Functions ───────────────────────────────────────────────────

function _exportDetectionJSON(ruleName) {
    const result = generateDetectionRule(ruleName);
    const exportData = {
        rule_name: result.ruleName,
        generated_at: result.generatedAt,
        template: result.templateKey,
        mitre_attack: result.mitre,
        severity: result.template.severity,
        log_sources: result.template.logSources,
        siem: { splunk_spl: result.template.splunk, sentinel_kql: result.template.kql },
        edr: { process_behavior: result.template.edrProcess, parent_child: result.template.edrParentChild, command_line_indicators: result.template.edrCmdIndicators, ioa: result.template.ioa },
        soar: { trigger: result.template.soarTrigger, actions: result.template.soarActions },
        detection_conditions: result.template.thresholds,
        false_positives: result.template.falsePositives,
        investigation_steps: result.template.investigationSteps,
        tuning: result.template.tuning,
        context_injected: result.context
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `detection-rule-${ruleName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function _copyFullDetection() {
    const output = document.getElementById('det-gen-output');
    navigator.clipboard.writeText(output.innerText).then(() => {
        const copyBtn = Array.from(output.querySelectorAll('button')).find(b => b.textContent.includes('Copy All'));
        if (copyBtn) {
            const orig = copyBtn.textContent;
            copyBtn.textContent = 'COPIED!';
            setTimeout(() => { copyBtn.textContent = orig; }, 2000);
        }
    });
}

// ── Backend API Integration ───────────────────────────────────────────

async function generateDetectionViaAPI(ruleName) {
    const context = getDetectionContext(ruleName);
    const platformFocus = document.getElementById('det-gen-platform')?.value || 'ALL';

    // Build the prompt using master template ({{RULE_NAME}} + {{CONTEXT_DATA}} replacement)
    const prompt = buildDetectionPrompt(ruleName, platformFocus);
    console.log('[BlueShell] Prompt built for:', ruleName, '| Platform:', platformFocus);
    console.log('[BlueShell] Context injected:', context.substring(0, 100) + '...');

    try {
        const response = await fetch('/api/generate-detection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ruleName, context, platformFocus })
        });
        if (!response.ok) return null;
        return await response.json();
    } catch (e) {
        return null;
    }
}

// ── Go Home Helper ────────────────────────────────────────────────────

function goHome() {
    document.getElementById('page-content').classList.add('hidden');
    document.getElementById('page-content').innerHTML = '';
    document.getElementById('dashboard').classList.remove('hidden');
}
