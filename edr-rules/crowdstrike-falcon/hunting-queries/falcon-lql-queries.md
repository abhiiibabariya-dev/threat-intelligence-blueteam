# CrowdStrike Falcon LogScale (LQL) Threat Hunting Queries

## Credential Access

### LSASS Memory Access (T1003.001)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(procdump|procdump64)\.exe$/i
| CommandLine=/lsass/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Mimikatz Command Patterns (T1003)
```lql
#event_simpleName=ProcessRollup2
| CommandLine=/sekurlsa|lsadump|kerberos::(list|golden|ptt)|privilege::debug/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

## Execution

### Suspicious PowerShell (T1059.001)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/powershell|pwsh/i
| CommandLine=/(enc|FromBase64|DownloadString|WebClient|IEX|Invoke-Expression|bypass|hidden|AmsiUtils)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### LOLBin Execution (T1218)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/(mshta|certutil|regsvr32|rundll32|msbuild|cmstp|installutil)\.exe$/i
| CommandLine=/(http|javascript|vbscript|decode|urlcache|scrobj)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

## Persistence

### Scheduled Task Creation (T1053.005)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/schtasks\.exe$/i
| CommandLine=/\/create/i
| CommandLine=/(powershell|cmd|wscript|mshta|http|bypass|enc)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Service Installation (T1543.003)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/sc\.exe$/i
| CommandLine=/create.*binPath/i
| CommandLine=/(powershell|cmd|Temp|AppData|http)/i
```

## Lateral Movement

### PsExec Usage (T1021.002)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/(psexec|psexec64|PSEXESVC)\.exe$/i
| groupBy([ComputerName, UserName, CommandLine, ParentBaseFileName])
```

### WMI Remote Execution (T1047)
```lql
#event_simpleName=ProcessRollup2
| ParentBaseFileName=wmiprvse.exe
| ImageFileName=/(cmd|powershell|cscript|wscript|mshta)\.exe$/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

## Defense Evasion

### AMSI Bypass (T1562.001)
```lql
#event_simpleName=ProcessRollup2
| CommandLine=/(AmsiUtils|amsiInitFailed|AmsiScanBuffer)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### Process Masquerading (T1036.005)
```lql
#event_simpleName=ProcessRollup2
| ImageFileName=/svchost\.exe$/i
| ImageFileName!=/C:\\Windows\\System32\\svchost\.exe/i
| groupBy([ComputerName, ImageFileName, CommandLine])
```

## Impact

### Ransomware Indicators (T1486, T1490)
```lql
#event_simpleName=ProcessRollup2
| (ImageFileName=/vssadmin\.exe$/i AND CommandLine=/delete.*shadows/i)
  OR (ImageFileName=/wmic\.exe$/i AND CommandLine=/shadowcopy.*delete/i)
  OR (ImageFileName=/bcdedit\.exe$/i AND CommandLine=/recoveryenabled.*no/i)
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

## Network

### C2 Beaconing - Regular Interval Connections (T1071)
```lql
#event_simpleName=NetworkConnectIP4
| RemotePort IN [80, 443, 8080, 8443]
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count())
| sort(_count, order=desc)
| _count > 30
```

### DNS to Suspicious Domains (T1071.004)
```lql
#event_simpleName=DnsRequest
| DomainName=/.{40,}/
| groupBy([ComputerName, DomainName], function=count())
| sort(_count, order=desc)
```

---

## Linux-Specific Hunting Queries

### Linux Reverse Shell Detection (T1059.004)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(\/dev\/tcp\/|bash -i|python.*socket.*subprocess|perl.*Socket|nc.*-e.*\/bin|socat.*TCP|ruby.*TCPSocket|php.*fsockopen)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### Linux Privilege Escalation - SUID/SGID Discovery (T1548.001)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(find.*-perm.*-4000|find.*-perm.*-u=s|find.*-perm.*-2000|find.*-perm.*-g=s|find.*-perm.*\/6000)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Credential Access - Shadow File (T1003.008)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(cat|head|tail|less|more|cp|scp|rsync).*\/etc\/(shadow|gshadow)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux SSH Key Theft (T1552.004)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(cat|cp|scp|tar|zip).*\.(ssh\/id_rsa|ssh\/id_ed25519|ssh\/id_ecdsa|ssh\/authorized_keys)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Persistence - Cron/Systemd (T1053.003, T1543.002)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| (CommandLine=/(crontab|systemctl enable|systemctl daemon-reload)/i)
  OR (CommandLine=/echo.*\*.*\*.*\*.*\*.*\*.*>>.*cron/i)
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Defense Evasion - Log Tampering (T1070.002)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(truncate.*\/var\/log|>.*\/var\/log|rm.*\/var\/log|shred.*\/var\/log|history -c|unset HISTFILE|export HISTSIZE=0|journalctl.*vacuum)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Firewall Manipulation (T1562.004)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(iptables -F|iptables -X|iptables.*ACCEPT|ufw disable|systemctl stop firewalld|nft flush|firewall-cmd.*panic)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Cryptominer Detection (T1496)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(stratum\+tcp|stratum\+ssl|xmrig|cryptonight|randomx|--donate-level|mining\.pool|pool\.|--algo)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### Linux Container Escape (T1611)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(nsenter.*--target 1|mount.*cgroup.*release_agent|docker\.sock|notify_on_release|chroot.*\/mnt)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux SSH Tunneling/Pivoting (T1572)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/ssh$/
| CommandLine=/(-L |-R |-D |-N -f|StrictHostKeyChecking=no|UserKnownHostsFile=\/dev\/null|ProxyJump|-J )/
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Lateral Movement - Tool Transfer (T1570)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(wget -O \/tmp|curl -o \/tmp|python.*http\.server|nc.*<|scp.*StrictHostKeyChecking=no)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### Linux Security Tool Disabling (T1562.001)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine=/(systemctl stop falcon|service falcon-sensor stop|setenforce 0|systemctl stop apparmor|systemctl stop auditd|aa-teardown|kill.*falcon)/i
| groupBy([ComputerName, UserName, CommandLine])
```

---

## macOS-Specific Hunting Queries

### macOS Reverse Shell Detection (T1059.004)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(\/dev\/tcp\/|bash -i|zsh.*zmodload.*net\/tcp|python.*socket.*subprocess|osascript.*do shell script|nc.*-e.*\/bin|socat.*TCP)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### macOS Persistence - Launch Agent/Daemon (T1543.001, T1543.004)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(launchctl load|launchctl submit|plutil.*LaunchAgents|plutil.*LaunchDaemons|PlistBuddy.*RunAtLoad)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Keychain Credential Theft (T1555.001)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(security find-generic-password|security find-internet-password|security dump-keychain|security export -k|security unlock-keychain|chainbreaker|keychaindump)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Fake Password Prompt (T1056.002)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| ImageFileName=/osascript$/
| CommandLine=/(display dialog|default answer|hidden answer|password|credential)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Gatekeeper Bypass (T1553.001)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(spctl --master-disable|spctl --add|xattr -d com\.apple\.quarantine|xattr -r -d com\.apple\.quarantine|LSQuarantine.*NO)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Defense Evasion - TCC/SIP (T1562.001)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(tccutil reset|sqlite3.*TCC\.db|csrutil disable|csrutil authenticated-root|nvram csr-active-config)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Privilege Escalation - Dylib Injection (T1574.004)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|DYLD_FRAMEWORK_PATH|DYLD_FORCE_FLAT_NAMESPACE)/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### macOS Browser Credential Theft (T1555.003)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(Login Data|Cookies\.binarycookies|key4\.db|logins\.json|Chrome\/Default)/i
| ImageFileName!=/Google Chrome|firefox|Safari/
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### macOS Apple Remote Desktop Abuse (T1021.006)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(kickstart -activate|allowAccessFor.*allUsers|ARDAgent|VNCServer|-configure -access -on)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Malware Indicators (T1204.002)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| (CommandLine=/(osascript.*display dialog.*hidden answer.*security find)/i)
  OR (CommandLine=/(curl -s0|wget -q|base64 -D)/i AND ParentBaseFileName=/(bash|zsh|sh)/)
| groupBy([ComputerName, UserName, ImageFileName, CommandLine])
```

### macOS Falcon Sensor Tampering (T1562.001)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(launchctl unload.*crowdstrike|kextunload.*crowdstrike|systemextensionsctl uninstall|falconctl uninstall|kill.*falcon)/i
| groupBy([ComputerName, UserName, CommandLine])
```

### macOS Log Clearing (T1070.002)
```lql
#event_simpleName=ProcessRollup2
| event_platform=Mac
| CommandLine=/(log erase|rm.*\/var\/log|rm.*Library\/Logs|sqlite3.*QuarantineEvents.*delete)/i
| groupBy([ComputerName, UserName, CommandLine])
```
