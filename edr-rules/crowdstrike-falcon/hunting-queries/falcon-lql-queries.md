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
