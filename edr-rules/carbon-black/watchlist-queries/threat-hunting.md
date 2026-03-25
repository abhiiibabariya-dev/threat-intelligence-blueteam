# Carbon Black EDR - Threat Hunting Watchlist Queries

## Credential Access (T1003)

### LSASS Memory Dumping
```
process_name:procdump.exe cmdline:lsass
```
```
process_name:rundll32.exe cmdline:comsvcs cmdline:MiniDump
```
```
cmdline:sekurlsa OR cmdline:lsadump OR cmdline:mimikatz
```

### Registry Hive Export (T1003.002)
```
process_name:reg.exe cmdline:save (cmdline:sam OR cmdline:system OR cmdline:security)
```

## Execution (T1059)

### Suspicious PowerShell
```
process_name:powershell.exe (cmdline:-enc OR cmdline:DownloadString OR cmdline:FromBase64 OR cmdline:IEX OR cmdline:bypass OR cmdline:AmsiUtils)
```

### LOLBin Abuse (T1218)
```
(process_name:mshta.exe OR process_name:certutil.exe OR process_name:regsvr32.exe OR process_name:msbuild.exe) (cmdline:http OR cmdline:javascript OR cmdline:-decode OR cmdline:-urlcache)
```

### Script Engine Spawning Shell (T1059.005)
```
parent_name:wscript.exe OR parent_name:cscript.exe OR parent_name:mshta.exe process_name:cmd.exe OR process_name:powershell.exe
```

## Persistence (T1547)

### Scheduled Task Creation
```
process_name:schtasks.exe cmdline:/create (cmdline:powershell OR cmdline:cmd OR cmdline:wscript OR cmdline:http OR cmdline:bypass)
```

### Suspicious Service Creation (T1543.003)
```
process_name:sc.exe cmdline:create cmdline:binPath (cmdline:powershell OR cmdline:cmd OR cmdline:\\Temp\\ OR cmdline:\\AppData\\)
```

## Lateral Movement (T1021)

### PsExec Usage
```
process_name:psexec.exe OR process_name:psexec64.exe
```
```
parent_name:services.exe process_name:PSEXESVC.exe
```

### WMI Remote Execution (T1047)
```
parent_name:wmiprvse.exe (process_name:cmd.exe OR process_name:powershell.exe OR process_name:cscript.exe)
```

## Defense Evasion (T1036)

### Process Masquerading
```
process_name:svchost.exe -path:c:\\windows\\system32\\svchost.exe
```
```
process_name:lsass.exe -path:c:\\windows\\system32\\lsass.exe
```

### Process from Unusual Location
```
(path:*\\temp\\*.exe OR path:*\\downloads\\*.exe OR path:*\\appdata\\local\\temp\\*.exe)
```

## Impact (T1486)

### Ransomware Indicators
```
process_name:vssadmin.exe cmdline:"delete shadows"
```
```
process_name:wmic.exe cmdline:"shadowcopy delete"
```
```
process_name:bcdedit.exe cmdline:"recoveryenabled no"
```
