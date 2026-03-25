# Carbon Black EDR - Ransomware Detection Watchlist Queries

## Shadow Copy Deletion (T1490)
```
process_name:vssadmin.exe cmdline:"delete shadows"
```
```
process_name:wmic.exe cmdline:shadowcopy cmdline:delete
```
```
process_name:bcdedit.exe (cmdline:"recoveryenabled no" OR cmdline:"bootstatuspolicy ignoreallfailures")
```
```
process_name:wbadmin.exe cmdline:"delete catalog"
```

## Backup Tampering
```
process_name:powershell.exe cmdline:Win32_ShadowCopy cmdline:Delete
```

## Mass File Operations
```
filemod_count:[500 TO *]
```

## Ransomware Tool Indicators
```
cmdline:"encrypt" OR cmdline:".locked" OR cmdline:".encrypted" OR cmdline:".crypto"
```

## Combined Pre-Ransomware Activity
```
(process_name:vssadmin.exe cmdline:delete) OR (process_name:wmic.exe cmdline:shadowcopy) OR (process_name:bcdedit.exe cmdline:recovery)
```
