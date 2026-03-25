# LogPoint LPQL - Execution Detection (TA0002)

# LP-EXE-001: Encoded PowerShell (T1059.001)
norm_id=WindowsSysmon event_id=1 image="*powershell.exe" command_line="*-enc*"
| chart count() by host, user, command_line

# LP-EXE-002: Office Macro Execution (T1204.002)
norm_id=WindowsSysmon event_id=1
parent_image IN ["*winword.exe", "*excel.exe", "*powerpnt.exe"]
image IN ["*cmd.exe", "*powershell.exe", "*wscript.exe", "*mshta.exe"]
| chart count() by host, parent_image, image, command_line

# LP-EXE-003: LOLBAS Download (T1105)
norm_id=WindowsSysmon event_id=1
image IN ["*certutil.exe", "*bitsadmin.exe", "*mshta.exe"]
command_line="*http*"
| chart count() by host, image, command_line

# LP-EXE-004: Regsvr32 Proxy (T1218.010)
norm_id=WindowsSysmon event_id=1 image="*regsvr32.exe"
(command_line="*scrobj*" OR command_line="*/i:*")
| chart count() by host, command_line

# LP-EXE-005: Reverse Shell (T1059.004)
command_line IN ["*bash -i >& /dev/tcp*", "*nc -e /bin*", "*python -c*import socket*"]
| chart count() by host, user, command_line
