# LogPoint LPQL - Lateral Movement Detection Queries
# MITRE ATT&CK Tactic: TA0008

# LP-LM-001: PsExec Service Installation (T1021.002)
"Windows Security" event_id=7045 service_name="*PSEXE*"
| chart count() by host, source_address, service_name

# LP-LM-002: WMI Remote Process (T1047)
norm_id=WindowsSysmon event_id=1 parent_image="*wmiprvse.exe"
image IN ["*cmd.exe", "*powershell.exe", "*pwsh.exe"]
| chart count() by host, image, command_line

# LP-LM-003: RDP Lateral Movement (T1021.001)
"Windows Security" event_id=4624 logon_type=10
| chart distinct_count(host) as unique_targets by source_address, user
| search unique_targets > 2

# LP-LM-004: Admin Share Access (T1021.002)
"Windows Security" event_id=5140 share_name IN ["*ADMIN$*", "*C$*"]
| chart count() by source_address, user, share_name, host

# LP-LM-005: WinRM Remote Shell (T1021.006)
norm_id=WindowsSysmon event_id=1 parent_image="*wsmprovhost.exe"
| chart count() by host, image, command_line

# LP-LM-006: Pass-the-Hash (T1550.002)
"Windows Security" event_id=4624 logon_type=9 authentication_package="Negotiate"
| chart count() by user, source_address, host
