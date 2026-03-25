// Cortex XDR - XQL Threat Hunting Queries
// MITRE ATT&CK Coverage

// ── Credential Access ──

// XQL-CA-001: LSASS Memory Access (T1003.001)
dataset = xdr_data
| filter event_type = PROCESS and action_process_image_name = "lsass.exe"
| filter causality_actor_process_image_name not in ("csrss.exe","svchost.exe","MsMpEng.exe")
| fields agent_hostname, causality_actor_process_image_name, action_process_image_name, actor_process_command_line

// XQL-CA-002: Kerberoasting (T1558.003)
dataset = xdr_data
| filter event_type = ENUM and event_sub_type = "kerberos_tgs"
| filter action_kerberos_encryption_type in ("0x17","0x18")
| fields agent_hostname, actor_primary_username, action_kerberos_service_name, action_kerberos_encryption_type

// XQL-CA-003: Credential Dumping Tools (T1003)
dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "mimikatz" or actor_process_command_line contains "sekurlsa" or actor_process_command_line contains "procdump" and actor_process_command_line contains "lsass"
| fields agent_hostname, actor_primary_username, actor_process_command_line

// ── Execution ──

// XQL-EXE-001: Encoded PowerShell (T1059.001)
dataset = xdr_data
| filter event_type = PROCESS and action_process_image_name in ("powershell.exe","pwsh.exe")
| filter actor_process_command_line contains "-enc"
| fields _time, agent_hostname, actor_primary_username, actor_process_command_line

// XQL-EXE-002: Office Macro Spawning Shell (T1204.002)
dataset = xdr_data
| filter event_type = PROCESS
| filter causality_actor_process_image_name in ("winword.exe","excel.exe","powerpnt.exe")
| filter action_process_image_name in ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
| fields _time, agent_hostname, causality_actor_process_image_name, action_process_image_name, actor_process_command_line

// XQL-EXE-003: LOLBAS Execution (T1218)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe","bitsadmin.exe")
| filter actor_process_command_line contains "http" or actor_process_command_line contains "urlcache" or actor_process_command_line contains "scrobj"
| fields _time, agent_hostname, action_process_image_name, actor_process_command_line

// ── Lateral Movement ──

// XQL-LM-001: PsExec Execution (T1021.002)
dataset = xdr_data
| filter event_type = PROCESS and causality_actor_process_image_name = "psexesvc.exe"
| fields _time, agent_hostname, action_process_image_name, actor_process_command_line

// XQL-LM-002: RDP to Multiple Hosts (T1021.001)
dataset = xdr_data
| filter event_type = NETWORK and action_remote_port = 3389
| comp count(agent_hostname) as target_count by action_remote_ip
| filter target_count > 2

// XQL-LM-003: WMI Remote Process (T1047)
dataset = xdr_data
| filter event_type = PROCESS and causality_actor_process_image_name = "wmiprvse.exe"
| filter action_process_image_name in ("cmd.exe","powershell.exe","pwsh.exe")
| fields _time, agent_hostname, action_process_image_name, actor_process_command_line

// ── Persistence ──

// XQL-PER-001: Registry Run Key (T1547.001)
dataset = xdr_data
| filter event_type = REGISTRY
| filter action_registry_key_name contains "\\CurrentVersion\\Run"
| fields _time, agent_hostname, actor_process_image_name, action_registry_key_name, action_registry_value_name

// XQL-PER-002: Scheduled Task Creation (T1053.005)
dataset = xdr_data
| filter event_type = PROCESS and action_process_image_name = "schtasks.exe"
| filter actor_process_command_line contains "/create"
| fields _time, agent_hostname, actor_primary_username, actor_process_command_line

// XQL-PER-003: Suspicious Service (T1543.003)
dataset = xdr_data
| filter event_type = PROCESS and event_sub_type = "SERVICE_START"
| filter action_process_image_path contains "\\temp\\" or action_process_image_path contains "\\appdata\\"
| fields _time, agent_hostname, action_process_image_name, action_process_image_path

// ── Defense Evasion ──

// XQL-DE-001: Log Clearing (T1070.001)
dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "wevtutil" and actor_process_command_line contains "cl"
| fields _time, agent_hostname, actor_primary_username, actor_process_command_line

// XQL-DE-002: Defender Disabled (T1562.001)
dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "Set-MpPreference" and actor_process_command_line contains "DisableRealtimeMonitoring"
| fields _time, agent_hostname, actor_primary_username, actor_process_command_line

// ── Exfiltration ──

// XQL-EX-001: Cloud Upload Tool (T1567.002)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("rclone.exe","megasync.exe","gdrive.exe")
| fields _time, agent_hostname, actor_primary_username, action_process_image_name, actor_process_command_line

// XQL-EX-002: Data Archiving (T1560.001)
dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "7z a" or actor_process_command_line contains "rar a" or actor_process_command_line contains "Compress-Archive"
| fields _time, agent_hostname, actor_process_command_line

// ── Command & Control ──

// XQL-C2-001: Tunneling Tools (T1572)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("plink.exe","chisel.exe","ngrok.exe","cloudflared.exe","socat.exe")
| fields _time, agent_hostname, action_process_image_name, actor_process_command_line

// XQL-C2-002: Remote Access Tools (T1219)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("teamviewer.exe","anydesk.exe","screenconnect.exe","rustdesk.exe")
| fields _time, agent_hostname, actor_primary_username, action_process_image_name

// XQL-C2-003: DNS Tunneling Suspect (T1071.004)
dataset = xdr_data
| filter event_type = NETWORK and action_remote_port = 53
| comp count() as dns_queries by agent_hostname
| filter dns_queries > 10000
