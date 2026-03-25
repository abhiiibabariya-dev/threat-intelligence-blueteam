# LogPoint LPQL - Persistence Detection (TA0003)

# LP-PER-001: Registry Run Key (T1547.001)
norm_id=WindowsSysmon event_id=13 target_object="*\\CurrentVersion\\Run*"
| chart count() by host, image, target_object

# LP-PER-002: Scheduled Task (T1053.005)
"Windows Security" event_id=4698
| chart count() by host, user, task_name

# LP-PER-003: Suspicious Service (T1543.003)
"Windows Security" event_id=7045
(service_path="*cmd.exe*" OR service_path="*powershell*" OR service_path="*\\temp\\*")
| chart count() by host, service_name, service_path

# LP-PER-004: Admin Account Created (T1136.001)
"Windows Security" event_id=4720 OR ("Windows Security" event_id=4732 group="*Administrators*")
| chart count() by host, user, target_user

# LP-PER-005: WMI Persistence (T1546.003)
norm_id=WindowsSysmon event_id=1 command_line="*__EventFilter*" OR command_line="*__EventConsumer*"
| chart count() by host, command_line

# LP-PER-006: Crontab Modified (T1053.003)
"Linux Syslog" file IN ["*/var/spool/cron/*", "*/etc/cron*"]
| chart count() by host, user, file
