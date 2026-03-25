# LogPoint LPQL - Exfiltration Detection (TA0010)

# LP-EX-001: DNS Tunneling (T1048.001)
label=DNS query_length > 50 query_type IN ["TXT", "NULL"]
| chart count() as queries, avg(query_length) as avg_len by source_address
| search queries > 20 AND avg_len > 40

# LP-EX-002: Cloud Storage Upload (T1567.002)
norm_id=WindowsSysmon event_id=1 image IN ["*rclone.exe", "*megasync.exe", "*gdrive.exe"]
| chart count() by host, user, image

# LP-EX-003: Large Outbound Transfer (T1041)
label=Connection destination_zone=external bytes_out > 524288000
| chart sum(bytes_out) as total_bytes by source_address, destination_address
| sort -total_bytes

# LP-EX-004: Email Exfiltration (T1048.003)
label=Email direction=outbound
-recipient_domain IN [$corporate_domains]
attachment_count > 0
| chart count() as emails by sender, recipient_domain
| search emails > 5

# LP-EX-005: Certutil Download (T1105)
norm_id=WindowsSysmon event_id=1 image="*certutil.exe" command_line="*urlcache*http*"
| chart count() by host, user, command_line
