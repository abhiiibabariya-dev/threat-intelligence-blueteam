# LogPoint LPQL - Insider Threat Detection

# LP-IT-001: Off-Hours Access
label=Logon status=success hour IN [0,1,2,3,4,5,22,23]
| chart count() by user, source_address
| search count > 5

# LP-IT-002: Bulk File Download
label="File Access" action=read
| chart count() as files, distinct_count(file) as unique_files by user
| search unique_files > 100

# LP-IT-003: USB Data Transfer
label="Removable Media" action=write bytes_out > 52428800
| chart sum(bytes_out) as total by user, host

# LP-IT-004: Personal Email Send
label=Email direction=outbound recipient_domain IN ["gmail.com", "yahoo.com", "hotmail.com", "protonmail.com"]
attachment_count > 0
| chart count() by sender
| search count > 3

# LP-IT-005: Cloud Upload Spike
destination_address IN ["*.dropbox.com", "*.google.com/drive", "*.onedrive.live.com"]
| chart sum(bytes_out) as uploaded by user | search uploaded > 104857600
