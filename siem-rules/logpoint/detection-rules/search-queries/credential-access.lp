# LogPoint LPQL - Credential Access Detection Queries
# MITRE ATT&CK Tactic: TA0006

# LP-CA-001: Brute Force Attack (T1110.001)
"Windows Security" label=Logon status=failure
| chart count() as failed_attempts by source_address, user
| search failed_attempts > 10
| sort -failed_attempts
| rename source_address as "Source IP", user as "Target Account"

# LP-CA-002: Password Spray (T1110.003)
"Windows Security" label=Logon status=failure
| chart count() as attempts, distinct_count(user) as unique_accounts by source_address
| search unique_accounts > 5 AND attempts > 10
| sort -unique_accounts

# LP-CA-003: LSASS Memory Access (T1003.001)
norm_id=WindowsSysmon event_id=10 target_image="*lsass.exe" granted_access IN ["0x1010", "0x1038", "0x1fffff"]
-source_image IN ["*csrss.exe", "*svchost.exe", "*MsMpEng.exe"]
| chart count() by host, source_image, granted_access

# LP-CA-004: Kerberoasting (T1558.003)
"Windows Security" event_id=4769 ticket_encryption_type IN ["0x17", "0x18"]
-user="*$"
| chart count() as tgs_requests by user, source_address
| search tgs_requests > 3

# LP-CA-005: DCSync Attack (T1003.006)
"Windows Security" event_id=4662
(properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
-source_address IN [$domain_controllers]
| chart count() by user, source_address, host

# LP-CA-006: Credential File Access (T1552.001)
norm_id=WindowsSysmon event_id=11
target_filename IN ["*unattend.xml*", "*sysprep.inf*", "*.aws\\credentials*", "*web.config*"]
| chart count() by host, image, target_filename
