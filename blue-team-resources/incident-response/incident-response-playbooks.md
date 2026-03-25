# Incident Response Playbooks

## Overview
Eight battle-tested IR playbooks following NIST SP 800-61 (Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned).

---

## Playbook 1: Phishing Incident

### Detection
- User reports suspicious email
- Email gateway alert (malicious URL/attachment)
- SIEM alert on credential harvesting domain

### Containment (First 30 minutes)
1. **DO NOT** click links or open attachments on production system
2. Quarantine the email from all mailboxes (Exchange: `Search-Mailbox -DeleteContent`)
3. Block sender domain at email gateway
4. Block malicious URLs at proxy/firewall
5. If credentials entered: force password reset + revoke sessions
6. If attachment opened: isolate endpoint from network

### Eradication
1. Submit URL/attachment to sandbox (VirusTotal, Any.Run, Joe Sandbox)
2. Extract IOCs: sender IP, domain, URL, file hash, C2 infrastructure
3. Search SIEM for other recipients who clicked/opened
4. Block IOCs across all security controls (firewall, proxy, EDR, DNS)
5. Check for mailbox rules created by attacker (forwarding, deletion)

### Recovery
1. Re-image affected endpoints if malware confirmed
2. Reset credentials for compromised accounts + enable MFA
3. Monitor affected accounts for 72 hours
4. Remove email quarantine blocks after investigation

### Lessons Learned
- Update email filter rules based on attack patterns
- Conduct targeted phishing awareness training
- Add IOCs to internal threat intelligence

---

## Playbook 2: Ransomware Incident

### Detection
- Multiple file encryption alerts from EDR
- Users unable to access files / ransom note found
- Shadow copy deletion (vssadmin/wmic)
- Large-scale file extension changes

### Containment (IMMEDIATE - First 15 minutes)
1. **ISOLATE** affected systems from network IMMEDIATELY
2. Disable network shares and mapped drives
3. Disable compromised accounts
4. Preserve evidence: DO NOT turn off systems (volatile memory)
5. Block C2 IPs/domains at perimeter firewall
6. Engage incident commander and notify CISO

### Eradication
1. Identify ransomware variant (ransom note, file extension, NoMoreRansom.org)
2. Determine initial access vector (phishing, RDP, VPN exploit, supply chain)
3. Identify all affected systems via EDR/SIEM
4. Map lateral movement path
5. Find and close the entry point
6. Remove ransomware binaries and persistence mechanisms
7. Check for data exfiltration (double extortion)

### Recovery
1. Restore from clean backups (verify backup integrity first)
2. Rebuild systems from gold images if backups unavailable
3. Reset ALL passwords (domain-wide if AD compromised)
4. Re-enable services in priority order (critical systems first)
5. Monitor restored systems for 30 days
6. Test restored data integrity

### Lessons Learned
- Review backup strategy (3-2-1 rule, air-gapped backups)
- Patch the exploited vulnerability
- Implement network segmentation
- Review privileged access management
- Update detection rules for the attack chain

---

## Playbook 3: Data Breach

### Detection
- DLP alert on large data transfer
- Anomalous database queries
- Cloud storage upload spike
- External notification (law enforcement, third party)

### Containment
1. Identify scope: what data, how much, how sensitive
2. Block exfiltration channel (IP, domain, protocol)
3. Revoke compromised credentials
4. Preserve logs and evidence (legal hold)
5. Engage legal counsel for breach notification requirements

### Eradication
1. Determine root cause and attack vector
2. Close the access path
3. Audit all access to affected data stores
4. Review and revoke excessive permissions

### Recovery
1. Implement additional access controls
2. Enable enhanced monitoring on affected systems
3. Notify affected parties per regulatory requirements (GDPR: 72h, HIPAA: 60 days)
4. Engage PR/communications team if public disclosure needed

---

## Playbook 4: Insider Threat

### Detection
- UEBA anomaly: off-hours access, bulk downloads, peer group deviation
- DLP alert: data to personal email/USB
- HR flag: resignation notice + increased data access

### Containment
1. **DO NOT alert the subject** - covert investigation
2. Increase monitoring (full packet capture, keystroke logging if legally approved)
3. Preserve evidence with legal/HR coordination
4. Restrict access to sensitive systems (gradually, to avoid tipping off)

### Eradication
1. Document all evidence with chain of custody
2. Coordinate with HR and legal for employee action
3. Upon termination: immediate account disable, badge revocation, device collection
4. Forensic imaging of all assigned devices

### Recovery
1. Audit all data the insider had access to
2. Reset shared credentials they knew
3. Review and implement least-privilege access
4. Update insider threat detection rules

---

## Playbook 5: DDoS Attack

### Detection
- Network monitoring alerts: bandwidth saturation
- Application unresponsive / high latency
- CDN/WAF alerts on traffic volume

### Containment
1. Activate DDoS mitigation service (Cloudflare, Akamai, AWS Shield)
2. Enable rate limiting at load balancer
3. Block attacking source IPs/ranges at perimeter
4. Enable geo-blocking if attack from specific regions
5. Scale infrastructure if cloud-hosted (auto-scaling)

### Eradication
1. Analyze attack vectors (volumetric, protocol, application layer)
2. Identify and block botnet C2 infrastructure
3. Update WAF rules for application-layer attacks
4. Implement challenge pages (CAPTCHA) for suspicious traffic

### Recovery
1. Gradually remove blocking rules, monitor for resurgence
2. Review and update DDoS response plan
3. Ensure DDoS mitigation service is properly configured
4. Conduct capacity planning review

---

## Playbook 6: Supply Chain Compromise

### Detection
- Unexpected software update behavior
- Unusual outbound connections from trusted software
- Vendor notification of compromise
- Threat intelligence alert (e.g., SolarWinds, 3CX)

### Containment
1. Isolate affected software/systems from network
2. Block known IOCs (C2 domains, IPs, hashes)
3. Disable auto-update for compromised software
4. Identify all systems running the affected version

### Eradication & Recovery
1. Remove compromised software version
2. Install clean version from verified source (or alternative)
3. Hunt for persistence mechanisms left by attacker
4. Full credential reset if domain access achieved
5. Review all vendor access and API keys

---

## Playbook 7: Cloud Security Incident

### Detection
- Cloud audit log anomaly (new admin, policy change, resource creation)
- Impossible travel to cloud console
- Crypto mining indicators (high compute usage)
- S3 bucket/storage account public exposure

### Containment
1. Disable compromised cloud credentials/API keys immediately
2. Revoke OAuth tokens and service principal access
3. Enable MFA on all cloud admin accounts
4. Apply restrictive security group / NSG rules
5. Snapshot affected instances for forensics

### Eradication
1. Rotate ALL API keys and secrets
2. Review IAM policies and remove excessive permissions
3. Audit CloudTrail/Activity logs for full attack scope
4. Remove unauthorized resources (VMs, storage, IAM users)

### Recovery
1. Implement SCPs/Azure Policy guardrails
2. Enable comprehensive cloud logging
3. Deploy CSPM (Cloud Security Posture Management)
4. Review and enforce least-privilege IAM

---

## Playbook 8: Business Email Compromise (BEC)

### Detection
- Report of fraudulent wire transfer request
- Email from spoofed or compromised executive account
- Mailbox rules forwarding to external address
- Unusual email patterns (CEO requesting gift cards, vendor payment changes)

### Containment
1. Contact bank to recall/freeze wire transfer (time-critical!)
2. Disable compromised email account
3. Remove malicious mailbox rules
4. Block attacker's email addresses and IPs
5. Notify all employees of the ongoing BEC campaign

### Eradication
1. Determine if account was compromised or spoofed
2. If compromised: reset password, revoke sessions, audit mailbox
3. Review all sent emails for other fraud attempts
4. Check for OAuth app consent grants

### Recovery
1. Implement anti-spoofing (DMARC, DKIM, SPF)
2. Require out-of-band verification for financial requests
3. Enable mailbox audit logging
4. Conduct BEC awareness training

---

## Universal IR Checklist

- [ ] Incident ticket created and classified
- [ ] Incident commander assigned
- [ ] Evidence preservation initiated (logs, memory, disk)
- [ ] Affected systems identified and contained
- [ ] IOCs extracted and shared
- [ ] Root cause determined
- [ ] Eradication completed
- [ ] Systems restored and verified
- [ ] Post-incident review scheduled
- [ ] Detection rules updated
- [ ] Documentation complete
