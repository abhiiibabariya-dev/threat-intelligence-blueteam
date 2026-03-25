# Google Chronicle Zero-to-Hero Training Guide

## 1. Introduction
Google Chronicle is a cloud-native SIEM built on Google infrastructure. It uses the Unified Data Model (UDM) for data normalization and YARA-L 2.0 for detection rules.

## 2. Architecture
- **Google Cloud infrastructure** - Petabyte-scale storage, sub-second search
- **UDM (Unified Data Model)** - Normalized schema for all events
- **YARA-L 2.0** - Detection rule language
- **Entity analytics** - Behavioral analysis per user/asset
- **Chronicle SOAR** - Integrated response automation
- **VirusTotal integration** - Built-in threat intelligence

## 3. UDM (Unified Data Model)
All logs normalized to UDM schema:
```
metadata.event_type: NETWORK_CONNECTION
principal.hostname: workstation1
principal.ip: 10.0.0.50
target.ip: 8.8.8.8
target.port: 443
network.application_protocol: HTTPS
security_result.action: ALLOW
```

Key UDM fields: `principal` (source), `target` (destination), `metadata`, `network`, `security_result`, `extensions`

## 4. YARA-L 2.0

### Rule Structure
```
rule brute_force_detection {
  meta:
    author = "SOC Team"
    description = "Detects brute force authentication"
    severity = "HIGH"
    mitre_attack = "T1110.001"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip

  match:
    $ip over 5m

  outcome:
    $risk_score = max(85)
    $event_count = count($e)

  condition:
    #e > 10
}
```

### Key Concepts
- **events** - Define event patterns with variables ($e, $login, $process)
- **match** - Group by fields over time window
- **outcome** - Calculate risk scores, counts, aggregations
- **condition** - Threshold for rule to fire

### Advanced YARA-L: Sequence Detection
```
rule lateral_movement_sequence {
  meta:
    description = "Auth failure then success then remote execution"
    severity = "HIGH"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.ip = $src_ip

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.principal.ip = $src_ip
    $success.metadata.event_timestamp.seconds > $fail.metadata.event_timestamp.seconds

    $exec.metadata.event_type = "PROCESS_LAUNCH"
    $exec.principal.ip = $src_ip
    $exec.target.process.file.full_path = /.*psexec.*/

  match:
    $src_ip over 30m

  condition:
    #fail > 5 and $success and $exec
}
```

## 5. Search
```
# UDM search
metadata.event_type = "NETWORK_CONNECTION" AND target.port = 3389
AND NOT principal.ip = "10.0.0.0/8"

# Raw log search
"Failed password" AND "10.0.0.50"

# IOC search (auto-enriched with VirusTotal)
artifact.ip = "1.2.3.4"
```

## 6. Entity Analytics
- User risk scores based on behavior
- Asset risk scores
- Alert timelines per entity
- First-seen / last-seen tracking
- Prevalence analysis (how rare is this behavior)

## 7. Chronicle SOAR
Integrated playbook automation:
- Trigger on detection rule match
- Enrich with VirusTotal, WHOIS, GeoIP
- Automated response: block IP, disable user, isolate host
- Case management and collaboration

## 8. API
```bash
# Search UDM events
curl -X POST 'https://chronicle.googleapis.com/v1/events:search' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"metadata.event_type=\"USER_LOGIN\" AND security_result.action=\"BLOCK\"","timeRange":{"startTime":"2026-03-01T00:00:00Z","endTime":"2026-03-02T00:00:00Z"}}'
```

## 9. Use Cases
1. Brute force (YARA-L threshold on failed logins)
2. Lateral movement (sequence: fail → success → remote exec)
3. Data exfiltration (high bytes to external IPs)
4. Malware C2 (IOC match with VirusTotal enrichment)
5. DNS tunneling (high DNS query volume anomaly)
6. Credential dumping (process access to lsass)
7. Phishing (email → download → execution sequence)
8. Insider threat (entity analytics deviation)
9. Cloud abuse (unusual GCP/AWS API calls)
10. Ransomware (shadow copy deletion + file rename)

## 10. Labs
### Lab 1: Write YARA-L Rule
1. Create rule for encoded PowerShell detection
2. Deploy to Chronicle
3. Verify detection fires on test event

### Lab 2: Entity Investigation
1. Search for user with high risk score
2. Review entity timeline
3. Correlate with network and process events

### Lab 3: IOC Search
1. Import threat intel IOCs
2. Search for matches in historical data
3. Create YARA-L rule for ongoing monitoring

---
*Compatible with Google Chronicle | Last updated March 2026*
