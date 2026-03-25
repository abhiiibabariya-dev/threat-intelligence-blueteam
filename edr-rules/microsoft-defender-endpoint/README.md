# Microsoft Defender for Endpoint Detection Rules

KQL-based advanced hunting queries and custom detection rules for Microsoft Defender for Endpoint (MDE).

## Contents

- `advanced-hunting/threat-hunting.kql` - Proactive threat hunting queries for SOC analysts
- `custom-detections/detection-rules.kql` - Scheduled custom detection rules for automated alerting

## Deployment

### Advanced Hunting Queries
1. Navigate to **Microsoft 365 Defender > Hunting > Advanced hunting**
2. Paste the KQL query into the query editor
3. Run the query to validate results
4. Save as a custom query for reuse or share with the hunting team

### Custom Detection Rules
1. Navigate to **Microsoft 365 Defender > Hunting > Custom detection rules**
2. Create a new rule using the provided KQL query
3. Configure the detection frequency (every 1, 3, 12, or 24 hours)
4. Set the alert severity and assign to the appropriate response group
5. Map impacted entities (devices, users, mailboxes) for automated investigation

## Tuning Guidance

- Review query results over a 30-day window before enabling as detection rules
- Add exclusions for known administrative tools and automation accounts
- Adjust time windows and thresholds based on environment size
- Test custom detection rules in audit mode before enforcement
