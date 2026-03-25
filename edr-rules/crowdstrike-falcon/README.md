# CrowdStrike Falcon Detection Rules

Custom Indicators of Attack (IOA) rules for CrowdStrike Falcon, organized by detection category.

## Contents

- `custom-ioa/process-based-detections.yml` - Process execution, injection, and credential theft detections
- `custom-ioa/network-detections.yml` - C2 beaconing, DNS exfiltration, lateral movement, and encrypted channel detections

## Deployment

1. Navigate to **Falcon Console > Custom IOA Rule Groups**
2. Create a new rule group or select an existing one
3. Add rules using the detection logic provided in each YAML file
4. Assign the rule group to the appropriate host groups
5. Set rules to **Detect** mode initially; promote to **Prevent** after tuning

## Tuning Guidance

- Exclude known administrative tools and scripts from PowerShell detections
- Whitelist legitimate LSASS access from security tooling (e.g., your own EDR agent)
- Baseline normal DNS query volumes before enabling DNS exfiltration rules
- Test LOLBin rules against your software deployment tooling to avoid false positives
