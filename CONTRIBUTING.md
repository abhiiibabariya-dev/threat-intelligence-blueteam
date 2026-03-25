# Contributing to BlueShell

## How to Contribute

### Adding New Detection Rules
1. Fork the repo
2. Add rules to the appropriate platform directory
3. Include MITRE ATT&CK mapping in every rule
4. Add false positive guidance
5. Submit a PR

### Adding New Platforms
If a new SIEM/EDR/XDR/SOAR is released:
1. Create directory under appropriate folder (`siem-rules/`, `edr-rules/`, etc.)
2. Add detection rules in the platform's native format
3. Add `training/zero-to-hero-[platform].md`
4. Update `webapp/js/app.js` pageData and sidebar navigation
5. Update `README.md` with the new platform

### Updating Existing Content
- Keep rules compatible with latest platform versions
- Update training guides when platforms release major versions
- Add new MITRE ATT&CK techniques as they're published
- Update the threat intel fetcher when new feeds become available

### Rule Quality Standards
- Every rule must have: name, description, MITRE mapping, severity
- Include data source requirements
- Document false positive scenarios
- Test before submitting

### Platform Version Tracking
When updating content, note the compatible version:
```
*Compatible with Splunk 9.x | Last updated [date]*
```

## Reporting Issues
- Detection rule false positives/negatives
- Outdated platform syntax
- Broken training guide links
- New platform requests
