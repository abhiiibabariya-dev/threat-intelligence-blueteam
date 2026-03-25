# Micro Focus ArcSight ESM Detection Rules

Detection content for ArcSight ESM including correlation rules and filter definitions in XML format.

## Contents

- **esm-rules/correlation-rules.xml** -- ESM correlation rules for multi-stage attack detection, asset-based risk scoring, threat intelligence correlation, user behavior anomaly detection, and network anomaly detection.
- **esm-rules/filters.xml** -- Reusable ArcSight filter definitions for common security event categories.

## Deployment

1. Import XML packages via **ArcSight Console > Packages > Import**.
2. Filters must be imported before correlation rules, as rules reference filter conditions.
3. Configure Active Lists and Session Lists referenced by the correlation rules.
4. Assign appropriate notification destinations and escalation groups.

## Requirements

- ArcSight ESM 7.x or ArcSight Platform
- SmartConnectors configured for Windows, firewall, IDS/IPS, and authentication log sources
- Active Lists for watchlists, asset inventory, and baseline data
