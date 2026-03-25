# IOC Management Guide

## Purpose

This guide establishes standardized procedures for managing Indicators of Compromise (IOCs) throughout their lifecycle. It covers collection, validation, enrichment, dissemination, and retirement of threat indicators to ensure the organization maintains a high-quality, actionable indicator repository.

---

## Table of Contents

1. [IOC Lifecycle Management](#1-ioc-lifecycle-management)
2. [Confidence Scoring Framework](#2-confidence-scoring-framework)
3. [TLP Handling Procedures](#3-tlp-handling-procedures)
4. [Enrichment Workflows](#4-enrichment-workflows)
5. [Feed Management](#5-feed-management)
6. [Deduplication Strategies](#6-deduplication-strategies)
7. [IOC Types and Handling](#7-ioc-types-and-handling)
8. [Quality Metrics](#8-quality-metrics)

---

## 1. IOC Lifecycle Management

### 1.1 Lifecycle Phases

```
Collection --> Validation --> Enrichment --> Dissemination --> Monitoring --> Review --> Retirement
    |              |              |               |               |            |           |
    v              v              v               v               v            v           v
  Ingest from   Verify         Add context,    Distribute to   Track hits,  Reassess   Archive or
  sources       accuracy,      correlate,      detection        false pos,   confidence delete
               dedup          score           platforms        true pos     and value
```

### 1.2 Collection

**Sources:**
- Internal incident response investigations
- Malware sandbox analysis (automated and manual)
- Threat intelligence feeds (commercial and open source)
- Information Sharing and Analysis Centers (ISACs)
- Government advisories (CISA, FBI Flash, CERT)
- Peer organization sharing (TLP-governed)
- OSINT collection (social media, paste sites, dark web)
- Honeypot and deception technology

**Collection Requirements:**
- Record the original source for every IOC
- Capture the date and time of collection
- Assign an initial confidence score based on source reliability
- Apply an initial TLP classification
- Record any known threat actor or campaign association

### 1.3 Validation

Before an IOC enters the active repository, validate it against these criteria:

| Check | Description | Action on Failure |
|-------|-------------|-------------------|
| Format validation | IOC matches expected format (valid IP, hash length, domain syntax) | Reject and log |
| Benign check | IOC is not a known legitimate service (CDN, cloud provider, OS update) | Flag for review |
| Duplicate check | IOC does not already exist in the repository | Merge with existing entry |
| Age check | IOC is not older than the maximum age threshold for its type | Reduce confidence or reject |
| Source verification | At least one reputable source corroborates the IOC | Lower confidence score |
| Context check | IOC has sufficient context (threat actor, campaign, technique) | Enrich before acceptance |

### 1.4 Monitoring

- Track detection hits against active IOCs across all platforms
- Record true positive and false positive rates per IOC
- Flag IOCs with high false positive rates for review
- Generate weekly reports on IOC hit rates and effectiveness

### 1.5 Review

Conduct regular reviews based on IOC type:

| IOC Type | Review Frequency | Maximum Active Age |
|----------|------------------|--------------------|
| IP Address | Every 30 days | 90 days |
| Domain | Every 60 days | 180 days |
| URL | Every 30 days | 90 days |
| File Hash (SHA-256) | Every 90 days | 365 days |
| File Hash (MD5/SHA-1) | Every 90 days | 365 days |
| Email Address | Every 60 days | 180 days |
| Registry Key | Every 90 days | 365 days |
| Mutex | Every 90 days | 365 days |
| Certificate Hash | Every 60 days | 180 days |

### 1.6 Retirement

IOCs should be retired when:
- They exceed the maximum active age for their type without recent hits
- The associated threat actor or campaign is no longer active
- The infrastructure has been taken down or sinkholed
- The IOC generates an unacceptable false positive rate (>20%)
- The confidence score drops below the minimum threshold (30)

**Retirement procedure:**
1. Remove the IOC from active detection platforms
2. Move the IOC to the archive repository with a retirement reason
3. Retain the IOC for historical correlation for a minimum of 2 years
4. Update any associated reports or campaign tracking documents

---

## 2. Confidence Scoring Framework

### 2.1 Scoring Scale

Confidence is scored on a scale of 0-100:

| Range | Label | Description |
|-------|-------|-------------|
| 90-100 | Confirmed | IOC verified through direct observation, forensic analysis, or multiple independent high-reliability sources |
| 70-89 | High | IOC from a reliable source with corroborating evidence or context |
| 50-69 | Medium | IOC from a generally reliable source but limited corroboration |
| 30-49 | Low | IOC from a single source or source of uncertain reliability |
| 0-29 | Unverified | IOC has not been validated or source reliability is unknown |

### 2.2 Scoring Factors

Calculate confidence by evaluating the following factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Source reliability | 30% | Historical accuracy of the reporting source |
| Corroboration | 25% | Number of independent sources reporting the same IOC |
| Context quality | 20% | Completeness of associated threat actor, campaign, and technique information |
| Timeliness | 15% | How recently the IOC was observed in active use |
| Technical validity | 10% | Whether the IOC is technically sound and specific |

### 2.3 Confidence Adjustment Events

| Event | Adjustment |
|-------|------------|
| True positive detection in environment | +10 |
| Corroborated by additional source | +10 |
| Verified by internal analysis | +15 |
| False positive detection | -15 |
| IOC age exceeds 50% of max active age | -5 |
| IOC age exceeds 75% of max active age | -10 |
| Source credibility downgraded | -10 |
| Associated campaign confirmed inactive | -20 |

### 2.4 Minimum Thresholds for Actions

| Action | Minimum Confidence |
|--------|-------------------|
| Block at perimeter (IP/domain) | 70 |
| Block at endpoint (hash) | 60 |
| Alert only (all types) | 30 |
| Automated enrichment query | 20 |
| Inclusion in hunt queries | 40 |
| Sharing with external partners | 60 |

---

## 3. TLP Handling Procedures

### 3.1 TLP Definitions

This organization follows the FIRST TLP v2.0 standard:

| TLP Level | Sharing Scope | Handling Requirements |
|-----------|---------------|----------------------|
| **TLP:RED** | Named recipients only | Do not share beyond the specific individuals or meeting. No electronic forwarding. Store in restricted-access systems only. |
| **TLP:AMBER+STRICT** | Organization only | Share within the organization on a need-to-know basis. Do not share with external parties including vendors. |
| **TLP:AMBER** | Organization and clients | Share within the organization and with clients/partners who need the information to protect themselves. |
| **TLP:GREEN** | Community | Share within the security community. Do not publish publicly or post on public-facing systems. |
| **TLP:CLEAR** | Unrestricted | No restrictions on sharing. May be published publicly. |

### 3.2 TLP Handling Matrix

| Action | RED | AMBER+STRICT | AMBER | GREEN | CLEAR |
|--------|-----|--------------|-------|-------|-------|
| Store in TIP | Restricted access | Standard access | Standard access | Standard access | Standard access |
| Deploy to SIEM/EDR | Named analysts only | All SOC staff | All SOC staff | All SOC staff | All SOC staff |
| Share with ISAC | No | No | Yes (with attribution removed) | Yes | Yes |
| Include in reports | Classified section only | Internal reports only | Internal + client reports | Community reports | Any report |
| Discuss on calls | Named participants | Internal calls only | Internal + partner calls | Community calls | Any forum |

### 3.3 TLP Assignment Guidelines

When assigning TLP to internally discovered IOCs:

- **TLP:RED**: IOC reveals an active compromise of the organization or a specific partner
- **TLP:AMBER+STRICT**: IOC is derived from sensitive internal systems or investigations in progress
- **TLP:AMBER**: IOC is relevant to partners and can be shared to improve collective defense
- **TLP:GREEN**: IOC is broadly relevant and the security community benefits from awareness
- **TLP:CLEAR**: IOC is derived from public sources and adds value through aggregation

### 3.4 TLP Downgrade Procedures

TLP may be downgraded (e.g., AMBER to GREEN) when:
1. The associated incident has been resolved and disclosed
2. The threat actor's infrastructure has been publicly reported
3. The IOC has been independently published by a third party
4. The original source explicitly approves the downgrade

TLP downgrades require approval from the Threat Intelligence Lead.

---

## 4. Enrichment Workflows

### 4.1 Automated Enrichment Pipeline

Every new IOC should pass through the automated enrichment pipeline:

```
New IOC Ingested
    │
    ├─> IP Address
    │     ├─> Geolocation lookup
    │     ├─> ASN/BGP information
    │     ├─> WHOIS registration
    │     ├─> Passive DNS (related domains)
    │     ├─> Reputation score (VirusTotal, AbuseIPDB)
    │     ├─> Shodan/Censys port scan data
    │     └─> Historical incident correlation
    │
    ├─> Domain
    │     ├─> WHOIS registration (registrar, dates, privacy)
    │     ├─> DNS resolution (A, AAAA, MX, NS, TXT)
    │     ├─> Passive DNS history
    │     ├─> SSL/TLS certificate information
    │     ├─> Reputation score
    │     ├─> URL scan results
    │     └─> Domain age and categorization
    │
    ├─> File Hash
    │     ├─> Antivirus detection ratio
    │     ├─> Sandbox analysis results
    │     ├─> YARA rule matches
    │     ├─> Signature verification
    │     ├─> File metadata (compilation time, imports, sections)
    │     ├─> Similar sample identification
    │     └─> Malware family classification
    │
    ├─> URL
    │     ├─> Domain enrichment (above)
    │     ├─> URL scan and screenshot
    │     ├─> Content categorization
    │     ├─> Redirect chain analysis
    │     └─> Hosting infrastructure
    │
    └─> Email Address
          ├─> Domain enrichment (domain portion)
          ├─> Historical phishing campaign association
          ├─> Email header analysis (if available)
          └─> Social media/OSINT correlation
```

### 4.2 Manual Enrichment Triggers

Manual analyst enrichment is required when:
- Automated enrichment returns conflicting results
- The IOC is associated with a high-priority threat actor (APT)
- The IOC is rated TLP:RED or TLP:AMBER+STRICT
- The IOC is linked to an active incident
- Confidence score is between 40-60 (ambiguous range)

### 4.3 Enrichment Data Sources

| Source | Type | IOC Types | Update Frequency |
|--------|------|-----------|-----------------|
| VirusTotal | Commercial | Hash, IP, Domain, URL | Real-time |
| AbuseIPDB | Community | IP | Real-time |
| Shodan | Commercial | IP | Daily |
| PassiveTotal | Commercial | Domain, IP | Real-time |
| URLhaus | Open Source | URL, Domain | Hourly |
| MalwareBazaar | Open Source | Hash | Real-time |
| AlienVault OTX | Open Source | All | Real-time |
| MISP | Community | All | Configurable |
| GreyNoise | Commercial | IP | Real-time |
| Censys | Commercial | IP, Certificate | Daily |

---

## 5. Feed Management

### 5.1 Feed Evaluation Criteria

Before onboarding a new threat intelligence feed, evaluate it against these criteria:

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Accuracy | 30% | Historical true positive rate of indicators from this feed |
| Timeliness | 20% | How quickly indicators are published relative to first observation |
| Relevance | 20% | Proportion of indicators relevant to the organization's threat landscape |
| Volume | 10% | Number of indicators and manageability of the feed |
| Format | 10% | Compatibility with the organization's TIP and detection platforms |
| Context | 10% | Quality of metadata, ATT&CK mapping, and threat actor attribution |

### 5.2 Feed Tiers

| Tier | Description | Example Sources | SLA |
|------|-------------|-----------------|-----|
| Tier 1 - Critical | High-confidence feeds directly relevant to the organization | Commercial TI vendors, ISAC feeds, government advisories | Process within 1 hour |
| Tier 2 - Standard | Reliable feeds with broad coverage | Open-source curated feeds, partner sharing | Process within 4 hours |
| Tier 3 - Supplemental | High-volume feeds used for enrichment | Community feeds, aggregated OSINT | Process within 24 hours |

### 5.3 Feed Health Monitoring

Monitor the following metrics for each feed:

- **Ingestion success rate**: Percentage of successful feed pulls (target: >99%)
- **Indicator volume**: Daily/weekly indicator count trends
- **Overlap rate**: Percentage of indicators already in the repository from other feeds
- **Detection rate**: Percentage of feed indicators that generate alerts
- **False positive rate**: Percentage of alerts from feed indicators that are false positives
- **Staleness**: Average age of indicators at time of ingestion

Generate monthly feed health reports and conduct quarterly feed reviews to determine whether feeds should be retained, upgraded, or removed.

### 5.4 Feed Ingestion Architecture

```
External Feeds ──> Feed Aggregator ──> Normalization ──> Deduplication ──> Validation
                                                                              │
                   Detection Platforms <── Distribution <── Enrichment <──────┘
                   (SIEM, EDR, XDR)         Engine           Pipeline
```

---

## 6. Deduplication Strategies

### 6.1 Deduplication Levels

| Level | Description | Method |
|-------|-------------|--------|
| Exact match | Identical IOC value | Direct string comparison (case-normalized) |
| Normalized match | Same IOC after normalization | Defang, strip protocol/path, resolve CIDR |
| Semantic match | Different representations of the same indicator | IP in domain vs. direct IP, shortened URLs |
| Related match | IOCs that refer to the same infrastructure | Passive DNS correlation, certificate linking |

### 6.2 Normalization Rules

Before deduplication, normalize all IOCs:

| IOC Type | Normalization |
|----------|--------------|
| IP Address | Remove leading zeros, expand IPv6 to full form |
| Domain | Convert to lowercase, remove trailing dots, strip `www.` prefix |
| URL | Convert scheme and host to lowercase, decode percent-encoding, remove default ports, normalize path |
| File Hash | Convert to lowercase |
| Email | Convert to lowercase |

### 6.3 Merge Strategy

When a duplicate is detected:
1. **Retain the existing entry** as the primary record
2. **Merge metadata**: Combine sources, tags, and campaign associations
3. **Update confidence**: Increase confidence by +10 for each additional independent source (cap at 95)
4. **Update timestamps**: Use the earliest `first_seen` and latest `last_seen`
5. **Preserve TLP**: Retain the most restrictive TLP classification
6. **Log the merge**: Record the merge event for audit purposes

### 6.4 Conflict Resolution

When duplicate IOCs have conflicting metadata:

| Conflict Type | Resolution |
|---------------|------------|
| Different threat actor attribution | Retain both attributions; flag for analyst review |
| Different confidence scores | Use the weighted average based on source reliability |
| Different TLP levels | Use the most restrictive TLP |
| Different MITRE ATT&CK mappings | Retain all mappings (IOC may be used across techniques) |
| Different campaign names | Retain both; may indicate IOC reuse across campaigns |

---

## 7. IOC Types and Handling

### 7.1 Type-Specific Guidance

| IOC Type | Detection Method | Typical Lifetime | False Positive Risk | Notes |
|----------|-----------------|-------------------|--------------------|----|
| IPv4/IPv6 | Firewall, proxy, DNS, netflow | 30-90 days | Medium-High | Cloud/CDN IPs may be shared; validate with context |
| Domain | DNS, proxy, certificate transparency | 60-180 days | Medium | Check for domain fronting and legitimate subdomains |
| URL | Proxy, web filter, endpoint | 30-90 days | Low-Medium | Most specific network indicator |
| SHA-256 | Endpoint, email gateway, sandbox | 180-365 days | Very Low | Highly specific but easily evaded by recompilation |
| MD5/SHA-1 | Endpoint, email gateway | 180-365 days | Very Low | Collision risk with MD5; prefer SHA-256 |
| Email Address | Email gateway, phishing filter | 60-180 days | Low | May be spoofed; combine with header analysis |
| Registry Key | EDR, endpoint monitoring | 180-365 days | Medium | May conflict with legitimate software |
| Mutex | EDR, endpoint monitoring | 180-365 days | Low | Unique to malware family; good for family identification |
| Certificate Hash | TLS inspection, proxy | 60-180 days | Low | Certificates rotate; track issuer patterns |
| YARA Rule | File scanning, memory scanning | 365+ days | Low | Behavioral; more resilient than hash IOCs |

---

## 8. Quality Metrics

### 8.1 IOC Repository Health Metrics

Track the following metrics monthly:

| Metric | Target | Description |
|--------|--------|-------------|
| Total active IOCs | N/A | Inventory size across all types |
| IOCs added (monthly) | Trending up | New IOCs ingested |
| IOCs retired (monthly) | N/A | IOCs removed from active detection |
| Average confidence score | >60 | Mean confidence across active IOCs |
| IOCs with ATT&CK mapping | >90% | Percentage of IOCs mapped to techniques |
| IOCs with threat actor attribution | >70% | Percentage with known attribution |
| True positive rate | >80% | Percentage of IOC-triggered alerts that are true positives |
| False positive rate | <10% | Percentage of IOC-triggered alerts that are false positives |
| Mean time to ingest | <4 hours | Average time from source publication to active detection |
| Feed uptime | >99% | Percentage of successful feed ingestions |
| Deduplication rate | <30% new duplicates | Percentage of new IOCs that are duplicates |

### 8.2 Reporting Cadence

| Report | Frequency | Audience |
|--------|-----------|----------|
| IOC ingestion summary | Daily | SOC analysts |
| Feed health dashboard | Weekly | TI team lead |
| IOC quality metrics | Monthly | Security management |
| Feed evaluation review | Quarterly | CISO / Security leadership |
| Annual TI program assessment | Annually | Executive leadership |
