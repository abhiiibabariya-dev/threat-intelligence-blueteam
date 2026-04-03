import React from 'react';

const iocs = [
  {
    type: 'IP Address',
    value: '203.0.113.42',
    source: 'abuse.ch FeodoTracker',
    reputation: 'Malicious',
    confidence: 95,
    tags: ['Emotet C2', 'Botnet', 'Active'],
    firstSeen: '2026-04-01',
    lastSeen: '2026-04-03',
  },
  {
    type: 'Domain',
    value: 'update-service[.]xyz',
    source: 'AlienVault OTX',
    reputation: 'Malicious',
    confidence: 90,
    tags: ['Cobalt Strike', 'C2 Domain', 'Phishing Infrastructure'],
    firstSeen: '2026-03-28',
    lastSeen: '2026-04-03',
  },
  {
    type: 'File Hash',
    value: '7f3e8c4d...a9b2d1f0',
    source: 'MalwareBazaar',
    reputation: 'Malicious',
    confidence: 98,
    tags: ['Mimikatz', 'Credential Dumper', 'PE32'],
    firstSeen: '2026-04-02',
    lastSeen: '2026-04-03',
  },
  {
    type: 'Domain',
    value: 'xf7k2.datacache[.]cloud',
    source: 'Chronicle SIEM',
    reputation: 'Suspicious',
    confidence: 82,
    tags: ['DNS Tunneling', 'DGA Pattern', 'Exfiltration'],
    firstSeen: '2026-04-01',
    lastSeen: '2026-04-03',
  },
  {
    type: 'IP Address',
    value: '185.220.101.33',
    source: 'Tor Project / AbuseIPDB',
    reputation: 'Malicious',
    confidence: 99,
    tags: ['Tor Exit Node', 'Brute Force', 'RDP Scanner'],
    firstSeen: '2026-01-15',
    lastSeen: '2026-04-03',
  },
];

const repColors = {
  Malicious: { bg: 'rgba(239,68,68,0.12)', color: '#ef4444' },
  Suspicious: { bg: 'rgba(245,158,11,0.12)', color: '#f59e0b' },
  Clean: { bg: 'rgba(34,197,94,0.12)', color: '#22c55e' },
};

export default function ThreatIntel() {
  return (
    <div className="card threat-intel-card">
      <div className="card-header">
        <h2>Threat Intelligence — IOC Database</h2>
        <span className="badge">{iocs.length} indicators</span>
      </div>
      <div className="ti-list">
        {iocs.map((ioc, i) => {
          const rep = repColors[ioc.reputation] || repColors.Suspicious;
          return (
            <div key={i} className="ti-row">
              <div className="ti-main">
                <div className="ti-type-badge">{ioc.type}</div>
                <div className="ti-value">{ioc.value}</div>
                <div className="ti-meta">
                  <span className="ti-source">{ioc.source}</span>
                  <span className="ti-dates">{ioc.firstSeen} — {ioc.lastSeen}</span>
                </div>
                <div className="ti-tags">
                  {ioc.tags.map((tag, j) => (
                    <span key={j} className="ti-tag">{tag}</span>
                  ))}
                </div>
              </div>
              <div className="ti-right">
                <div
                  className="ti-reputation"
                  style={{ background: rep.bg, color: rep.color }}
                >
                  {ioc.reputation}
                </div>
                <div className="ti-confidence">
                  <div className="ti-conf-label">Confidence</div>
                  <div className="ti-conf-bar">
                    <div
                      className="ti-conf-fill"
                      style={{
                        width: `${ioc.confidence}%`,
                        background: ioc.confidence >= 90 ? '#ef4444' : ioc.confidence >= 70 ? '#f59e0b' : '#22d3ee',
                      }}
                    />
                  </div>
                  <div className="ti-conf-value">{ioc.confidence}%</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
