import React from 'react';

const alerts = [
  {
    id: 1,
    rule: 'Credential Dumping via LSASS',
    severity: 'Critical',
    host: 'WS-PC042',
    user: 'admin.jdoe',
    technique: 'T1003.001',
  },
  {
    id: 2,
    rule: 'Suspicious PowerShell Execution',
    severity: 'High',
    host: 'SRV-DC01',
    user: 'svc_deploy',
    technique: 'T1059.001',
  },
  {
    id: 3,
    rule: 'Lateral Movement via SMB',
    severity: 'High',
    host: 'WS-PC015',
    user: 'j.smith',
    technique: 'T1021.002',
  },
  {
    id: 4,
    rule: 'Registry Persistence Key Added',
    severity: 'Medium',
    host: 'WS-PC089',
    user: 'contractor_01',
    technique: 'T1547.001',
  },
];

const sevClass = {
  Critical: 'sev-critical',
  High: 'sev-high',
  Medium: 'sev-medium',
  Low: 'sev-low',
};

export default function AlertCard({ onInvestigate }) {
  return (
    <div className="card alert-card">
      <div className="card-header">
        <h2>Active Alerts</h2>
        <span className="badge">{alerts.length} alerts</span>
      </div>
      <div className="alert-list">
        {alerts.map((a) => (
          <div key={a.id} className="alert-row">
            <div className="alert-info">
              <div className="alert-rule">{a.rule}</div>
              <div className="alert-meta">
                <span className={`sev-badge ${sevClass[a.severity]}`}>{a.severity}</span>
                <span className="meta-tag">🖥 {a.host}</span>
                <span className="meta-tag">👤 {a.user}</span>
                <span className="meta-tag mitre">{a.technique}</span>
              </div>
            </div>
            <button className="btn-investigate" onClick={() => onInvestigate(a)}>
              Investigate
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
