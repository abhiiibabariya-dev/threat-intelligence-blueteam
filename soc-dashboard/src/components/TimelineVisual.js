import React from 'react';

const stages = [
  {
    label: 'Initial Access',
    technique: 'T1566.001',
    detail: 'Spearphishing email with macro-enabled doc',
    status: 'compromised',
  },
  {
    label: 'Execution',
    technique: 'T1059.001',
    detail: 'Encoded PowerShell download cradle',
    status: 'compromised',
  },
  {
    label: 'Credential Access',
    technique: 'T1003.001',
    detail: 'LSASS memory dump via Mimikatz',
    status: 'active',
  },
  {
    label: 'Lateral Movement',
    technique: 'T1021.002',
    detail: 'SMB/Admin share pivot to file server',
    status: 'pending',
  },
];

const statusColors = {
  compromised: '#ef4444',
  active: '#f59e0b',
  pending: '#6b7280',
};

export default function TimelineVisual() {
  return (
    <div className="card xdr-timeline">
      <div className="card-header">
        <h2>XDR Attack Flow</h2>
        <span className="badge">MITRE ATT&CK</span>
      </div>
      <div className="flow-container">
        {stages.map((s, i) => (
          <React.Fragment key={s.label}>
            <div className={`flow-stage ${s.status}`}>
              <div className="flow-dot" style={{ background: statusColors[s.status] }} />
              <div className="flow-label">{s.label}</div>
              <div className="flow-technique">{s.technique}</div>
              <div className="flow-detail">{s.detail}</div>
            </div>
            {i < stages.length - 1 && (
              <div className="flow-arrow">
                <svg width="40" height="20" viewBox="0 0 40 20">
                  <line x1="0" y1="10" x2="30" y2="10" stroke="#22d3ee" strokeWidth="2" strokeDasharray="4 3" />
                  <polygon points="30,5 40,10 30,15" fill="#22d3ee" />
                </svg>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
