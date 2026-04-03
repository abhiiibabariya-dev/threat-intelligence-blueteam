import React from 'react';

const defaultTimeline = [
  { time: '14:32:01', event: 'PowerShell.exe spawned with encoded command', type: 'suspicious' },
  { time: '14:32:18', event: 'LSASS.exe memory access by unknown process', type: 'critical' },
  { time: '14:33:05', event: 'SMB connection to \\\\SRV-FILE03\\C$', type: 'suspicious' },
  { time: '14:33:42', event: 'Scheduled task created: SvcUpdate', type: 'suspicious' },
  { time: '14:34:10', event: 'Data staged to %TEMP%\\exfil.zip', type: 'critical' },
];

export default function InvestigationPanel({ alert }) {
  const target = alert || {
    user: 'admin.jdoe',
    host: 'WS-PC042',
    technique: 'T1003.001',
  };

  return (
    <div className="card investigation-panel">
      <div className="card-header">
        <h2>Investigation</h2>
        <span className="badge live-badge">LIVE</span>
      </div>

      <div className="investigation-target">
        <div className="target-field">
          <span className="target-label">User</span>
          <span className="target-value">{target.user}</span>
        </div>
        <div className="target-field">
          <span className="target-label">Host</span>
          <span className="target-value">{target.host}</span>
        </div>
        <div className="target-field">
          <span className="target-label">IP</span>
          <span className="target-value">10.0.5.42</span>
        </div>
      </div>

      <div className="timeline-section">
        <h3 className="section-label">Event Timeline</h3>
        <div className="timeline">
          {defaultTimeline.map((e, i) => (
            <div key={i} className={`timeline-event ${e.type}`}>
              <span className="tl-dot" />
              <span className="tl-time">{e.time}</span>
              <span className="tl-desc">{e.event}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="investigation-actions">
        <button className="action-btn danger">Kill Process</button>
        <button className="action-btn warning">Isolate Host</button>
        <button className="action-btn warning">Disable User</button>
      </div>
    </div>
  );
}
