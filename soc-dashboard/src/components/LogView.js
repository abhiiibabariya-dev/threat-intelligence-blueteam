import React from 'react';

const logs = [
  { line: 1, text: '[2024-03-15 14:31:58] INFO  sshd: Accepted publickey for admin from 10.0.1.5', type: 'normal' },
  { line: 2, text: '[2024-03-15 14:32:01] WARN  powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0A...', type: 'suspicious' },
  { line: 3, text: '[2024-03-15 14:32:05] INFO  svchost.exe: Service control manager started', type: 'normal' },
  { line: 4, text: '[2024-03-15 14:32:18] CRIT  lsass.exe: Unexpected memory read by PID 4728', type: 'critical' },
  { line: 5, text: '[2024-03-15 14:32:22] INFO  dns: Query for windowsupdate.microsoft.com', type: 'normal' },
  { line: 6, text: '[2024-03-15 14:32:35] WARN  net.exe: "net user /domain" executed by admin.jdoe', type: 'suspicious' },
  { line: 7, text: '[2024-03-15 14:33:01] INFO  smb: Connection from 10.0.5.42 to \\\\SRV-FILE03', type: 'normal' },
  { line: 8, text: '[2024-03-15 14:33:05] CRIT  smb: Admin$ share accessed on SRV-FILE03 by WS-PC042', type: 'critical' },
  { line: 9, text: '[2024-03-15 14:33:20] INFO  defender: Real-time protection scan completed', type: 'normal' },
  { line: 10, text: '[2024-03-15 14:33:42] WARN  schtasks.exe: Task "SvcUpdate" created pointing to C:\\Temp\\svc.exe', type: 'suspicious' },
  { line: 11, text: '[2024-03-15 14:34:10] CRIT  File staging detected: exfil.zip created in %TEMP% (34 MB)', type: 'critical' },
  { line: 12, text: '[2024-03-15 14:34:30] INFO  firewall: Outbound HTTPS to 203.0.113.42 allowed', type: 'normal' },
];

const typeClass = {
  normal: 'log-normal',
  suspicious: 'log-suspicious',
  critical: 'log-critical',
};

export default function LogView() {
  return (
    <div className="card log-view">
      <div className="card-header">
        <h2>Log Analysis</h2>
        <span className="badge">{logs.length} entries</span>
      </div>
      <div className="log-container">
        {logs.map((l) => (
          <div key={l.line} className={`log-line ${typeClass[l.type]}`}>
            <span className="log-num">{String(l.line).padStart(3, '0')}</span>
            <span className="log-text">{l.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
