import React from 'react';

export default function Header() {
  return (
    <header className="header">
      <div className="header-left">
        <div className="header-logo">
          <span className="logo-glyph">◈</span>
          <h1 className="header-title">AI SOC Detection &amp; Response Platform</h1>
        </div>
      </div>
      <div className="header-right">
        <div className="header-badge risk-badge">
          <span className="badge-label">RISK SCORE</span>
          <span className="badge-value risk-critical">91%</span>
        </div>
        <div className="header-badge threat-badge">
          <span className="badge-label">THREAT LEVEL</span>
          <span className="badge-value threat-critical">CRITICAL</span>
        </div>
        <button className="btn-demo">TRY DEMO</button>
      </div>
    </header>
  );
}
