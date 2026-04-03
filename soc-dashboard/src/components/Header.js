import React from 'react';

export default function Header() {
  return (
    <header className="header">
      <div className="header-left">
        <h1 className="header-title">AI SOC Detection &amp; Response Platform</h1>
        <span className="header-sub">Real-time threat monitoring &amp; automated response</span>
      </div>
      <div className="header-right">
        <div className="risk-badge">
          <span className="risk-label">RISK SCORE</span>
          <span className="risk-value critical">87</span>
        </div>
        <button className="btn-demo">TRY DEMO</button>
      </div>
    </header>
  );
}
