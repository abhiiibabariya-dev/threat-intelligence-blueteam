import React from 'react';

const menuItems = [
  { icon: '⊞', label: 'Dashboard' },
  { icon: '⚠', label: 'Alerts' },
  { icon: '◉', label: 'Cases' },
  { icon: '⌕', label: 'Investigation' },
  { icon: '⛊', label: 'Detection Engine' },
  { icon: '☠', label: 'Threat Intelligence' },
  { icon: '⚡', label: 'Response (SOAR)' },
];

export default function Sidebar({ active, onSelect }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <span className="logo-icon">◈</span>
        <span className="logo-text">BlueShell</span>
      </div>
      <nav className="sidebar-nav">
        {menuItems.map((item) => (
          <button
            key={item.label}
            className={`sidebar-item${active === item.label ? ' active' : ''}`}
            onClick={() => onSelect(item.label)}
          >
            <span className="sidebar-icon">{item.icon}</span>
            <span className="sidebar-label">{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className="sidebar-status">
          <span className="status-dot" />
          <span>System Online</span>
        </div>
      </div>
    </aside>
  );
}
