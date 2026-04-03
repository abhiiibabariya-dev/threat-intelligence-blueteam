import React, { useState } from 'react';

const actions = [
  { id: 'kill', label: 'Kill Process', icon: '✕', desc: 'Terminate PID 4728 (mimikatz.exe)', type: 'danger' },
  { id: 'isolate', label: 'Isolate Host', icon: '⊘', desc: 'Network-isolate WS-PC042', type: 'warning' },
  { id: 'block', label: 'Block IP', icon: '⛔', desc: 'Block 203.0.113.42 on perimeter FW', type: 'warning' },
  { id: 'disable', label: 'Disable User', icon: '🔒', desc: 'Disable admin.jdoe in Active Directory', type: 'danger' },
];

export default function ResponsePanel() {
  const [completed, setCompleted] = useState({});

  const handleAction = (id) => {
    setCompleted((prev) => ({ ...prev, [id]: true }));
  };

  return (
    <div className="card response-panel">
      <div className="card-header">
        <h2>Response Actions</h2>
        <span className="badge">SOAR</span>
      </div>
      <div className="response-list">
        {actions.map((a) => (
          <div key={a.id} className={`response-row ${completed[a.id] ? 'done' : ''}`}>
            <div className="response-info">
              <span className="response-icon">{a.icon}</span>
              <div>
                <div className="response-label">{a.label}</div>
                <div className="response-desc">{a.desc}</div>
              </div>
            </div>
            {completed[a.id] ? (
              <span className="response-done">✔ Action Completed</span>
            ) : (
              <button
                className={`action-btn ${a.type}`}
                onClick={() => handleAction(a.id)}
              >
                Execute
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
