import React, { useState } from 'react';
import Header from './components/Header';
import AlertCard from './components/AlertCard';
import InvestigationPanel from './components/InvestigationPanel';
import TimelineVisual from './components/TimelineVisual';
import LogView from './components/LogView';
import ResponsePanel from './components/ResponsePanel';
import ThreatIntel from './components/ThreatIntel';
import './App.css';

const tabs = [
  { id: 'detection', label: 'Detection' },
  { id: 'investigation', label: 'Investigation' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'logs', label: 'Logs' },
  { id: 'response', label: 'Response' },
  { id: 'threat-intel', label: 'Threat Intel' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('detection');
  const [selectedAlert, setSelectedAlert] = useState(null);

  return (
    <div className="app">
      <Header />
      <nav className="pill-nav">
        <div className="pill-track">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`pill-tab${activeTab === tab.id ? ' active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </nav>
      <main className="main-content">
        {activeTab === 'detection' && (
          <div className="tab-panel fade-in">
            <AlertCard onInvestigate={(alert) => { setSelectedAlert(alert); setActiveTab('investigation'); }} />
          </div>
        )}
        {activeTab === 'investigation' && (
          <div className="tab-panel fade-in">
            <InvestigationPanel alert={selectedAlert} />
          </div>
        )}
        {activeTab === 'timeline' && (
          <div className="tab-panel fade-in">
            <TimelineVisual />
          </div>
        )}
        {activeTab === 'logs' && (
          <div className="tab-panel fade-in">
            <LogView />
          </div>
        )}
        {activeTab === 'response' && (
          <div className="tab-panel fade-in">
            <ResponsePanel />
          </div>
        )}
        {activeTab === 'threat-intel' && (
          <div className="tab-panel fade-in">
            <ThreatIntel />
          </div>
        )}
      </main>
    </div>
  );
}
