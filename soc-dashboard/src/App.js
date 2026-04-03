import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import AlertCard from './components/AlertCard';
import InvestigationPanel from './components/InvestigationPanel';
import TimelineVisual from './components/TimelineVisual';
import LogView from './components/LogView';
import ResponsePanel from './components/ResponsePanel';
import './App.css';

export default function App() {
  const [activePage, setActivePage] = useState('Dashboard');
  const [selectedAlert, setSelectedAlert] = useState(null);

  return (
    <div className="app">
      <Sidebar active={activePage} onSelect={setActivePage} />
      <main className="main">
        <Header />
        <div className="dashboard-grid">
          <div className="col-left">
            <AlertCard onInvestigate={setSelectedAlert} />
            <TimelineVisual />
            <LogView />
          </div>
          <div className="col-right">
            <InvestigationPanel alert={selectedAlert} />
            <ResponsePanel />
          </div>
        </div>
      </main>
    </div>
  );
}
