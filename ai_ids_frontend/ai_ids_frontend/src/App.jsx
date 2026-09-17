import { Activity, AlertTriangle, RadioTower, ShieldCheck } from "lucide-react";
import Sidebar from "./components/Sidebar";
import StatCard from "./components/StatCard";
import TrafficChart from "./components/TrafficChart";
import ThreatTable from "./components/ThreatTable";

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS</p>
            <h1>Intrusion Detection Dashboard</h1>
            <p className="subtext">AI-powered monitoring of network traffic and malicious activity.</p>
          </div>
          <div className="live-pill"><span className="pulse"></span>LIVE MONITORING</div>
        </header>

        <section className="stats-grid">
          <StatCard title="Network Flows" value="128.4K" subtitle="+8.4% in the last hour" icon={RadioTower} />
          <StatCard title="Detected Threats" value="1,284" subtitle="37 new alerts" icon={AlertTriangle} tone="warning" />
          <StatCard title="Blocked Attacks" value="937" subtitle="72.9% automatically contained" icon={ShieldCheck} tone="success" />
          <StatCard title="Threat Level" value="HIGH" subtitle="Elevated DDoS activity" icon={Activity} tone="danger" />
        </section>

        <section className="content-grid">
          <TrafficChart />
          <div className="panel threat-panel">
            <div className="panel-heading"><div><h3>AI Threat Score</h3><p>Current network risk</p></div></div>
            <div className="score-ring"><div className="score-inner"><strong>84</strong><span>/100</span></div></div>
            <div className="risk-row"><span>Risk classification</span><strong>High Risk</strong></div>
            <div className="risk-row"><span>Model confidence</span><strong>96.8%</strong></div>
            <div className="risk-row"><span>Primary attack</span><strong>DDoS</strong></div>
          </div>
        </section>

        <ThreatTable />
      </main>
    </div>
  );
}
