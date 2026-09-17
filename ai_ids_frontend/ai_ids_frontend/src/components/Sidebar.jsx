import { Activity, BellRing, BrainCircuit, LayoutDashboard, Network, Settings, ShieldCheck } from "lucide-react";

const items = [
  [LayoutDashboard, "Overview"],
  [Activity, "Live Traffic"],
  [ShieldCheck, "Threats"],
  [Network, "Network Map"],
  [BrainCircuit, "AI Engine"],
  [BellRing, "Alerts"],
  [Settings, "Settings"]
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon"><ShieldCheck size={22} /></div>
        <div><strong>Sentinel AI</strong><span>Intrusion Detection</span></div>
      </div>
      <nav>
        {items.map(([Icon, label], i) => (
          <button key={label} className={`nav-item ${i === 0 ? "active" : ""}`}>
            <Icon size={18} /><span>{label}</span>
          </button>
        ))}
      </nav>
      <div className="model-card">
        <span className="status-dot"></span>
        <div><strong>AI Engine Online</strong><small>Random Forest v1</small></div>
      </div>
    </aside>
  );
}
