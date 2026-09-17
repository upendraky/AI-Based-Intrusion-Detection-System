export default function StatCard({ title, value, subtitle, icon: Icon, tone = "neutral" }) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="stat-top">
        <span>{title}</span><div className="stat-icon"><Icon size={18} /></div>
      </div>
      <strong className="stat-value">{value}</strong>
      <small>{subtitle}</small>
    </div>
  );
}
