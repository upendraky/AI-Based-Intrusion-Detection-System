import { threats } from "../data/mockData";

export default function ThreatTable() {
  return (
    <div className="panel">
      <div className="panel-heading">
        <div><h3>Recent Threat Events</h3><p>Latest AI-classified network activity</p></div>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Event</th><th>Time</th><th>Source IP</th><th>Detection</th><th>Severity</th><th>Confidence</th><th>Status</th></tr></thead>
          <tbody>
            {threats.map((item) => (
              <tr key={item.id}>
                <td className="mono">{item.id}</td><td>{item.time}</td><td className="mono">{item.source}</td>
                <td>{item.type}</td><td><span className={`badge ${item.severity.toLowerCase()}`}>{item.severity}</span></td>
                <td>{item.confidence}%</td><td>{item.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
