import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { trafficData } from "../data/mockData";

export default function TrafficChart() {
  return (
    <div className="panel chart-panel">
      <div className="panel-heading">
        <div><h3>Network Traffic</h3><p>Normal vs suspicious flows</p></div>
      </div>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trafficData}>
            <CartesianGrid stroke="#1b2a3b" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="time" stroke="#6f8299" tickLine={false} axisLine={false} />
            <YAxis stroke="#6f8299" tickLine={false} axisLine={false} />
            <Tooltip contentStyle={{ background: "#0d1724", border: "1px solid #22344a", borderRadius: 10 }} />
            <Area type="monotone" dataKey="normal" stroke="#56d7ff" fill="#56d7ff22" strokeWidth={2} />
            <Area type="monotone" dataKey="malicious" stroke="#ff5d73" fill="#ff5d7322" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
