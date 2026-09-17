export const trafficData = [
  { time: "10:00", normal: 4200, malicious: 210 },
  { time: "10:05", normal: 4700, malicious: 260 },
  { time: "10:10", normal: 5100, malicious: 330 },
  { time: "10:15", normal: 4900, malicious: 610 },
  { time: "10:20", normal: 5600, malicious: 980 },
  { time: "10:25", normal: 5300, malicious: 760 },
  { time: "10:30", normal: 6100, malicious: 1220 },
  { time: "10:35", normal: 5900, malicious: 410 },
  { time: "10:40", normal: 6400, malicious: 290 },
  { time: "10:45", normal: 6200, malicious: 520 }
];

export const threats = [
  { id: "EVT-1098", time: "10:45:18", source: "185.23.44.91", type: "DDoS", severity: "Critical", confidence: 99.2, status: "Blocked" },
  { id: "EVT-1097", time: "10:43:51", source: "45.61.188.12", type: "Port Scan", severity: "High", confidence: 94.8, status: "Investigating" },
  { id: "EVT-1096", time: "10:41:02", source: "103.91.22.7", type: "Brute Force", severity: "High", confidence: 91.7, status: "Blocked" },
  { id: "EVT-1095", time: "10:38:34", source: "172.18.4.21", type: "Anomalous Flow", severity: "Medium", confidence: 82.1, status: "Observed" },
  { id: "EVT-1094", time: "10:35:16", source: "192.168.1.41", type: "Normal", severity: "Low", confidence: 98.7, status: "Allowed" }
];
