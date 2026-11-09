import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  RiFileChartLine,
  RiShieldCheckLine,
  RiAlertLine,
  RiSkullLine,
  RiDownloadLine,
  RiCalendarLine,
} from "react-icons/ri";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

interface Scan {
  id: number;
  filename: string;
  file_hash: string;
  verdict: string;
  threat_score: number;
  findings: string;
  scan_duration_ms: number;
  scanned_at: string;
}

interface Stats {
  total_files: number;
  total_scans: number;
  threats_blocked: number;
  active_alerts: number;
}

const COLORS = {
  clean: "#10b981",
  suspicious: "#f59e0b",
  dangerous: "#ef4444",
};

const verdictColor = (v: string) =>
  v === "dangerous"
    ? "text-red-400 bg-red-400/10"
    : v === "suspicious"
      ? "text-amber-400 bg-amber-400/10"
      : "text-emerald-400 bg-emerald-400/10";

export default function Reports() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [range, setRange] = useState("all");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const [sRes, stRes] = await Promise.all([
        fetch("http://127.0.0.1:8000/api/scans?limit=500"),
        fetch("http://127.0.0.1:8000/api/stats"),
      ]);
      const sData = await sRes.json();
      const stData = await stRes.json();
      setScans(Array.isArray(sData) ? sData : []);
      setStats(stData);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = scans.filter((s) => {
    if (range === "all" || !s.scanned_at) return true;
    const d = new Date(s.scanned_at);
    const now = new Date();
    const days = range === "today" ? 1 : range === "7d" ? 7 : 30;
    return (now.getTime() - d.getTime()) / 86400000 <= days;
  });

  const verdictCounts = filtered.reduce(
    (acc, s) => {
      acc[s.verdict] = (acc[s.verdict] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );
  const pieData = Object.entries(verdictCounts).map(([name, value]) => ({
    name,
    value,
  }));

  const dailyMap: Record<string, number> = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    dailyMap[d.toISOString().slice(0, 10)] = 0;
  }
  filtered.forEach((s) => {
    if (s.scanned_at) {
      const day = s.scanned_at.slice(0, 10);
      if (day in dailyMap) dailyMap[day]++;
    }
  });
  const barData = Object.entries(dailyMap).map(([date, count]) => ({
    date: date.slice(5),
    count,
  }));

  const exportCSV = () => {
    const header =
      "Filename,Verdict,Threat Score,Hash,Duration (ms),Scanned At\n";
    const rows = filtered
      .map(
        (s) =>
          `"${s.filename}",${s.verdict},${s.threat_score},${s.file_hash},${s.scan_duration_ms},${s.scanned_at}`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sftms-report-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold gradient-text">Reports</h1>
          <p className="text-sm text-slate-500 mt-1">
            Scan analytics and threat breakdown
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-slate-900/60 rounded-xl p-1 border border-white/5">
            <RiCalendarLine className="w-4 h-4 text-slate-500 ml-2" />
            {["today", "7d", "30d", "all"].map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`range-btn ${range === r ? "active" : ""}`}
              >
                {r === "today"
                  ? "Today"
                  : r === "7d"
                    ? "7 Days"
                    : r === "30d"
                      ? "30 Days"
                      : "All"}
              </button>
            ))}
          </div>
          <button onClick={exportCSV} className="export-btn">
            <RiDownloadLine className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            icon: RiFileChartLine,
            label: "Total Scans",
            value: stats?.total_scans ?? 0,
            color: "text-cyan-400",
          },
          {
            icon: RiShieldCheckLine,
            label: "Clean Files",
            value: verdictCounts["clean"] ?? 0,
            color: "text-emerald-400",
          },
          {
            icon: RiAlertLine,
            label: "Suspicious",
            value: verdictCounts["suspicious"] ?? 0,
            color: "text-amber-400",
          },
          {
            icon: RiSkullLine,
            label: "Dangerous",
            value: verdictCounts["dangerous"] ?? 0,
            color: "text-red-400",
          },
        ].map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.08 }}
            className="report-card p-5"
          >
            <card.icon className={`w-8 h-8 mb-3 ${card.color}`} />
            <p className="text-2xl font-bold text-white">{card.value}</p>
            <p className="text-xs text-slate-500 mt-1">{card.label}</p>
          </motion.div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="report-card p-6"
        >
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Scans Per Day (Last 7 Days)
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData}>
              <XAxis
                dataKey="date"
                tick={{ fill: "#64748b", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#64748b", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#0f172a",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 12,
                  fontSize: 12,
                }}
              />
              <Bar
                dataKey="count"
                fill="#06b6d4"
                radius={[6, 6, 0, 0]}
                maxBarSize={40}
              />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="report-card p-6"
        >
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Verdict Distribution
          </h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={
                        COLORS[entry.name as keyof typeof COLORS] || "#64748b"
                      }
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 12,
                    fontSize: 12,
                  }}
                />
                <Legend wrapperStyle={{ fontSize: 12, color: "#94a3b8" }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[220px] text-slate-600 text-sm">
              No scan data yet
            </div>
          )}
        </motion.div>
      </div>

      {/* Scan History Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="report-card overflow-hidden"
      >
        <div className="p-5 border-b border-white/5">
          <h3 className="text-sm font-semibold text-slate-300">
            Scan History ({filtered.length} records)
          </h3>
        </div>
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="scan-history-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Duration</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center text-slate-600 py-8">
                    No scans in this time range
                  </td>
                </tr>
              ) : (
                filtered.slice(0, 50).map((s) => (
                  <tr key={s.id}>
                    <td className="text-slate-300 font-medium truncate max-w-[200px]">
                      {s.filename}
                    </td>
                    <td>
                      <span
                        className={`px-2 py-0.5 rounded-md text-xs font-medium ${verdictColor(s.verdict)}`}
                      >
                        {s.verdict}
                      </span>
                    </td>
                    <td className="text-slate-400">{s.threat_score}</td>
                    <td className="text-slate-400">{s.scan_duration_ms}ms</td>
                    <td className="text-slate-500 text-xs">
                      {s.scanned_at
                        ? new Date(s.scanned_at).toLocaleString()
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </motion.div>
    </motion.div>
  );
}