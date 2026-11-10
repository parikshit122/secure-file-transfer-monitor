import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  RiFolderShield2Fill,
  RiShieldCrossLine,
  RiAlertLine,
  RiArrowRightLine,
  RiUsbLine,
  RiShieldCheckLine,
  RiQuestionLine,
} from "react-icons/ri";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface Stats {
  total_files: number;
  total_scans: number;
  threats_blocked: number;
  active_alerts: number;
  total_transfers: number;
  tampered_files: number;
}

interface FileEvent {
  id: number;
  filename: string;
  event_type: string;
  source_path: string | null;
  dest_path: string | null;
  file_size: number;
  integrity_status: string;
  process_name: string | null;
  timestamp: string | null;
}

interface Alert {
  id: number;
  severity: string;
  alert_type: string;
  title: string;
  description: string;
  created_at: string | null;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<FileEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const [sRes, eRes, aRes] = await Promise.all([
        fetch("http://127.0.0.1:8000/api/stats"),
        fetch("http://127.0.0.1:8000/api/events?limit=10"),
        fetch("http://127.0.0.1:8000/api/alerts?active_only=true"),
      ]);
      setStats(await sRes.json());
      setEvents(await eRes.json());
      setAlerts(await aRes.json());
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  const chartData = [
    { time: "00:00", events: 2 },
    { time: "04:00", events: 5 },
    { time: "08:00", events: 12 },
    { time: "12:00", events: 25 },
    { time: "16:00", events: stats?.total_files || 0 },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const criticalAlert = alerts.find(
    (a) => a.severity === "critical" || a.severity === "high"
  );

  return (
    <div className="space-y-6">
      {/* Critical Alert Banner */}
      {criticalAlert && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="dashboard-alert-banner"
        >
          <RiAlertLine className="w-5 h-5 text-red-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-bold text-red-400 uppercase tracking-wider">
              {criticalAlert.alert_type.replace("_", " ")} ALERT
            </p>
            <p className="text-sm font-medium text-white truncate">
              {criticalAlert.title}
            </p>
          </div>
          <a
            href="/alerts"
            className="text-xs font-semibold text-red-400 hover:underline shrink-0"
          >
            View Alerts →
          </a>
        </motion.div>
      )}

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold gradient-text">System Dashboard</h1>
        <p className="text-sm text-slate-500 mt-1">
          Real-time file movement tracking, threat detection, and integrity monitoring
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            title: "Total Logged Events",
            value: stats?.total_files ?? 0,
            icon: RiFolderShield2Fill,
            color: "cyan",
          },
          {
            title: "Transfers Detected",
            value: stats?.total_transfers ?? 0,
            icon: RiUsbLine,
            color: "violet",
          },
          {
            title: "Threats / Violations",
            value: stats?.threats_blocked ?? 0,
            icon: RiShieldCrossLine,
            color: "red",
          },
          {
            title: "Active Security Alerts",
            value: stats?.active_alerts ?? 0,
            icon: RiAlertLine,
            color: "amber",
          },
        ].map((card, i) => (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.08 }}
            className="dashboard-card p-5"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-slate-500 font-medium">
                {card.title}
              </span>
              <card.icon className={`w-5 h-5 text-${card.color}-400`} />
            </div>
            <p className="text-2xl font-bold text-white">{card.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Chart Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="dashboard-card p-6"
      >
        <h3 className="text-sm font-semibold text-slate-300 mb-4">
          File Activity Trend (Today)
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorEvt" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="time"
              tick={{ fill: "#64748b", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "#64748b", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                background: "#0f172a",
                border: "1px solid rgba(255,255,255,0.1)",
                borderRadius: 12,
                fontSize: 12,
              }}
            />
            <Area
              type="monotone"
              dataKey="events"
              stroke="#06b6d4"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorEvt)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </motion.div>

      {/* Recent File Transfers Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="dashboard-card overflow-hidden"
      >
        <div className="p-5 border-b border-white/5 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300">
            Recent File Transfers &amp; Events
          </h3>
          <a
            href="/monitor"
            className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
          >
            Full Audit Log <RiArrowRightLine className="w-3 h-3" />
          </a>
        </div>
        <div className="overflow-x-auto">
          <table className="dashboard-table">
            <thead>
              <tr>
                <th>Event</th>
                <th>File</th>
                <th>Source → Destination</th>
                <th>Process</th>
                <th>Integrity</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center text-slate-600 py-8">
                    No activity recorded yet
                  </td>
                </tr>
              ) : (
                events.slice(0, 5).map((e) => (
                  <tr key={e.id}>
                    <td>
                      <span
                        className={
                          "px-2 py-0.5 rounded-md text-xs font-medium uppercase " +
                          (e.event_type === "transfer" || e.event_type === "move"
                            ? "bg-violet-400/10 text-violet-400"
                            : e.event_type === "delete"
                              ? "bg-red-400/10 text-red-400"
                              : "bg-cyan-400/10 text-cyan-400")
                        }
                      >
                        {e.event_type}
                      </span>
                    </td>
                    <td className="text-slate-200 font-medium truncate max-w-45">
                      {e.filename}
                    </td>
                    <td className="text-slate-400 text-xs truncate max-w-50">
                      {e.source_path
                        ? e.source_path.split("\\").slice(-2).join("\\")
                        : "—"}
                    </td>
                    <td className="text-slate-400 text-xs">
                      {e.process_name || "—"}
                    </td>
                    <td>
                      <span
                        className={
                          "text-xs flex items-center gap-1 " +
                          (e.integrity_status === "verified"
                            ? "text-emerald-400"
                            : e.integrity_status === "tampered"
                              ? "text-red-400"
                              : "text-slate-500")
                        }
                      >
                        {e.integrity_status === "verified" ? (
                          <RiShieldCheckLine className="w-3.5 h-3.5" />
                        ) : e.integrity_status === "tampered" ? (
                          <RiShieldCrossLine className="w-3.5 h-3.5" />
                        ) : (
                          <RiQuestionLine className="w-3.5 h-3.5" />
                        )}
                        {e.integrity_status}
                      </span>
                    </td>
                    <td className="text-slate-500 text-xs">
                      {e.timestamp
                        ? new Date(e.timestamp).toLocaleTimeString()
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </motion.div>
    </div>
  );
}