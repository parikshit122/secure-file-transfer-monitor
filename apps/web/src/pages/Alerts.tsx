import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiAlarmWarningFill,
  RiCheckDoubleFill,
  RiErrorWarningFill,
  RiCloseCircleFill,
  RiShieldCheckFill,
  RiRefreshLine,
  RiTimeFill,
  RiDeleteBin6Fill,
  RiAlertFill,
  RiInformationFill,
} from "react-icons/ri";
import type { IconType } from "react-icons";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface Alert {
  id: number;
  severity: string;
  title: string;
  description: string;
  is_resolved: boolean;
  created_at: string;
}

const SEV: Record<
  string,
  {
    icon: IconType;
    color: string;
    bg: string;
    border: string;
    label: string;
    bar: string;
    css: string;
  }
> = {
  dangerous: {
    icon: RiCloseCircleFill,
    color: "text-rose-400",
    bg: "bg-rose-400/10",
    border: "border-rose-400/30",
    label: "Dangerous",
    bar: "#f43f5e",
    css: "alert-dangerous",
  },
  suspicious: {
    icon: RiErrorWarningFill,
    color: "text-amber-400",
    bg: "bg-amber-400/10",
    border: "border-amber-400/30",
    label: "Suspicious",
    bar: "#f59e0b",
    css: "alert-suspicious",
  },
  info: {
    icon: RiInformationFill,
    color: "text-cyan-400",
    bg: "bg-cyan-400/10",
    border: "border-cyan-400/30",
    label: "Info",
    bar: "#06b6d4",
    css: "alert-info",
  },
};

function timeAgo(ts: string) {
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return s + "s ago";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60);
  if (h < 24) return h + "h ago";
  return Math.floor(h / 24) + "d ago";
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState("active");
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    const url =
      filter === "active"
        ? "/api/alerts?active_only=true"
        : "/api/alerts?active_only=false";
    fetch(url)
      .then((r) => r.json())
      .then((data) => {
        setAlerts(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  const dismiss = (id: number) => {
    fetch("/api/alerts/" + id + "/resolve", { method: "POST" }).then(() =>
      setAlerts(alerts.filter((a) => a.id !== id)),
    );
  };

  const dismissAll = () => {
    Promise.all(
      alerts.map((a) =>
        fetch("/api/alerts/" + a.id + "/resolve", { method: "POST" }),
      ),
    ).then(() => setAlerts([]));
  };

  const counts = {
    active: alerts.filter((a) => !a.is_resolved).length,
    dangerous: alerts.filter((a) => a.severity === "dangerous").length,
    suspicious: alerts.filter((a) => a.severity === "suspicious").length,
  };

  const chartData = [
    { name: "Dangerous", count: counts.dangerous },
    { name: "Suspicious", count: counts.suspicious },
    {
      name: "Clean",
      count: Math.max(0, 10 - counts.dangerous - counts.suspicious),
    },
  ];

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
      >
        <h1 className="text-3xl font-bold gradient-text">Threat Alerts</h1>
        <p className="text-slate-400 mt-1">
          Security alerts from your Downloads folder
        </p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {(
          [
            {
              label: "Active Alerts",
              value: counts.active,
              icon: RiAlarmWarningFill,
              gradient: "from-rose-400 to-pink-500",
              shadow: "shadow-rose-400/20",
            },
            {
              label: "Dangerous",
              value: counts.dangerous,
              icon: RiCloseCircleFill,
              gradient: "from-red-500 to-rose-600",
              shadow: "shadow-red-400/20",
            },
            {
              label: "Suspicious",
              value: counts.suspicious,
              icon: RiErrorWarningFill,
              gradient: "from-amber-400 to-orange-500",
              shadow: "shadow-amber-400/20",
            },
          ] as {
            label: string;
            value: number;
            icon: IconType;
            gradient: string;
            shadow: string;
          }[]
        ).map((c, i) => (
          <motion.div
            key={c.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            whileHover={{ y: -3 }}
            className="glass rounded-2xl p-5 glow-border relative overflow-hidden stat-card-glow"
          >
            <div
              className={
                "absolute -top-8 -right-8 w-24 h-24 rounded-full bg-linear-to-br " +
                c.gradient +
                " opacity-10 blur-2xl"
              }
            />
            <div className="flex items-center gap-3 relative">
              <div
                className={
                  "p-2.5 rounded-xl bg-linear-to-br " +
                  c.gradient +
                  " shadow-lg " +
                  c.shadow
                }
              >
                <c.icon className="w-5 h-5 text-white" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{c.value}</p>
                <p className="text-xs text-slate-400">{c.label}</p>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="glass rounded-2xl p-5 glow-border"
        >
          <h2 className="text-lg font-semibold text-white mb-4">
            Threat Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData} barSize={40}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  border: "1px solid #334155",
                  borderRadius: "12px",
                  color: "#e2e8f0",
                }}
              />
              <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                {chartData.map((_entry, i) => (
                  <Cell
                    key={i}
                    fill={i === 0 ? "#f43f5e" : i === 1 ? "#f59e0b" : "#10b981"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="lg:col-span-2 glass rounded-2xl glow-border overflow-hidden"
        >
          <div className="flex items-center justify-between p-5 border-b border-white/5">
            <div className="flex items-center gap-3">
              <RiAlertFill className="w-5 h-5 text-rose-400" />
              <h2 className="text-lg font-semibold text-white">Alert Feed</h2>
              <span className="text-xs bg-rose-400/10 text-rose-400 px-2 py-0.5 rounded-full border border-rose-400/30">
                {alerts.length}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex bg-slate-800 rounded-lg p-0.5">
                {["active", "all"].map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={
                      "px-3 py-1.5 rounded-md text-xs font-medium transition-colors " +
                      (filter === f
                        ? "bg-slate-700 text-white"
                        : "text-slate-500 hover:text-white")
                    }
                  >
                    {f === "active" ? "Active" : "All"}
                  </button>
                ))}
              </div>
              {alerts.length > 0 && (
                <button
                  onClick={dismissAll}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-400/10 text-rose-400 border border-rose-400/30 hover:bg-rose-400/20 transition-colors clear-all-hover"
                >
                  <RiDeleteBin6Fill className="w-3 h-3" /> Clear All
                </button>
              )}
              <button
                onClick={load}
                className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-white/5 transition-colors"
              >
                <RiRefreshLine className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="max-h-100 overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center text-slate-500 shimmer rounded-lg m-4 h-20" />
            ) : alerts.length === 0 ? (
              <div className="p-12 text-center">
                <RiShieldCheckFill className="w-16 h-16 text-emerald-400/30 mx-auto mb-3" />
                <p className="text-lg font-medium text-emerald-400">
                  All Clear!
                </p>
                <p className="text-sm text-slate-500 mt-1">
                  No active threats detected
                </p>
              </div>
            ) : (
              <AnimatePresence>
                {alerts.map((alert, i) => {
                  const s = SEV[alert.severity] || SEV.info;
                  const SIcon = s.icon;
                  return (
                    <motion.div
                      key={alert.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20, height: 0 }}
                      transition={{ delay: i * 0.05 }}
                      whileHover={{ backgroundColor: "rgba(255,255,255,0.02)" }}
                      className={
                        "flex items-start gap-4 p-4 border-b border-white/5 transition-colors " +
                        s.css +
                        (alert.is_resolved ? " opacity-50" : "")
                      }
                    >
                      <div
                        className={
                          "p-2 rounded-xl " + s.bg + " shrink-0 mt-0.5"
                        }
                      >
                        <SIcon className={"w-5 h-5 " + s.color} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-bold text-white truncate">
                            {alert.title}
                          </p>
                          <span
                            className={
                              "text-[10px] font-bold px-2 py-0.5 rounded-full " +
                              s.bg +
                              " " +
                              s.color +
                              " border " +
                              s.border
                            }
                          >
                            {s.label}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                          {alert.description}
                        </p>
                        <p className="text-xs text-slate-600 mt-1.5 flex items-center gap-1">
                          <RiTimeFill className="w-3 h-3" />{" "}
                          {timeAgo(alert.created_at)}
                        </p>
                      </div>
                      {!alert.is_resolved && (
                        <button
                          onClick={() => dismiss(alert.id)}
                          className="shrink-0 flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:bg-emerald-400/10 hover:text-emerald-400 border border-slate-700 hover:border-emerald-400/30 transition-colors"
                        >
                          <RiCheckDoubleFill className="w-3 h-3" /> Dismiss
                        </button>
                      )}
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
