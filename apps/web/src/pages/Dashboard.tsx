import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  RiHardDrive3Fill,
  RiScan2Fill,
  RiShieldCrossFill,
  RiAlarmWarningFill,
  RiArrowUpSFill,
  RiArrowDownSFill,
  RiTimeFill,
  RiCheckDoubleFill,
  RiErrorWarningFill,
  RiCloseCircleFill,
  RiShieldCheckFill,
} from "react-icons/ri";
import type { IconType } from "react-icons";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const activityData = [
  { time: "00:00", events: 2 },
  { time: "03:00", events: 0 },
  { time: "06:00", events: 1 },
  { time: "09:00", events: 5 },
  { time: "12:00", events: 8 },
  { time: "15:00", events: 12 },
  { time: "18:00", events: 7 },
  { time: "21:00", events: 4 },
  { time: "Now", events: 3 },
];

function AnimatedNumber({ value }: { value: number }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = Math.max(1, Math.floor(value / 60));
    const interval = setInterval(() => {
      start += step;
      if (start >= value) {
        setDisplay(value);
        clearInterval(interval);
      } else setDisplay(start);
    }, 16);
    return () => clearInterval(interval);
  }, [value]);
  return <>{display}</>;
}

function VerdictIcon({ verdict }: { verdict: string }) {
  const map: Record<string, { icon: IconType; cls: string }> = {
    clean: { icon: RiCheckDoubleFill, cls: "text-emerald-400" },
    suspicious: { icon: RiErrorWarningFill, cls: "text-amber-400" },
    dangerous: { icon: RiCloseCircleFill, cls: "text-rose-400" },
  };
  const cfg = map[verdict] || {
    icon: RiShieldCheckFill,
    cls: "text-slate-400",
  };
  const Icon = cfg.icon;
  return <Icon className={"w-5 h-5 " + cfg.cls} />;
}

const cardVariants = {
  hidden: { opacity: 0, y: 30, scale: 0.95 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { delay: i * 0.1, duration: 0.5, ease: "easeOut" as const },
  }),
};

export default function Dashboard() {
  const [stats, setStats] = useState({
    total_files: 0,
    total_scans: 0,
    threats_blocked: 0,
    active_alerts: 0,
  });
  const [scans, setScans] = useState<Record<string, unknown>[]>([]);
  const [alerts, setAlerts] = useState<Record<string, unknown>[]>([]);

  useEffect(() => {
    const load = () => {
      fetch("/api/stats")
        .then((r) => r.json())
        .then(setStats)
        .catch(() => {});
      fetch("/api/scans")
        .then((r) => r.json())
        .then(setScans)
        .catch(() => {});
      fetch("/api/alerts")
        .then((r) => r.json())
        .then(setAlerts)
        .catch(() => {});
    };
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  const cards = [
    {
      label: "Files Monitored",
      value: stats.total_files,
      icon: RiHardDrive3Fill,
      gradient: "from-cyan-400 to-blue-500",
      shadow: "shadow-cyan-400/20",
      change: "Downloads",
      up: true,
    },
    {
      label: "Files Scanned",
      value: stats.total_scans,
      icon: RiScan2Fill,
      gradient: "from-violet-400 to-purple-500",
      shadow: "shadow-violet-400/20",
      change: "Auto",
      up: true,
    },
    {
      label: "Threats Caught",
      value: stats.threats_blocked,
      icon: RiShieldCrossFill,
      gradient: "from-rose-400 to-pink-500",
      shadow: "shadow-rose-400/20",
      change: stats.threats_blocked > 0 ? "Action needed" : "All clear",
      up: stats.threats_blocked === 0,
    },
    {
      label: "Active Alerts",
      value: stats.active_alerts,
      icon: RiAlarmWarningFill,
      gradient: "from-amber-400 to-orange-500",
      shadow: "shadow-amber-400/20",
      change: stats.active_alerts > 0 ? "Review" : "None",
      up: stats.active_alerts === 0,
    },
  ];

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
      >
        <h1 className="text-3xl font-bold gradient-text">Security Dashboard</h1>
        <p className="text-slate-400 mt-1">
          Auto-scanning your Downloads folder in real time
        </p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((c, i) => (
          <motion.div
            key={c.label}
            custom={i}
            variants={cardVariants}
            initial="hidden"
            animate="visible"
            whileHover={{ y: -4, scale: 1.02 }}
            className="glass rounded-2xl p-5 glow-border relative overflow-hidden group cursor-default stat-card-glow"
          >
            <div
              className={
                "absolute -top-10 -right-10 w-32 h-32 rounded-full bg-linear-to-br " +
                c.gradient +
                " opacity-10 group-hover:opacity-20 transition-opacity blur-2xl"
              }
            />
            <div className="flex items-center justify-between relative">
              <div
                className={
                  "p-3 rounded-xl bg-linear-to-br " +
                  c.gradient +
                  " shadow-lg " +
                  c.shadow
                }
              >
                <c.icon className="w-6 h-6 text-white" />
              </div>
              <span
                className={
                  "flex items-center text-xs font-medium " +
                  (c.up ? "text-emerald-400" : "text-rose-400")
                }
              >
                {c.up ? (
                  <RiArrowUpSFill className="w-4 h-4" />
                ) : (
                  <RiArrowDownSFill className="w-4 h-4" />
                )}
                {c.change}
              </span>
            </div>
            <div className="mt-4 relative">
              <p className="text-4xl font-bold text-white">
                <AnimatedNumber value={c.value} />
              </p>
              <p className="text-sm text-slate-400 mt-1">{c.label}</p>
            </div>
          </motion.div>
        ))}
      </div>

      {alerts.length > 0 && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass rounded-2xl p-5 border-rose-400/20"
        >
          <div className="flex items-center gap-3 mb-4">
            <RiCloseCircleFill className="w-6 h-6 text-rose-400" />
            <h2 className="text-lg font-bold text-rose-400">
              Active Threat Alerts
            </h2>
          </div>
          <div className="space-y-2">
            {alerts.slice(0, 5).map((a, i) => (
              <motion.div
                key={String(a.id)}
                initial={{ x: -20, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: i * 0.1 }}
                className="flex items-center gap-3 bg-slate-900/50 rounded-xl p-3"
              >
                <VerdictIcon verdict={String(a.severity)} />
                <div className="flex-1">
                  <p className="text-sm font-medium text-white">
                    {String(a.title)}
                  </p>
                  <p className="text-xs text-slate-400">
                    {String(a.description)}
                  </p>
                </div>
                <button
                  onClick={() => {
                    fetch("/api/alerts/" + a.id + "/resolve", {
                      method: "POST",
                    }).then(() =>
                      setAlerts(alerts.filter((x) => x.id !== a.id)),
                    );
                  }}
                  className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 transition-colors"
                >
                  Dismiss
                </button>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="glass rounded-2xl p-5 glow-border"
        >
          <h2 className="text-lg font-semibold text-white mb-4">
            Activity Timeline
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={activityData}>
              <defs>
                <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  border: "1px solid #334155",
                  borderRadius: "12px",
                  color: "#e2e8f0",
                }}
              />
              <Area
                type="monotone"
                dataKey="events"
                stroke="#06b6d4"
                strokeWidth={2}
                fill="url(#cg)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="glass rounded-2xl p-5 glow-border"
        >
          <h2 className="text-lg font-semibold text-white mb-4">
            Recent Scans
          </h2>
          {scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-slate-500">
              <RiScan2Fill className="w-12 h-12 mb-2 text-slate-700" />
              <p className="text-sm">Download a file to see scan results</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-56 overflow-y-auto">
              {scans.slice(0, 10).map((s, i) => (
                <motion.div
                  key={String(s.id)}
                  initial={{ x: 20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: i * 0.05 }}
                  whileHover={{
                    x: 4,
                    backgroundColor: "rgba(255,255,255,0.03)",
                  }}
                  className="flex items-center gap-3 p-3 rounded-xl bg-slate-800/30 transition-colors event-row-new"
                >
                  <VerdictIcon verdict={String(s.verdict)} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white truncate font-medium">
                      {String(s.filename)}
                    </p>
                    <p className="text-xs text-slate-500 flex items-center gap-1">
                      <RiTimeFill className="w-3 h-3" />{" "}
                      {String(s.scan_duration_ms)}ms &middot; Score:{" "}
                      {String(s.threat_score)}
                    </p>
                  </div>
                  <span
                    className={
                      "text-xs font-bold px-2.5 py-1 rounded-full " +
                      (s.verdict === "clean"
                        ? "bg-emerald-400/10 text-emerald-400 border border-emerald-400/30"
                        : s.verdict === "suspicious"
                          ? "bg-amber-400/10 text-amber-400 border border-amber-400/30"
                          : "bg-rose-400/10 text-rose-400 border border-rose-400/30")
                    }
                  >
                    {String(s.verdict)}
                  </span>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      </div>
    </div>
  );
}
