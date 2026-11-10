import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiAlertLine,
  RiCheckLine,
  RiShieldCrossLine,
  RiFolderWarningLine,
  RiFileShieldLine,
  RiUsbLine,
  RiFilter3Line,
  RiSafe2Line,
  RiRestartLine,
  RiDeleteBinLine,
} from "react-icons/ri";

interface Alert {
  id: number;
  severity: string;
  alert_type: string;
  title: string;
  description: string;
  is_resolved: boolean;
  created_at: string | null;
}

interface QuarantinedFile {
  id: number;
  filename: string;
  original_path: string;
  file_size: number;
  reason: string;
  quarantined_at: string | null;
}

const alertTypeConfig: Record<
  string,
  { icon: typeof RiAlertLine; color: string; label: string }
> = {
  threat: {
    icon: RiShieldCrossLine,
    color: "text-red-400 bg-red-400/10 border-red-400/20",
    label: "Threat",
  },
  unauthorized_move: {
    icon: RiFolderWarningLine,
    color: "text-amber-400 bg-amber-400/10 border-amber-400/20",
    label: "Unauthorized Move",
  },
  integrity_mismatch: {
    icon: RiFileShieldLine,
    color: "text-violet-400 bg-violet-400/10 border-violet-400/20",
    label: "Tampering Mismatch",
  },
  exfiltration: {
    icon: RiUsbLine,
    color: "text-rose-400 bg-rose-400/10 border-rose-400/20",
    label: "Exfiltration Risk",
  },
};

const severityConfig: Record<string, string> = {
  critical: "text-red-400 bg-red-400/10",
  high: "text-amber-400 bg-amber-400/10",
  medium: "text-yellow-400 bg-yellow-400/10",
  low: "text-cyan-400 bg-cyan-400/10",
};

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantinedFile[]>([]);
  const [activeTab, setActiveTab] = useState<"alerts" | "quarantine">("alerts");
  const [filter, setFilter] = useState("active");
  const [typeFilter, setTypeFilter] = useState("all");
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const [aRes, qRes] = await Promise.all([
        fetch(
          `http://127.0.0.1:8000/api/alerts?active_only=${filter === "active"}`
        ),
        fetch("http://127.0.0.1:8000/api/quarantine"),
      ]);
      setAlerts(await aRes.json());
      setQuarantine(await qRes.json());
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
  }, [filter]);

  const handleResolve = async (id: number) => {
    try {
      await fetch(`http://127.0.0.1:8000/api/alerts/${id}/resolve`, {
        method: "POST",
      });
      setAlerts((prev) => prev.filter((a) => a.id !== id));
    } catch {
      /* ignore */
    }
  };

  const handleRestore = async (id: number) => {
    try {
      await fetch(`http://127.0.0.1:8000/api/quarantine/${id}/restore`, {
        method: "POST",
      });
      setQuarantine((prev) => prev.filter((q) => q.id !== id));
      loadData();
    } catch {
      /* ignore */
    }
  };

  const handleDeleteQuarantine = async (id: number) => {
    try {
      await fetch(`http://127.0.0.1:8000/api/quarantine/${id}`, {
        method: "DELETE",
      });
      setQuarantine((prev) => prev.filter((q) => q.id !== id));
    } catch {
      /* ignore */
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (typeFilter === "all") return true;
    return a.alert_type === typeFilter;
  });

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
          <h1 className="text-2xl font-bold gradient-text">
            Security Alerts &amp; Quarantine Vault
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Real-time security violations and active threat neutralization
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-2 bg-slate-900/80 p-1 rounded-xl border border-white/5">
          <button
            onClick={() => setActiveTab("alerts")}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "alerts"
                ? "bg-cyan-400/20 text-cyan-400 border border-cyan-400/30"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <RiAlertLine className="w-4 h-4" />
            Alerts ({alerts.length})
          </button>
          <button
            onClick={() => setActiveTab("quarantine")}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "quarantine"
                ? "bg-red-400/20 text-red-400 border border-red-400/30"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <RiSafe2Line className="w-4 h-4" />
            Quarantine Vault ({quarantine.length})
          </button>
        </div>
      </div>

      {activeTab === "alerts" ? (
        <>
          {/* Alerts Filter Row */}
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2 overflow-x-auto pb-1">
              <RiFilter3Line className="w-4 h-4 text-slate-500 shrink-0" />
              {[
                { key: "all", label: "All Types" },
                { key: "threat", label: "Threats" },
                { key: "unauthorized_move", label: "Unauthorized Movement" },
                { key: "integrity_mismatch", label: "Integrity Mismatch" },
                { key: "exfiltration", label: "Exfiltration" },
              ].map((t) => (
                <button
                  key={t.key}
                  onClick={() => setTypeFilter(t.key)}
                  className={`alert-type-btn ${
                    typeFilter === t.key ? "active" : ""
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setFilter("active")}
                className={`alert-tab-btn ${
                  filter === "active" ? "active" : ""
                }`}
              >
                Active
              </button>
              <button
                onClick={() => setFilter("all")}
                className={`alert-tab-btn ${filter === "all" ? "active" : ""}`}
              >
                All History
              </button>
            </div>
          </div>

          {/* Alert Feed */}
          <div className="space-y-3">
            <AnimatePresence>
              {filteredAlerts.length === 0 ? (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="alert-empty-card"
                >
                  <RiCheckLine className="w-12 h-12 text-emerald-400 mx-auto mb-2" />
                  <p className="text-slate-300 font-semibold">All Clear!</p>
                  <p className="text-slate-500 text-xs mt-1">
                    No security alerts found in this view.
                  </p>
                </motion.div>
              ) : (
                filteredAlerts.map((alert) => {
                  const cfg =
                    alertTypeConfig[alert.alert_type] || alertTypeConfig.threat;
                  const Icon = cfg.icon;

                  return (
                    <motion.div
                      key={alert.id}
                      layout
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                      className="alert-card p-4"
                    >
                      <div className="flex items-start gap-4">
                        <div
                          className={`p-2.5 rounded-xl border ${cfg.color} shrink-0`}
                        >
                          <Icon className="w-5 h-5" />
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span
                              className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider ${
                                severityConfig[alert.severity] ||
                                severityConfig.medium
                              }`}
                            >
                              {alert.severity}
                            </span>
                            <span className="text-xs text-slate-500 font-medium">
                              {cfg.label}
                            </span>
                            <span className="text-slate-600 text-xs">•</span>
                            <span className="text-xs text-slate-500">
                              {alert.created_at
                                ? new Date(alert.created_at).toLocaleString()
                                : "—"}
                            </span>
                          </div>

                          <h3 className="text-sm font-semibold text-white">
                            {alert.title}
                          </h3>
                          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                            {alert.description}
                          </p>
                        </div>

                        {!alert.is_resolved && (
                          <button
                            onClick={() => handleResolve(alert.id)}
                            className="alert-resolve-btn shrink-0"
                            title="Mark as Resolved"
                          >
                            <RiCheckLine className="w-4 h-4" />
                            Resolve
                          </button>
                        )}
                      </div>
                    </motion.div>
                  );
                })
              )}
            </AnimatePresence>
          </div>
        </>
      ) : (
        /* Quarantine Vault Section */
        <div className="space-y-3">
          <AnimatePresence>
            {quarantine.length === 0 ? (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="alert-empty-card"
              >
                <RiSafe2Line className="w-12 h-12 text-slate-600 mx-auto mb-2" />
                <p className="text-slate-300 font-semibold">
                  Vault Empty
                </p>
                <p className="text-slate-500 text-xs mt-1">
                  No files currently isolated in quarantine.
                </p>
              </motion.div>
            ) : (
              quarantine.map((file) => (
                <motion.div
                  key={file.id}
                  layout
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="alert-card p-4 border-l-4 border-l-red-500"
                >
                  <div className="flex items-center justify-between flex-wrap gap-4">
                    <div className="flex items-center gap-3.5 min-w-0">
                      <div className="p-2.5 rounded-xl bg-red-400/10 text-red-400 border border-red-400/20 shrink-0">
                        <RiSafe2Line className="w-5 h-5" />
                      </div>

                      <div className="min-w-0">
                        <h3 className="text-sm font-bold text-white truncate">
                          {file.filename}
                        </h3>
                        <p className="text-xs text-slate-400 mt-0.5 truncate max-w-lg">
                          Original Path: {file.original_path}
                        </p>
                        <p className="text-[11px] text-red-400 mt-1 italic">
                          Reason: {file.reason}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleRestore(file.id)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold text-cyan-400 bg-cyan-400/10 border border-cyan-400/20 hover:bg-cyan-400/20 transition-all"
                        title="Restore file back to original path"
                      >
                        <RiRestartLine className="w-3.5 h-3.5" />
                        Restore
                      </button>

                      <button
                        onClick={() => handleDeleteQuarantine(file.id)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold text-red-400 bg-red-400/10 border border-red-400/20 hover:bg-red-400/20 transition-all"
                        title="Permanently Delete file from disk"
                      >
                        <RiDeleteBinLine className="w-3.5 h-3.5" />
                        Delete
                      </button>
                    </div>
                  </div>
                </motion.div>
              ))
            )}
          </AnimatePresence>
        </div>
      )}
    </motion.div>
  );
}