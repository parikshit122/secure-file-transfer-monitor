import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  RiFolderShield2Fill,
  RiSearchLine,
  RiArrowRightLine,
  RiShieldCheckLine,
  RiShieldCrossLine,
  RiQuestionLine,
  RiAlertLine,
  RiUsbLine,
  RiDeleteBinLine,
  RiFileCopyLine,
  RiFileTransferLine,
  RiEditLine,
  RiAddLine,
  RiFingerprintLine,
} from "react-icons/ri";

interface FileEvent {
  id: number;
  filename: string;
  event_type: string;
  source_path: string | null;
  dest_path: string | null;
  file_size: number;
  file_hash: string | null;
  pre_hash: string | null;
  post_hash: string | null;
  integrity_status: string;
  process_name: string | null;
  username: string | null;
  is_sensitive: boolean;
  timestamp: string | null;
}

const eventTypeConfig: Record<
  string,
  { icon: typeof RiAddLine; color: string; label: string }
> = {
  create: { icon: RiAddLine, color: "text-cyan-400 bg-cyan-400/10", label: "Created" },
  modify: { icon: RiEditLine, color: "text-blue-400 bg-blue-400/10", label: "Modified" },
  move: { icon: RiFileTransferLine, color: "text-violet-400 bg-violet-400/10", label: "Moved" },
  transfer: { icon: RiUsbLine, color: "text-red-400 bg-red-400/10", label: "Transfer" },
  delete: { icon: RiDeleteBinLine, color: "text-slate-400 bg-slate-400/10", label: "Deleted" },
  copy: { icon: RiFileCopyLine, color: "text-amber-400 bg-amber-400/10", label: "Copied" },
};

const integrityConfig: Record<
  string,
  { icon: typeof RiShieldCheckLine; color: string; label: string }
> = {
  baseline: { icon: RiFingerprintLine, color: "text-cyan-400", label: "Baseline" },
  verified: { icon: RiShieldCheckLine, color: "text-emerald-400", label: "Verified" },
  modified: { icon: RiEditLine, color: "text-amber-400", label: "Modified" },
  tampered: { icon: RiShieldCrossLine, color: "text-red-400 font-bold", label: "Tampered" },
  unknown: { icon: RiQuestionLine, color: "text-slate-500", label: "Unknown" },
};

function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export default function FileMonitor() {
  const [events, setEvents] = useState<FileEvent[]>([]);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/events?limit=100");
      const data = await res.json();
      setEvents(Array.isArray(data) ? data : []);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

  const filtered = events.filter((e) => {
    const matchSearch =
      !search ||
      e.filename.toLowerCase().includes(search.toLowerCase()) ||
      (e.source_path || "").toLowerCase().includes(search.toLowerCase()) ||
      (e.dest_path || "").toLowerCase().includes(search.toLowerCase());
    const matchType = typeFilter === "all" || e.event_type === typeFilter;
    return matchSearch && matchType;
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
          <h1 className="text-2xl font-bold gradient-text">File Monitor</h1>
          <p className="text-sm text-slate-500 mt-1">
            Real-time file transfer tracking &amp; integrity verification
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Live — {events.length} events
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="monitor-search">
          <RiSearchLine className="w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search files or paths..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="monitor-search-input"
          />
        </div>
        <div className="flex items-center gap-1 bg-slate-900/60 rounded-xl p-1 border border-white/5">
          {["all", "create", "modify", "move", "transfer", "delete"].map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`monitor-filter-btn ${typeFilter === t ? "active" : ""}`}
            >
              {t === "all" ? "All" : t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Event Table */}
      <div className="monitor-table-card">
        <div className="overflow-x-auto max-h-125 overflow-y-auto">
          <table className="monitor-table">
            <thead>
              <tr>
                <th>Event</th>
                <th>File</th>
                <th>Source → Destination</th>
                <th>User</th>
                <th>Size</th>
                <th>Integrity</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center text-slate-600 py-12">
                    <RiFolderShield2Fill className="w-12 h-12 mx-auto mb-3 text-slate-700" />
                    <p>No file events detected yet</p>
                    <p className="text-xs mt-1">
                      Move, copy, or download files in Downloads or Documents
                    </p>
                  </td>
                </tr>
              ) : (
                filtered.map((e) => {
                  const evt = eventTypeConfig[e.event_type] || eventTypeConfig.create;
                  const integ = integrityConfig[e.integrity_status] || integrityConfig.unknown;
                  const EvtIcon = evt.icon;
                  const IntegIcon = integ.icon;

                  return (
                    <tr key={e.id} className="monitor-table-row">
                      <td>
                        <span className={`monitor-badge ${evt.color}`}>
                          <EvtIcon className="w-3 h-3" />
                          {evt.label}
                        </span>
                        {e.is_sensitive && (
                          <span className="monitor-badge text-red-400 bg-red-400/10 ml-1">
                            <RiAlertLine className="w-3 h-3" />
                            Sensitive
                          </span>
                        )}
                      </td>
                      <td className="text-slate-200 font-medium truncate max-w-45">
                        {e.filename}
                      </td>
                      <td className="text-xs">
                        <div className="flex items-center gap-1 text-slate-400">
                          <span className="truncate max-w-35" title={e.source_path || ""}>
                            {e.source_path
                              ? e.source_path.split("\\").slice(-2).join("\\")
                              : "—"}
                          </span>
                          {(e.event_type === "move" || e.event_type === "transfer") && (
                            <>
                              <RiArrowRightLine className="w-3 h-3 text-cyan-400 shrink-0" />
                              <span
                                className="truncate max-w-35 text-cyan-400"
                                title={e.dest_path || ""}
                              >
                                {e.dest_path
                                  ? e.dest_path.split("\\").slice(-2).join("\\")
                                  : "—"}
                              </span>
                            </>
                          )}
                        </div>
                      </td>
                      <td className="text-slate-400 text-xs">
                        {e.username || "—"}
                      </td>
                      <td className="text-slate-400 text-xs">
                        {formatSize(e.file_size)}
                      </td>
                      <td>
                        <span className={`flex items-center gap-1 text-xs ${integ.color}`}>
                          <IntegIcon className="w-3.5 h-3.5" />
                          {integ.label}
                        </span>
                      </td>
                      <td className="text-slate-500 text-xs whitespace-nowrap">
                        {e.timestamp
                          ? new Date(e.timestamp).toLocaleTimeString()
                          : "—"}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );
}