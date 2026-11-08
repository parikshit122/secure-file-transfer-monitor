import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import {
  RiSearchLine,
  RiFilter3Line,
  RiRefreshLine,
  RiEyeLine,
  RiEyeOffLine,
  RiFileAddFill,
  RiFileEditFill,
  RiFileReduceFill,
  RiFileTransferFill,
  RiFolderOpenFill,
  RiRadioButtonFill,
  RiCheckDoubleFill,
  RiErrorWarningFill,
  RiCloseCircleFill,
} from "react-icons/ri";
import type { IconType } from "react-icons";

interface FileEvent {
  id: number;
  filename: string;
  event_type: string;
  file_path: string;
  file_size: number;
  file_hash: string;
  timestamp: string;
}

interface ScanData {
  id: number;
  filename: string;
  verdict: string;
  threat_score: number;
}

const EVT: Record<
  string,
  { label: string; icon: IconType; color: string; bg: string }
> = {
  created: {
    label: "Created",
    icon: RiFileAddFill,
    color: "text-emerald-400",
    bg: "bg-emerald-400/10 border-emerald-400/30",
  },
  modified: {
    label: "Modified",
    icon: RiFileEditFill,
    color: "text-amber-400",
    bg: "bg-amber-400/10 border-amber-400/30",
  },
  deleted: {
    label: "Deleted",
    icon: RiFileReduceFill,
    color: "text-rose-400",
    bg: "bg-rose-400/10 border-rose-400/30",
  },
  moved: {
    label: "Moved",
    icon: RiFileTransferFill,
    color: "text-cyan-400",
    bg: "bg-cyan-400/10 border-cyan-400/30",
  },
};

function formatSize(b: number) {
  if (!b) return "—";
  const k = 1024,
    s = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(1)) + " " + s[i];
}

function timeAgo(ts: string) {
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return s + "s ago";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m ago";
  return Math.floor(m / 60) + "h ago";
}

function VerdictBadge({ verdict }: { verdict: string }) {
  if (verdict === "clean")
    return (
      <span className="flex items-center gap-1 text-xs font-medium text-emerald-400 bg-emerald-400/10 border border-emerald-400/30 px-2 py-1 rounded-full">
        <RiCheckDoubleFill className="w-3 h-3" />
        Clean
      </span>
    );
  if (verdict === "suspicious")
    return (
      <span className="flex items-center gap-1 text-xs font-medium text-amber-400 bg-amber-400/10 border border-amber-400/30 px-2 py-1 rounded-full">
        <RiErrorWarningFill className="w-3 h-3" />
        Suspicious
      </span>
    );
  if (verdict === "dangerous")
    return (
      <span className="flex items-center gap-1 text-xs font-medium text-rose-400 bg-rose-400/10 border border-rose-400/30 px-2 py-1 rounded-full">
        <RiCloseCircleFill className="w-3 h-3" />
        Dangerous
      </span>
    );
  return <span className="text-xs text-slate-500">—</span>;
}

export default function FileMonitor() {
  const [events, setEvents] = useState<FileEvent[]>([]);
  const [scans, setScans] = useState<ScanData[]>([]);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const load = useCallback(() => {
    fetch("/api/events")
      .then((r) => r.json())
      .then(setEvents)
      .catch(() => {});
    fetch("/api/scans")
      .then((r) => r.json())
      .then(setScans)
      .catch(() => {});
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    if (!autoRefresh) return;
    const iv = setInterval(load, 3000);
    return () => clearInterval(iv);
  }, [autoRefresh, load]);

  const scanMap = new Map(scans.map((s) => [s.filename, s.verdict]));
  const filtered = events.filter((e) => {
    const mt = filter === "all" || e.event_type === filter;
    const ms =
      !search || e.filename.toLowerCase().includes(search.toLowerCase());
    return mt && ms;
  });

  const counts: Record<string, number> = {
    all: events.length,
    created: 0,
    modified: 0,
    deleted: 0,
    moved: 0,
  };
  events.forEach((e) => {
    if (counts[e.event_type] !== undefined) counts[e.event_type]++;
  });

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4"
      >
        <div>
          <h1 className="text-3xl font-bold gradient-text">File Monitor</h1>
          <p className="text-slate-400 mt-1 flex items-center gap-2">
            <RiFolderOpenFill className="w-4 h-4" />
            Downloads folder &middot; Auto-scanning
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={
              "flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border " +
              (autoRefresh
                ? "bg-emerald-400/10 text-emerald-400 border-emerald-400/30"
                : "bg-slate-800 text-slate-400 border-slate-700")
            }
          >
            {autoRefresh ? (
              <RiEyeLine className="w-4 h-4" />
            ) : (
              <RiEyeOffLine className="w-4 h-4" />
            )}
            {autoRefresh ? "Live" : "Paused"}
          </button>
          <button
            onClick={load}
            className="p-2 rounded-lg bg-slate-800 text-slate-400 border border-slate-700 hover:text-white"
          >
            <RiRefreshLine className="w-4 h-4" />
          </button>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass rounded-2xl p-4 flex items-center gap-4 glow-border"
      >
        <div className="flex items-center gap-2">
          <div className="relative live-dot text-emerald-400">
            <RiRadioButtonFill className="w-5 h-5" />
          </div>
          <span className="text-emerald-400 font-medium text-sm">
            Scanning Downloads
          </span>
        </div>
        <div className="h-5 w-px bg-slate-700" />
        <span className="text-sm text-slate-400">{events.length} events</span>
        <div className="h-5 w-px bg-slate-700" />
        <span className="text-sm text-slate-400">{scans.length} scanned</span>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="flex flex-col sm:flex-row gap-3"
      >
        <div className="flex gap-2 flex-wrap">
          <RiFilter3Line className="w-4 h-4 text-slate-500 mt-2" />
          {["all", "created", "modified", "deleted", "moved"].map((t) => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={
                "px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors " +
                (filter === t
                  ? t === "all"
                    ? "bg-slate-700 text-white border-slate-600 filter-active"
                    : EVT[t].bg + " " + EVT[t].color + " filter-active"
                  : "bg-slate-900 text-slate-500 border-slate-800 hover:border-slate-700")
              }
            >
              {t === "all" ? "All" : EVT[t].label} ({counts[t]})
            </button>
          ))}
        </div>
        <div className="relative sm:ml-auto">
          <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search files..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full sm:w-64 bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400/50"
          />
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass rounded-2xl overflow-hidden glow-border"
      >
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs text-slate-500 uppercase tracking-wider bg-slate-800/50">
              <th className="px-5 py-3">File</th>
              <th className="px-5 py-3">Event</th>
              <th className="px-5 py-3">Scan</th>
              <th className="px-5 py-3">Size</th>
              <th className="px-5 py-3">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="px-5 py-12 text-center text-slate-500"
                >
                  <RiFolderOpenFill className="w-10 h-10 text-slate-700 mx-auto mb-3" />
                  Download a file to see it here
                </td>
              </tr>
            ) : (
              filtered.map((ev) => {
                const c = EVT[ev.event_type] || EVT.created;
                const Icon = c.icon;
                const verdict = scanMap.get(ev.filename) || "";
                return (
                  <tr
                    key={ev.id}
                    className="hover:bg-slate-800/30 transition-colors event-row-new"
                  >
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-3">
                        <Icon className={"w-4 h-4 " + c.color} />
                        <div>
                          <p className="text-sm text-white font-medium">
                            {ev.filename}
                          </p>
                          <p className="text-xs text-slate-600 truncate max-w-xs">
                            {ev.file_path}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={
                          "text-xs font-medium px-2.5 py-1 rounded-full border " +
                          c.bg +
                          " " +
                          c.color
                        }
                      >
                        {c.label}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <VerdictBadge verdict={verdict} />
                    </td>
                    <td className="px-5 py-3.5 text-sm text-slate-400">
                      {formatSize(ev.file_size)}
                    </td>
                    <td className="px-5 py-3.5 text-sm text-slate-400 whitespace-nowrap">
                      {timeAgo(ev.timestamp)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </motion.div>
    </div>
  );
}
