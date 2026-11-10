import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  RiFolderLockFill,
  RiFolderShield2Fill,
  RiAddLine,
  RiDeleteBinLine,
  RiCheckLine,
  RiHardDrive2Fill,
  RiShieldFlashFill,
} from "react-icons/ri";

interface SensitiveDir {
  id: number;
  path: string;
  label: string;
  alert_on_access: boolean;
  alert_on_copy: boolean;
  alert_on_move: boolean;
  alert_on_delete: boolean;
}

export default function Settings() {
  const [sensitiveDirs, setSensitiveDirs] = useState<SensitiveDir[]>([]);
  const [newPath, setNewPath] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [loading, setLoading] = useState(true);
  const [savedMsg, setSavedMsg] = useState(false);

  // Toggle state settings
  const [autoScan, setAutoScan] = useState(true);
  const [usbDetect, setUsbDetect] = useState(true);
  const [integrityCheck, setIntegrityCheck] = useState(true);

  const loadSensitiveDirs = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/sensitive-dirs");
      const data = await res.json();
      setSensitiveDirs(Array.isArray(data) ? data : []);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSensitiveDirs();
  }, []);

  const handleAddDir = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPath.trim()) return;

    try {
      await fetch("http://127.0.0.1:8000/api/sensitive-dirs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: newPath.trim(),
          label: newLabel.trim() || "Restricted Folder",
        }),
      });
      setNewPath("");
      setNewLabel("");
      loadSensitiveDirs();
    } catch {
      /* ignore */
    }
  };

  const handleDeleteDir = async (id: number) => {
    try {
      await fetch(`http://127.0.0.1:8000/api/sensitive-dirs/${id}`, {
        method: "DELETE",
      });
      setSensitiveDirs((prev) => prev.filter((d) => d.id !== id));
    } catch {
      /* ignore */
    }
  };

  const handleSavePreferences = () => {
    setSavedMsg(true);
    setTimeout(() => setSavedMsg(false), 2500);
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
      className="space-y-6 max-w-4xl"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold gradient-text">System Settings</h1>
          <p className="text-sm text-slate-500 mt-1">
            Configure monitoring directories, sensitive path protection, and alert rules
          </p>
        </div>
        {savedMsg && (
          <motion.div
            initial={{ opacity: 0, x: 10 }}
            animate={{ opacity: 1, x: 0 }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-400/10 text-emerald-400 text-xs font-semibold border border-emerald-400/20"
          >
            <RiCheckLine className="w-4 h-4" /> Saved!
          </motion.div>
        )}
      </div>

      {/* Monitored Directories */}
      <div className="settings-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <RiFolderShield2Fill className="w-6 h-6 text-cyan-400" />
          <div>
            <h2 className="text-sm font-bold text-white">
              Active Monitored Locations
            </h2>
            <p className="text-xs text-slate-500">
              System watches these locations in real-time for file events
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            { label: "Downloads Folder", icon: RiFolderShield2Fill, active: true },
            { label: "Documents Folder", icon: RiFolderShield2Fill, active: true },
            { label: "Desktop Folder", icon: RiFolderShield2Fill, active: false },
            { label: "External / USB Drives", icon: RiHardDrive2Fill, active: true },
          ].map((item) => (
            <div key={item.label} className="settings-item-row">
              <item.icon className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-xs text-slate-300 font-medium flex-1">
                {item.label}
              </span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded-md font-bold ${
                  item.active
                    ? "bg-emerald-400/10 text-emerald-400"
                    : "bg-slate-800 text-slate-500"
                }`}
              >
                {item.active ? "Active" : "Disabled"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Sensitive Directories Management */}
      <div className="settings-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <RiFolderLockFill className="w-6 h-6 text-amber-400" />
          <div>
            <h2 className="text-sm font-bold text-white">
              Restricted / Sensitive Folders
            </h2>
            <p className="text-xs text-slate-500">
              Triggers Critical Security Alerts if files in these folders are moved or deleted
            </p>
          </div>
        </div>

        {/* Add Folder Form */}
        <form onSubmit={handleAddDir} className="flex gap-2 mb-4 flex-wrap">
          <input
            type="text"
            placeholder="Folder Path (e.g. C:\Users\Public\Confidential)"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
            className="settings-input flex-1 min-w-60"
          />
          <input
            type="text"
            placeholder="Label (e.g. HR Records)"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
            className="settings-input w-48"
          />
          <button type="submit" className="settings-btn-primary">
            <RiAddLine className="w-4 h-4" /> Add Path
          </button>
        </form>

        {/* Sensitive Directories List */}
        <div className="space-y-2">
          {sensitiveDirs.length === 0 ? (
            <p className="text-xs text-slate-600 italic py-2">
              No restricted folders defined yet. Add a path above to protect sensitive files.
            </p>
          ) : (
            sensitiveDirs.map((dir) => (
              <div key={dir.id} className="settings-item-row">
                <RiFolderLockFill className="w-4 h-4 text-amber-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-white truncate">
                    {dir.path}
                  </p>
                  <p className="text-[10px] text-slate-500">{dir.label}</p>
                </div>
                <button
                  onClick={() => handleDeleteDir(dir.id)}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-400/10 transition-colors"
                  title="Remove Folder"
                >
                  <RiDeleteBinLine className="w-4 h-4" />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Defense Preferences */}
      <div className="settings-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <RiShieldFlashFill className="w-6 h-6 text-violet-400" />
          <div>
            <h2 className="text-sm font-bold text-white">Defense Engine Preferences</h2>
            <p className="text-xs text-slate-500">
              Configure active monitoring behavior and hashing rules
            </p>
          </div>
        </div>

        <div className="space-y-4">
          {[
            {
              title: "Automatic Real-time Threat Scanning",
              desc: "Automatically run threat rule engine on all created/modified files",
              state: autoScan,
              setState: setAutoScan,
            },
            {
              title: "BLAKE3 Integrity Hashing",
              desc: "Compare pre/post transfer hashes to detect file tampering",
              state: integrityCheck,
              setState: setIntegrityCheck,
            },
            {
              title: "USB & Cross-Drive Exfiltration Alerting",
              desc: "Raise critical alert when files are transferred across drive letters",
              state: usbDetect,
              setState: setUsbDetect,
            },
          ].map((item) => (
            <div
              key={item.title}
              className="flex items-center justify-between gap-4 p-3 rounded-xl bg-slate-900/40 border border-white/5"
            >
              <div>
                <p className="text-xs font-semibold text-slate-200">
                  {item.title}
                </p>
                <p className="text-[11px] text-slate-500 mt-0.5">{item.desc}</p>
              </div>
              <button
                type="button"
                onClick={() => {
                  item.setState(!item.state);
                  handleSavePreferences();
                }}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out ${
                  item.state ? "bg-cyan-500" : "bg-slate-800"
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                    item.state ? "translate-x-5" : "translate-x-0"
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}