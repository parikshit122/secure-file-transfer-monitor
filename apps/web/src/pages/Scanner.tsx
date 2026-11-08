import { useState, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiUploadCloud2Fill,
  RiCheckDoubleFill,
  RiErrorWarningFill,
  RiCloseCircleFill,
  RiFileFill,
  RiTimeFill,
  RiShieldCheckFill,
  RiFingerprintFill,
  RiLoader4Fill,
} from "react-icons/ri";
import type { IconType } from "react-icons";

interface ScanResult {
  filename: string;
  file_size: number;
  file_hash: string;
  file_type: string;
  verdict: string;
  threat_score: number;
  findings: string[];
  scan_duration_ms: number;
}

function formatSize(b: number) {
  if (!b) return "0 B";
  const k = 1024,
    s = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(1)) + " " + s[i];
}

const vCfg: Record<
  string,
  {
    icon: IconType;
    color: string;
    bg: string;
    border: string;
    label: string;
    bar: string;
    glow: string;
  }
> = {
  clean: {
    icon: RiCheckDoubleFill,
    color: "text-emerald-400",
    bg: "from-emerald-400/10 to-emerald-500/5",
    border: "border-emerald-400/30",
    label: "CLEAN — Safe to share",
    bar: "bg-emerald-400",
    glow: "threat-bar-clean",
  },
  suspicious: {
    icon: RiErrorWarningFill,
    color: "text-amber-400",
    bg: "from-amber-400/10 to-amber-500/5",
    border: "border-amber-400/30",
    label: "SUSPICIOUS — Review first",
    bar: "bg-amber-400",
    glow: "threat-bar-suspicious",
  },
  dangerous: {
    icon: RiCloseCircleFill,
    color: "text-rose-400",
    bg: "from-rose-400/10 to-rose-500/5",
    border: "border-rose-400/30",
    label: "DANGEROUS — Do NOT share",
    bar: "bg-rose-400",
    glow: "threat-bar-dangerous",
  },
};

export default function Scanner() {
  const [dragging, setDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(async (file: File) => {
    setScanning(true);
    setResult(null);
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch("/api/scan", { method: "POST", body: form });
      const data = await res.json();
      if (data.error) setError(data.error);
      else setResult(data);
    } catch {
      setError("Scan failed. Is the backend running?");
    } finally {
      setScanning(false);
    }
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
    },
    [handleFile],
  );

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
      >
        <h1 className="text-3xl font-bold gradient-text">File Scanner</h1>
        <p className="text-slate-400 mt-1">
          Upload a file to scan for threats before sharing
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        whileHover={{ scale: 1.01 }}
        whileTap={{ scale: 0.99 }}
        className={
          "relative border-2 border-dashed rounded-2xl p-16 text-center cursor-pointer transition-all duration-300 overflow-hidden " +
          (dragging
            ? "upload-zone-drag"
            : "border-slate-700 glass hover:border-slate-500")
        }
      >
        {dragging && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="absolute inset-0 bg-linear-to-r from-cyan-400/5 via-violet-400/5 to-cyan-400/5"
          />
        )}
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            if (e.target.files?.[0]) handleFile(e.target.files[0]);
          }}
        />
        {scanning ? (
          <div className="flex flex-col items-center gap-4">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 1.5, ease: "linear" }}
              className="scan-spinner"
            >
              <RiLoader4Fill className="w-16 h-16 text-cyan-400" />
            </motion.div>
            <p className="text-xl text-white font-bold">Scanning file...</p>
            <p className="text-sm text-slate-400">Running 9 security checks</p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-4 relative">
            <motion.div
              animate={dragging ? { scale: 1.2, y: -8 } : { scale: 1, y: 0 }}
              className={
                "p-5 rounded-2xl transition-colors " +
                (dragging ? "bg-cyan-400/10" : "bg-slate-800/80")
              }
            >
              <RiUploadCloud2Fill
                className={
                  "w-14 h-14 transition-colors " +
                  (dragging ? "text-cyan-400" : "text-slate-500")
                }
              />
            </motion.div>
            <div>
              <p className="text-xl text-white font-bold">
                {dragging ? "Drop it here!" : "Drag & drop a file"}
              </p>
              <p className="text-sm text-slate-500 mt-1">
                or click to browse &middot; Any file type &middot; Max 100MB
              </p>
            </div>
          </div>
        )}
      </motion.div>

      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="bg-rose-400/10 border border-rose-400/30 rounded-xl p-4 flex items-center gap-3"
          >
            <RiCloseCircleFill className="w-5 h-5 text-rose-400" />
            <p className="text-rose-400 text-sm">{error}</p>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {result &&
          (() => {
            const v = vCfg[result.verdict] || vCfg.clean;
            const VIcon = v.icon;
            return (
              <motion.div
                initial={{ opacity: 0, y: 30, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ type: "spring", stiffness: 200, damping: 20 }}
                className={
                  "glass rounded-2xl border p-6 bg-linear-to-br " +
                  v.bg +
                  " " +
                  v.border +
                  " scan-result-enter"
                }
              >
                <div className="flex items-center gap-4 mb-6">
                  <motion.div
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    transition={{ type: "spring", delay: 0.2 }}
                    className="p-4 rounded-2xl bg-slate-900/50"
                  >
                    <VIcon className={"w-10 h-10 " + v.color} />
                  </motion.div>
                  <div>
                    <p className={"text-2xl font-bold " + v.color}>{v.label}</p>
                    <p className="text-sm text-slate-400 mt-0.5">
                      {result.filename}
                    </p>
                  </div>
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ delay: 0.3, type: "spring" }}
                    className="ml-auto text-right"
                  >
                    <p className="text-4xl font-bold text-white">
                      {result.threat_score}
                    </p>
                    <p className="text-xs text-slate-500">threat score</p>
                  </motion.div>
                </div>

                <div
                  className={
                    "mb-6 h-3 bg-slate-800 rounded-full overflow-hidden " +
                    v.glow
                  }
                >
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: Math.max(result.threat_score, 3) + "%" }}
                    transition={{ duration: 1, delay: 0.4, ease: "easeOut" }}
                    className={"h-full rounded-full " + v.bar}
                  />
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                  {(
                    [
                      {
                        icon: RiFileFill,
                        label: "Type",
                        val: result.file_type,
                      },
                      {
                        icon: RiUploadCloud2Fill,
                        label: "Size",
                        val: formatSize(result.file_size),
                      },
                      {
                        icon: RiTimeFill,
                        label: "Scan Time",
                        val: result.scan_duration_ms + "ms",
                      },
                      {
                        icon: RiShieldCheckFill,
                        label: "Checks",
                        val: "9 rules",
                      },
                    ] as { icon: IconType; label: string; val: string }[]
                  ).map((d, i) => (
                    <motion.div
                      key={d.label}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.5 + i * 0.1 }}
                      className="bg-slate-900/50 rounded-xl p-3"
                    >
                      <d.icon className="w-5 h-5 text-slate-500 mb-1" />
                      <p className="text-xs text-slate-500">{d.label}</p>
                      <p className="text-sm text-white font-medium">{d.val}</p>
                    </motion.div>
                  ))}
                </div>

                <div className="bg-slate-900/50 rounded-xl p-3 mb-4">
                  <div className="flex items-center gap-2 mb-1">
                    <RiFingerprintFill className="w-4 h-4 text-slate-500" />
                    <p className="text-xs text-slate-500">BLAKE3 Hash</p>
                  </div>
                  <p className="text-xs text-slate-300 font-mono break-all">
                    {result.file_hash}
                  </p>
                </div>

                <p className="text-sm font-medium text-slate-300 mb-2">
                  Findings
                </p>
                <div className="space-y-1.5">
                  {result.findings.map((f, i) => (
                    <motion.div
                      key={i}
                      initial={{ x: -10, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      transition={{ delay: 0.7 + i * 0.05 }}
                      className="flex items-center gap-2 text-sm"
                    >
                      <div className={"w-2 h-2 rounded-full " + v.bar} />
                      <span className="text-slate-400">{f}</span>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            );
          })()}
      </AnimatePresence>
    </div>
  );
}
