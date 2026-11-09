import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiShieldCheckFill,
  RiShieldCrossFill,
  RiAddFill,
  RiDeleteBin6Fill,
  RiFileShieldFill,
  RiFolderShieldFill,
  RiHardDrive3Fill,
  RiScan2Fill,
  RiCheckboxCircleFill,
  RiErrorWarningFill,
  RiForbid2Fill,
} from "react-icons/ri";
import type { IconType } from "react-icons";

interface Policy {
  id: number;
  name: string;
  description: string;
  rule_type: string;
  rule_value: string;
  action: string;
  is_active: boolean;
  created_at: string;
}

const TYPE_CFG: Record<
  string,
  { icon: IconType; color: string; bg: string; label: string }
> = {
  extension_block: {
    icon: RiForbid2Fill,
    color: "text-rose-400",
    bg: "bg-rose-400/10",
    label: "Block Ext",
  },
  size_limit: {
    icon: RiHardDrive3Fill,
    color: "text-amber-400",
    bg: "bg-amber-400/10",
    label: "Size Limit",
  },
  double_extension: {
    icon: RiErrorWarningFill,
    color: "text-orange-400",
    bg: "bg-orange-400/10",
    label: "Double Ext",
  },
  deep_scan: {
    icon: RiScan2Fill,
    color: "text-cyan-400",
    bg: "bg-cyan-400/10",
    label: "Deep Scan",
  },
  whitelist: {
    icon: RiCheckboxCircleFill,
    color: "text-emerald-400",
    bg: "bg-emerald-400/10",
    label: "Whitelist",
  },
};

const ACTION_CFG: Record<string, { color: string; bg: string; label: string }> =
  {
    block: {
      color: "text-rose-400",
      bg: "bg-rose-400/10 border-rose-400/30",
      label: "Block",
    },
    alert: {
      color: "text-amber-400",
      bg: "bg-amber-400/10 border-amber-400/30",
      label: "Alert",
    },
    allow: {
      color: "text-emerald-400",
      bg: "bg-emerald-400/10 border-emerald-400/30",
      label: "Allow",
    },
  };

export default function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({
    name: "",
    description: "",
    rule_type: "extension_block",
    rule_value: "",
    action: "alert",
  });

  const load = useCallback(() => {
    fetch("/api/policies")
      .then((r) => r.json())
      .then(setPolicies)
      .catch(() => {});
  }, []);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    fetch("/api/policies/seed", { method: "POST" }).then(() => load());
  }, [load]);
  const toggle = (id: number) => {
    fetch("/api/policies/" + id + "/toggle", { method: "POST" }).then(() =>
      setPolicies(
        policies.map((p) =>
          p.id === id ? { ...p, is_active: !p.is_active } : p,
        ),
      ),
    );
  };

  const remove = (id: number) => {
    fetch("/api/policies/" + id, { method: "DELETE" }).then(() =>
      setPolicies(policies.filter((p) => p.id !== id)),
    );
  };

  const add = () => {
    if (!form.name || !form.rule_value) return;
    const params = new URLSearchParams(form);
    fetch("/api/policies?" + params, { method: "POST" }).then(() => {
      setShowAdd(false);
      setForm({
        name: "",
        description: "",
        rule_type: "extension_block",
        rule_value: "",
        action: "alert",
      });
      load();
    });
  };

  const active = policies.filter((p) => p.is_active).length;

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold gradient-text">
            Security Policies
          </h1>
          <p className="text-slate-400 mt-1">
            Custom rules for file scanning and threat detection
          </p>
        </div>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-linear-to-r from-cyan-400 to-violet-500 text-white font-medium text-sm shadow-lg shadow-cyan-400/20 hover:shadow-cyan-400/40 transition-shadow"
        >
          <RiAddFill className="w-5 h-5" /> New Policy
        </button>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {(
          [
            {
              label: "Total Policies",
              value: policies.length,
              icon: RiFileShieldFill,
              gradient: "from-cyan-400 to-blue-500",
            },
            {
              label: "Active Rules",
              value: active,
              icon: RiShieldCheckFill,
              gradient: "from-emerald-400 to-green-500",
            },
            {
              label: "Blocked Types",
              value: policies.filter((p) => p.action === "block" && p.is_active)
                .length,
              icon: RiShieldCrossFill,
              gradient: "from-rose-400 to-pink-500",
            },
          ] as {
            label: string;
            value: number;
            icon: IconType;
            gradient: string;
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
                  " shadow-lg"
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

      {/* Add Form */}
      <AnimatePresence>
        {showAdd && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="glass rounded-2xl p-6 glow-border overflow-hidden"
          >
            <h2 className="text-lg font-bold text-white mb-4">
              Create New Policy
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">
                  Name
                </label>
                <input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g. Block DLL files"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400/50"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">
                  Rule Type
                </label>
                <select
                  value={form.rule_type}
                  onChange={(e) =>
                    setForm({ ...form, rule_type: e.target.value })
                  }
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400/50"
                >
                  <option value="extension_block">Extension Block</option>
                  <option value="size_limit">Size Limit (bytes)</option>
                  <option value="double_extension">Double Extension</option>
                  <option value="deep_scan">Deep Scan</option>
                  <option value="whitelist">Whitelist</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">
                  Value
                </label>
                <input
                  value={form.rule_value}
                  onChange={(e) =>
                    setForm({ ...form, rule_value: e.target.value })
                  }
                  placeholder="e.g. .exe,.dll,.bat"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400/50"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">
                  Action
                </label>
                <select
                  value={form.action}
                  onChange={(e) => setForm({ ...form, action: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400/50"
                >
                  <option value="alert">Alert</option>
                  <option value="block">Block</option>
                  <option value="allow">Allow</option>
                </select>
              </div>
              <div className="sm:col-span-2">
                <label className="text-xs text-slate-400 mb-1 block">
                  Description
                </label>
                <input
                  value={form.description}
                  onChange={(e) =>
                    setForm({ ...form, description: e.target.value })
                  }
                  placeholder="Optional description"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400/50"
                />
              </div>
            </div>
            <div className="flex gap-3 mt-4">
              <button
                onClick={add}
                className="px-4 py-2 rounded-lg bg-emerald-400/10 text-emerald-400 border border-emerald-400/30 text-sm font-medium hover:bg-emerald-400/20 transition-colors"
              >
                Save Policy
              </button>
              <button
                onClick={() => setShowAdd(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-400 border border-slate-700 text-sm font-medium hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Policy List */}
      <div className="space-y-3">
        {policies.length === 0 ? (
          <div className="glass rounded-2xl p-12 text-center">
            <RiFolderShieldFill className="w-16 h-16 text-slate-700 mx-auto mb-3" />
            <p className="text-lg text-slate-400">No policies yet</p>
            <p className="text-sm text-slate-500 mt-1">
              Click "New Policy" or wait for defaults to load
            </p>
          </div>
        ) : (
          policies.map((p, i) => {
            const tc = TYPE_CFG[p.rule_type] || TYPE_CFG.extension_block;
            const ac = ACTION_CFG[p.action] || ACTION_CFG.alert;
            const TIcon = tc.icon;
            return (
              <motion.div
                key={p.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                whileHover={{ x: 4 }}
                className={
                  "glass rounded-2xl p-4 flex items-center gap-4 transition-all " +
                  (p.is_active ? "policy-card-active" : "policy-card-inactive")
                }
              >
                <div className={"p-2.5 rounded-xl " + tc.bg + " shrink-0"}>
                  <TIcon className={"w-5 h-5 " + tc.color} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-bold text-white">{p.name}</p>
                    <span
                      className={"policy-type-badge " + tc.bg + " " + tc.color}
                    >
                      {tc.label}
                    </span>
                    <span
                      className={
                        "text-[10px] font-bold px-2 py-0.5 rounded-full border " +
                        ac.bg +
                        " " +
                        ac.color
                      }
                    >
                      {ac.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{p.description}</p>
                  <p className="text-xs text-slate-600 mt-0.5 font-mono">
                    {p.rule_value}
                  </p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <button
                    onClick={() => toggle(p.id)}
                    className={
                      "policy-toggle " +
                      (p.is_active ? "policy-toggle-on" : "policy-toggle-off")
                    }
                  >
                    <div className="policy-toggle-knob" />
                  </button>
                  <button
                    onClick={() => remove(p.id)}
                    className="p-2 rounded-lg text-slate-600 hover:text-rose-400 hover:bg-rose-400/10 transition-colors"
                  >
                    <RiDeleteBin6Fill className="w-4 h-4" />
                  </button>
                </div>
              </motion.div>
            );
          })
        )}
      </div>
    </div>
  );
}
