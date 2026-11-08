import { Outlet, NavLink, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiDashboard3Fill,
  RiFolderShield2Fill,
  RiScan2Fill,
  RiAlarmWarningFill,
  RiShieldCheckFill,
  RiBarChartBoxFill,
  RiSettings4Fill,
  RiShieldFlashFill,
  RiMenuFoldLine,
  RiMenuUnfoldLine,
} from "react-icons/ri";
import { useState } from "react";

const navItems = [
  { to: "/", icon: RiDashboard3Fill, label: "Dashboard" },
  { to: "/monitor", icon: RiFolderShield2Fill, label: "File Monitor" },
  { to: "/scanner", icon: RiScan2Fill, label: "Scanner" },
  { to: "/alerts", icon: RiAlarmWarningFill, label: "Alerts" },
  {
    to: "/policies",
    icon: RiShieldCheckFill,
    label: "Policies",
    disabled: true,
  },
  { to: "/reports", icon: RiBarChartBoxFill, label: "Reports", disabled: true },
  { to: "/settings", icon: RiSettings4Fill, label: "Settings", disabled: true },
];

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <div className="flex h-screen bg-slate-950 text-slate-200 overflow-hidden relative">
      <div className="mesh-bg" />

      <motion.aside
        animate={{ width: collapsed ? 72 : 240 }}
        transition={{ duration: 0.3, ease: "easeInOut" }}
        className="glass border-r border-white/5 flex flex-col shrink-0 z-10 relative sidebar-transition"
      >
        <div className="p-4 border-b border-white/5">
          <div className="flex items-center gap-3">
            <motion.div
              whileHover={{ rotate: 180, scale: 1.1 }}
              transition={{ duration: 0.5 }}
              className="w-10 h-10 rounded-xl bg-linear-to-br from-cyan-400 to-violet-500 flex items-center justify-center shrink-0 shadow-lg shadow-cyan-400/20"
            >
              <RiShieldFlashFill className="w-5 h-5 text-white" />
            </motion.div>
            <AnimatePresence>
              {!collapsed && (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -10 }}
                >
                  <h1 className="text-sm font-bold gradient-text tracking-tight">
                    SFTMS
                  </h1>
                  <p className="text-[10px] text-slate-500">Security Monitor</p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
          {navItems.map((item, i) => {
            if (item.disabled) {
              return (
                <div
                  key={item.label}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-slate-600 cursor-not-allowed"
                >
                  <item.icon className="w-5 h-5 shrink-0" />
                  <AnimatePresence>
                    {!collapsed && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="text-sm whitespace-nowrap"
                      >
                        {item.label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                  {!collapsed && (
                    <span className="ml-auto text-[9px] bg-slate-800 text-slate-600 px-1.5 py-0.5 rounded-md">
                      Soon
                    </span>
                  )}
                </div>
              );
            }
            const isActive = location.pathname === item.to;
            return (
              <NavLink key={item.to} to={item.to} end={item.to === "/"}>
                <motion.div
                  initial={{ x: -20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: i * 0.05 }}
                  whileHover={{ x: 4 }}
                  className={
                    "flex items-center gap-3 px-3 py-2.5 rounded-xl transition-colors relative nav-item-hover " +
                    (isActive
                      ? "bg-linear-to-r from-cyan-400/10 to-violet-400/10 text-cyan-400 nav-active-glow"
                      : "text-slate-400 hover:text-white")
                  }
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeNav"
                      className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-linear-to-b from-cyan-400 to-violet-400 rounded-r-full"
                      transition={{
                        type: "spring",
                        stiffness: 300,
                        damping: 30,
                      }}
                    />
                  )}
                  <item.icon
                    className={
                      "w-5 h-5 shrink-0 " +
                      (isActive
                        ? "drop-shadow-[0_0_6px_rgba(6,182,212,0.5)]"
                        : "")
                    }
                  />
                  <AnimatePresence>
                    {!collapsed && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="text-sm font-medium whitespace-nowrap"
                      >
                        {item.label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </motion.div>
              </NavLink>
            );
          })}
        </nav>

        <div className="p-3 border-t border-white/5 space-y-2">
          <div className="flex items-center gap-2 text-xs text-slate-500 px-2">
            <div className="relative w-2.5 h-2.5 shrink-0">
              <span className="absolute inset-0 rounded-full bg-emerald-400" />
              <span className="absolute inset-0 rounded-full bg-emerald-400 animate-ping" />
            </div>
            {!collapsed && <span>System Online</span>}
          </div>
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="w-full flex items-center justify-center p-2 rounded-lg text-slate-500 hover:text-white hover:bg-white/5 transition-colors"
          >
            {collapsed ? (
              <RiMenuUnfoldLine className="w-4 h-4" />
            ) : (
              <RiMenuFoldLine className="w-4 h-4" />
            )}
          </button>
        </div>
      </motion.aside>

      <main className="flex-1 overflow-y-auto p-6 lg:p-8 z-10 relative">
        <AnimatePresence mode="wait">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            <Outlet />
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
