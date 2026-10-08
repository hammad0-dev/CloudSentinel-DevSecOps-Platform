import { useEffect, useRef, useState } from "react";
import { Bell, Search, Settings, X } from "lucide-react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const titles = {
  "/dashboard": "Security Overview",
  "/projects": "Projects",
  "/cicd": "CI/CD",
  "/dependencies": "Dependencies",
  "/iac": "IaC Security",
  "/cloud": "Cloud",
  "/kubernetes": "Kubernetes",
  "/compliance": "Compliance",
  "/monitoring": "Monitoring",
  "/secrets": "Secrets",
  "/settings": "Settings",
};

export default function Navbar() {
  const { pathname } = useLocation();
  const { logout } = useAuth();
  const rootPath = `/${pathname.split("/").filter(Boolean)[0] || "dashboard"}`;
  const crumb = titles[rootPath] || "CloudSentinel";
  const leaf = pathname.includes("/sast")
    ? "SAST Results"
    : pathname.includes("/dast")
      ? "DAST Results"
      : pathname.includes("/iac")
        ? "IaC Results"
        : pathname.match(/^\/projects\/\w+/)
          ? "Project Details"
          : null;

  const links = [
    ["/dashboard", "Dashboard"],
    ["/projects", "Projects"],
    ["/cicd", "CI/CD"],
    ["/dependencies", "Dependencies"],
    ["/iac", "IaC"],
    ["/cloud", "Cloud"],
    ["/kubernetes", "Kubernetes"],
    ["/compliance", "Compliance"],
    ["/monitoring", "Monitoring"],
    ["/secrets", "Secrets"],
  ];

  const [searchOpen, setSearchOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [notifOpen, setNotifOpen] = useState(false);
  const searchInputRef = useRef(null);
  const notifRef = useRef(null);

  const notifications = [
    { id: 1, text: "3 critical alerts in auth.js", time: "2m ago" },
    { id: 2, text: "Dependency scan completed", time: "7m ago" },
    { id: 3, text: "New compliance report ready", time: "14m ago" },
  ];

  useEffect(() => {
    if (searchOpen) searchInputRef.current?.focus();
  }, [searchOpen]);

  useEffect(() => {
    const onClickOutside = (event) => {
      if (!notifRef.current) return;
      if (!notifRef.current.contains(event.target)) setNotifOpen(false);
    };
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  return (
    <header className="sticky top-0 z-30 bg-[var(--bg-secondary)] border-b border-[var(--border-subtle)]">
      <div className="h-12 px-6 flex items-center justify-between">
        <div className="text-sm font-semibold text-[var(--text-primary)]">CloudSentinel</div>
        <div className="text-sm hidden md:block">
          <span className="text-[var(--text-secondary)]">{crumb}</span>
          {leaf ? <span className="text-[var(--text-tertiary)]"> / </span> : null}
          {leaf ? <span className="text-[var(--text-primary)]">{leaf}</span> : null}
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setSearchOpen((v) => !v)}
            className="p-2 rounded-md hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            title="Search"
          >
            <Search size={16} />
          </button>
          <div className="relative" ref={notifRef}>
            <button
              onClick={() => setNotifOpen((v) => !v)}
              className="relative p-2 rounded-md hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              title="Notifications"
            >
              <Bell size={16} />
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 text-[10px] rounded-full bg-[var(--accent-red)] text-white grid place-items-center">3</span>
            </button>
            {notifOpen ? (
              <div className="absolute right-0 mt-2 w-72 card p-2 z-40 shadow-xl">
                <p className="px-2 py-1 text-xs uppercase tracking-wide text-[var(--text-secondary)]">
                  Notifications
                </p>
                <div className="max-h-64 overflow-auto">
                  {notifications.map((n) => (
                    <div
                      key={n.id}
                      className="px-2 py-2 rounded-md hover:bg-[var(--bg-hover)] border-b border-[var(--border-subtle)] last:border-b-0"
                    >
                      <p className="text-sm text-[var(--text-primary)]">{n.text}</p>
                      <p className="text-xs text-[var(--text-secondary)] mt-0.5">{n.time}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
          <Link to="/settings" className="p-2 rounded-md hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
            <Settings size={16} />
          </Link>
          <button onClick={logout} className="secondary-btn py-1.5 text-xs">
            Logout
          </button>
        </div>
      </div>
      {searchOpen ? (
        <div className="px-6 pb-2">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
            <input
              ref={searchInputRef}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search projects, reports, alerts..."
              className="input input-with-icon-both w-full"
            />
            <button
              onClick={() => {
                setSearchTerm("");
                setSearchOpen(false);
              }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              title="Close search"
            >
              <X size={14} />
            </button>
          </div>
        </div>
      ) : null}
      <div className="px-6 pb-2 overflow-x-auto">
        <div className="flex items-center gap-1 min-w-max">
          {links.map(([to, label]) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `px-3 py-1.5 rounded-md text-sm border transition-all ${
                  isActive
                    ? "border-[var(--accent-green)] text-[var(--accent-green)] bg-[rgba(47,111,79,0.10)]"
                    : "border-transparent text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </div>
      </div>
    </header>
  );
}
