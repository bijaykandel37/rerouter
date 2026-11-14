import { useEffect, useState, type ReactNode } from "react";
import { get, post, setUnauthorizedHandler, type Status } from "./api";
import { LiveProvider, ToastProvider, useApi, useLive, useTopic } from "./hooks";
import { href, useRoute } from "./router";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Traffic from "./pages/Traffic";
import LiveFlows from "./pages/LiveFlows";
import DecryptedHttp from "./pages/DecryptedHttp";
import Devices from "./pages/Devices";
import Interfaces from "./pages/Interfaces";
import Network from "./pages/Network";
import Diagnostics from "./pages/Diagnostics";
import Alerts from "./pages/Alerts";
import System from "./pages/System";

const NAV: { path: string; label: string; icon: string; section?: string }[] = [
  { path: "/", label: "Dashboard", icon: "M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z", section: "Monitor" },
  { path: "/traffic", label: "Traffic explorer", icon: "M3 17l6-6 4 4 8-8M15 7h6v6" },
  { path: "/live", label: "Live flows", icon: "M2 12h4l3-8 4 16 3-8h6" },
  { path: "/http", label: "Decrypted HTTP", icon: "M4 6h16M4 6a0 0 0 000 0v12h16V6M9 10l-2 2 2 2M15 10l2 2-2 2" },
  { path: "/devices", label: "Devices", icon: "M4 5h16v10H4zM8 19h8M12 15v4" },
  { path: "/alerts", label: "Alerts", icon: "M12 3l9 16H3zM12 10v4M12 17h.01" },
  { path: "/interfaces", label: "Interfaces", icon: "M4 9h16v6H4zM8 12h.01M12 12h.01", section: "Configure" },
  { path: "/network", label: "Network & firewall", icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" },
  { path: "/diagnostics", label: "Diagnostics & logs", icon: "M10 4a6 6 0 104.5 10L20 20M10 7v3l2 2" },
  { path: "/system", label: "System", icon: "M12 15a3 3 0 100-6 3 3 0 000 6zM19 12l2-1-1-3-2 .5-1.5-1.5.5-2-3-1-1 2h-2L10 3 7 4l.5 2L6 7.5 4 7l-1 3 2 1v2l-2 1 1 3 2-.5L7.5 18 7 20l3 1 1-2h2l1 2 3-1-.5-2 1.5-1.5 2 .5 1-3-2-1z" },
];

function Icon({ d }: { d: string }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

function ThemeSwitch() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? "auto");
  const set = (t: string) => {
    setTheme(t);
    if (t === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
    try {
      localStorage.setItem("rerouter-theme", t);
    } catch {
      /* ignore */
    }
  };
  return (
    <select value={theme} onChange={(e) => set(e.target.value)} aria-label="Color theme" style={{ fontSize: 12 }}>
      <option value="auto">Theme: system</option>
      <option value="light">Theme: light</option>
      <option value="dark">Theme: dark</option>
    </select>
  );
}

function Shell({ user, onLogout }: { user: string; onLogout: () => void }) {
  const { path } = useRoute();
  const { connected } = useLive();
  const [open, setOpen] = useState(false);
  const status = useApi<Status>("/status", [], 30000);
  const [openAlerts, setOpenAlerts] = useState(0);
  useEffect(() => setOpenAlerts(status.data?.counts.open_alerts ?? 0), [status.data]);
  useTopic("alert", () => setOpenAlerts((n) => n + 1));
  useEffect(() => setOpen(false), [path]);

  const pages: Record<string, ReactNode> = {
    "/": <Dashboard status={status.data} />,
    "/traffic": <Traffic />,
    "/live": <LiveFlows />,
    "/http": <DecryptedHttp />,
    "/devices": <Devices />,
    "/alerts": <Alerts onChange={status.reload} />,
    "/interfaces": <Interfaces />,
    "/network": <Network caps={status.data?.capabilities ?? []} />,
    "/diagnostics": <Diagnostics />,
    "/system": <System status={status.data} reloadStatus={status.reload} />,
  };

  return (
    <div className="shell">
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Main">
        <div className="brand">
          <span className="brand-mark"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M3 15h5l3-8 3 12 2-5h5" /></svg></span>
          rerouter
        </div>
        {NAV.map((n) => (
          <div key={n.path}>
            {n.section && <div className="nav-section">{n.section}</div>}
            <a className={`nav-item ${path === n.path ? "active" : ""}`} href={href(n.path)} aria-current={path === n.path ? "page" : undefined}>
              <Icon d={n.icon} />
              {n.label}
              {n.path === "/alerts" && openAlerts > 0 && <span className="count">{openAlerts > 99 ? "99+" : openAlerts}</span>}
            </a>
          </div>
        ))}
        <div className="sidebar-foot">
          <div className="row"><span className={`live-dot ${connected ? "" : "off"}`} />{connected ? "Live" : "Reconnecting…"}</div>
          {status.data && (
            <div className="row">
              <span className={`dot ${status.data.online ? "on" : "bad"}`} />
              {status.data.driver}{status.data.router_host ? ` · ${status.data.router_host}` : ""}
            </div>
          )}
          <ThemeSwitch />
          <div className="row">
            <span className="grow">{user}</span>
            <button className="small" onClick={onLogout}>Sign out</button>
          </div>
        </div>
      </nav>
      {open && <div className="drawer-backdrop" style={{ zIndex: 25 }} onClick={() => setOpen(false)} />}
      <div style={{ minWidth: 0 }}>
        <div className="mobile-bar">
          <button onClick={() => setOpen(true)} aria-label="Open menu">☰</button>
          <b>rerouter</b>
        </div>
        <main className="main">{pages[path] ?? <div className="empty">Page not found. <a href="#/">Go to dashboard</a></div>}</main>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    get<{ username: string }>("/auth/me").then((r) => setUser(r.username)).catch(() => setUser(null));
  }, []);

  if (user === undefined) return null;
  return (
    <ToastProvider>
      {user === null ? (
        <Login onLogin={setUser} />
      ) : (
        <LiveProvider>
          <Shell user={user} onLogout={async () => { await post("/auth/logout").catch(() => {}); setUser(null); }} />
        </LiveProvider>
      )}
    </ToastProvider>
  );
}
