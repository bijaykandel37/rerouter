import { Fragment, useState } from "react";
import { post, put, type AuditEntry, type CommandResult, type RuntimeSettings, type Status } from "../api";
import { Card, Empty, ErrorBox, Tabs, useConfirm } from "../components/ui";
import { ago, bytes, duration, num, pct, time } from "../format";
import { useAction, useApi } from "../hooks";

type Tab = "overview" | "collectors" | "settings" | "audit" | "account";

export default function System({ status, reloadStatus }: { status: Status | null; reloadStatus: () => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  return (
    <div>
      <div className="page-head"><h1>System</h1></div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "overview", label: "Router" }, { value: "collectors", label: "Data collection" },
        { value: "settings", label: "Settings" }, { value: "audit", label: "Audit log" }, { value: "account", label: "Account" },
      ]} />
      {tab === "overview" && <Overview status={status} />}
      {tab === "collectors" && <Collectors status={status} reload={reloadStatus} />}
      {tab === "settings" && <Settings />}
      {tab === "audit" && <Audit />}
      {tab === "account" && <Account />}
    </div>
  );
}

function Overview({ status }: { status: Status | null }) {
  const sys = useApi<Status["system"]>("/system", [], 15000);
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const s = sys.data;
  const caps = status?.capabilities ?? [];
  return (
    <div className="grid g2">
      {element}
      <Card title="Router">
        <ErrorBox error={sys.error} />
        {s && (
          <dl className="kv">
            <dt>Hostname</dt><dd>{s.hostname}</dd>
            <dt>Model</dt><dd>{s.model}</dd>
            <dt>Firmware</dt><dd>{s.firmware}</dd>
            <dt>Uptime</dt><dd>{duration(s.uptime_s)}</dd>
            <dt>CPU</dt><dd>{pct(s.cpu_percent)}</dd>
            <dt>Load</dt><dd>{s.load.join(" / ") || "–"}</dd>
            <dt>Memory</dt><dd>{s.mem_total ? `${bytes(s.mem_total - (s.mem_free ?? 0))} used of ${bytes(s.mem_total)}` : "–"}</dd>
            <dt>Temperature</dt><dd>{s.temperature_c != null ? `${s.temperature_c} °C` : "–"}</dd>
            <dt>Driver</dt><dd>{status?.driver}{status?.router_host ? ` → ${status.router_host}` : ""}</dd>
            <dt>Router addresses</dt><dd className="mono small">{status?.router_ips.join(", ") || "–"}</dd>
          </dl>
        )}
      </Card>
      <Card title="Maintenance">
        <div className="stack">
          {caps.includes("backup") && (
            <div>
              <a className="btn" href="/api/system/backup" download>Download configuration backup</a>
              <div className="muted small" style={{ marginTop: 4 }}>OpenWrt: sysupgrade archive · RouterOS: <code>/export</code> script</div>
            </div>
          )}
          {caps.includes("reboot") && (
            <div>
              <button className="danger" disabled={busy} onClick={async () => {
                if (await confirm("Reboot the router?", "All connections will drop for a minute or two while it restarts.", "Reboot now"))
                  run(() => post("/system/reboot"), "Reboot requested");
              }}>Reboot router</button>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

function Collectors({ status, reload }: { status: Status | null; reload: () => void }) {
  const { run, busy } = useAction();
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<CommandResult | null>(null);
  if (!status) return <Empty>Loading…</Empty>;
  const nf = status.collectors.netflow;
  const cap = status.collectors.capture;
  const sink = status.collectors.sink;
  return (
    <div className="stack">
      <div className="grid g3">
        <Card title="NetFlow / IPFIX collector">
          {nf ? (
            <dl className="kv">
              <dt>Listening</dt><dd>{nf.listening ? <span className="badge good">udp/{nf.port}</span> : <span className="badge bad">not listening</span>}</dd>
              {nf.error && <><dt>Error</dt><dd className="small">{nf.error}</dd></>}
              <dt>Exporters</dt><dd>{Object.keys(nf.exporters).length || "none yet"}</dd>
              {Object.entries(nf.exporters).map(([k, v]) => <Fragment key={k}><dt className="mono small">{k}</dt><dd className="small">{num(v.flows)} flows · {ago(v.last_seen)}</dd></Fragment>)}
              {Object.entries(nf.parser).map(([k, v]) => <Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd>{num(v)}</dd></Fragment>)}
            </dl>
          ) : <Empty>Disabled (REROUTER_NETFLOW_ENABLED=false)</Empty>}
        </Card>
        <Card title="Packet capture">
          {cap ? (
            <dl className="kv">
              <dt>Interface</dt><dd>{cap.interface}</dd>
              <dt>Status</dt><dd>{cap.running ? <span className="badge good">capturing</span> : <span className="badge bad">stopped</span>}</dd>
              <dt>Packets</dt><dd>{num(cap.packets)}</dd>
              <dt>Active flows</dt><dd>{num(cap.active_flows)}</dd>
              {cap.error && <><dt>Error</dt><dd className="small">{cap.error}</dd></>}
            </dl>
          ) : <div className="muted small">Not configured. Set <code>REROUTER_CAPTURE_INTERFACE</code> when rerouter runs on the router or on a mirror port — it also learns hostnames from DNS answers.</div>}
        </Card>
        <Card title="Flow pipeline">
          <dl className="kv">
            <dt>Received</dt><dd>{num(sink.received)}</dd>
            <dt>Stored</dt><dd>{num(sink.stored)}</dd>
            <dt>Dropped</dt><dd>{num(sink.dropped)}</dd>
            <dt>Last write</dt><dd>{ago(sink.last_flush)}</dd>
            {Object.entries(sink.by_source).map(([k, v]) => <Fragment key={k}><dt>from {k}</dt><dd>{num(v)}</dd></Fragment>)}
          </dl>
          <button className="small" style={{ marginTop: 10 }} onClick={reload}>Refresh</button>
        </Card>
      </div>
      {status.capabilities.includes("flow_export") && (
        <Card title="Configure flow export on the router" hint="sends NetFlow v9 for all traffic to this rerouter instance">
          <div className="row">
            <input placeholder="collector IP (auto-detect)" value={ip} onChange={(e) => setIp(e.target.value)} aria-label="Collector IP" style={{ width: 220 }} />
            <button className="primary" disabled={busy} onClick={() => run(async () => {
              const r = await post<CommandResult>("/system/flow-export", ip ? { collector_ip: ip } : {});
              setResult(r);
            })}>Configure exporter</button>
          </div>
          {result && <pre className="output" style={{ marginTop: 10 }}>{result.output}</pre>}
          <div className="muted small" style={{ marginTop: 8 }}>
            OpenWrt uses <code>softflowd</code> (install it first: <code>opkg install softflowd</code>); MikroTik uses the built-in Traffic Flow.
            Any other NetFlow v5/v9/IPFIX exporter can point at udp/{nf?.port ?? 2055} too.
          </div>
        </Card>
      )}
    </div>
  );
}

function listToText(a: (string | number)[]) { return a.join("\n"); }
function textToList(s: string) { return s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean); }

function Settings() {
  const data = useApi<{ runtime: RuntimeSettings; static: Record<string, unknown> }>("/settings");
  const [draft, setDraft] = useState<RuntimeSettings | null>(null);
  const { run, busy } = useAction();
  const s = draft ?? data.data?.runtime;
  if (!s) return <ErrorBox error={data.error} />;
  const set = (patch: Partial<RuntimeSettings>) => setDraft({ ...s, ...patch });
  const setA = (patch: Partial<RuntimeSettings["alerts"]>) => setDraft({ ...s, alerts: { ...s.alerts, ...patch } });
  const n = (v: string) => Number(v);
  return (
    <div className="stack">
      <div className="grid g2">
        <Card title="Traffic classification">
          <div className="stack">
            <label className="field">LAN networks (one CIDR per line) — traffic between these and anything else counts as internet traffic
              <textarea rows={5} className="mono" value={listToText(s.lan_networks)} onChange={(e) => set({ lan_networks: textToList(e.target.value) })} />
            </label>
            <label className="field">Extra router addresses (WAN IPs are detected automatically)
              <textarea rows={2} className="mono" value={listToText(s.router_ips)} onChange={(e) => set({ router_ips: textToList(e.target.value) })} />
            </label>
            <label className="row small"><input type="checkbox" checked={s.reverse_dns} onChange={(e) => set({ reverse_dns: e.target.checked })} />
              Reverse-DNS (PTR) lookups for remote hosts — sends queries for observed IPs to your resolver</label>
          </div>
        </Card>
        <Card title="Retention">
          <div className="form-grid">
            <label className="field">Keep flow records (days)<input type="number" min={1} value={s.flow_retention_days} onChange={(e) => set({ flow_retention_days: n(e.target.value) })} /></label>
            <label className="field">Keep interface samples (days)<input type="number" min={1} value={s.sample_retention_days} onChange={(e) => set({ sample_retention_days: n(e.target.value) })} /></label>
          </div>
          <h3 style={{ marginTop: 16 }}>Static configuration (file / environment)</h3>
          <pre className="output small">{JSON.stringify(data.data?.static, null, 2)}</pre>
        </Card>
      </div>
      <Card title="Alert thresholds">
        <div className="form-grid">
          <label className="field">Scan: distinct targets in 5 min<input type="number" min={5} value={s.alerts.scan_targets} onChange={(e) => setA({ scan_targets: n(e.target.value) })} /></label>
          <label className="field">Spike: σ above device baseline<input type="number" step="0.5" min={1} value={s.alerts.spike_sigma} onChange={(e) => setA({ spike_sigma: n(e.target.value) })} /></label>
          <label className="field">Spike: minimum MB per minute<input type="number" min={0} value={s.alerts.spike_min_bytes / 1e6} onChange={(e) => setA({ spike_min_bytes: n(e.target.value) * 1e6 })} /></label>
          <label className="field">Bulk upload: MB per 10 min (0 = off)<input type="number" min={0} value={s.alerts.upload_bytes_10m / 1e6} onChange={(e) => setA({ upload_bytes_10m: n(e.target.value) * 1e6 })} /></label>
          <label className="field">Interface errors per poll (0 = off)<input type="number" min={0} value={s.alerts.interface_errors} onChange={(e) => setA({ interface_errors: n(e.target.value) })} /></label>
          <label className="field">Risky remote ports<input value={s.alerts.risky_ports.join(", ")} onChange={(e) => setA({ risky_ports: textToList(e.target.value).map(Number).filter((x) => x > 0 && x < 65536) })} /></label>
          <label className="row small"><input type="checkbox" checked={s.alerts.new_device} onChange={(e) => setA({ new_device: e.target.checked })} />Alert on new devices</label>
        </div>
      </Card>
      <div className="row">
        <button className="primary" disabled={busy || !draft} onClick={() => run(async () => { await put("/settings", draft); setDraft(null); data.reload(); }, "Settings saved")}>Save settings</button>
        {draft && <button onClick={() => setDraft(null)}>Discard changes</button>}
      </div>
    </div>
  );
}

function Audit() {
  const log = useApi<AuditEntry[]>("/audit?limit=500", [], 30000);
  return (
    <Card title="Audit log" hint="every configuration change made through rerouter">
      <ErrorBox error={log.error} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Result</th><th>Details</th></tr></thead>
          <tbody>
            {log.data?.map((a) => (
              <tr key={a.id}>
                <td className="nowrap num small">{time(a.ts, true)}</td>
                <td>{a.username ?? "–"}</td>
                <td className="nowrap">{a.action.replace(/_/g, " ")}</td>
                <td>{a.ok ? <span className="badge good">ok</span> : <span className="badge bad">failed</span>}</td>
                <td className="mono small" style={{ maxWidth: 480, overflowWrap: "anywhere" }}>{Object.entries(a.details).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {log.data && !log.data.length && <Empty>No actions recorded yet.</Empty>}
      </div>
    </Card>
  );
}

function Account() {
  const [old, setOld] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const { run, busy } = useAction();
  const mismatch = pw2 !== "" && pw !== pw2;
  return (
    <Card title="Change password">
      <form className="stack" style={{ maxWidth: 360 }} onSubmit={(e) => {
        e.preventDefault();
        run(async () => { await post("/auth/password", { old, new: pw }); location.reload(); }, "Password changed — please sign in again");
      }}>
        <label className="field">Current password<input type="password" autoComplete="current-password" value={old} onChange={(e) => setOld(e.target.value)} required /></label>
        <label className="field">New password (min. 10 characters)<input type="password" autoComplete="new-password" minLength={10} value={pw} onChange={(e) => setPw(e.target.value)} required /></label>
        <label className="field">Repeat new password<input type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} required /></label>
        {mismatch && <div className="error-box">Passwords do not match.</div>}
        <div><button className="primary" disabled={busy || mismatch || pw.length < 10}>Change password</button></div>
      </form>
    </Card>
  );
}
