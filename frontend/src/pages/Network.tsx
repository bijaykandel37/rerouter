import { useState, type ReactNode } from "react";
import { del, patch, post, put, type FirewallRule, type Lease, type PortForward, type Route, type Wifi } from "../api";
import { Card, Empty, ErrorBox, Modal, Tabs, Toggle, useConfirm } from "../components/ui";
import { until } from "../format";
import { useAction, useApi } from "../hooks";

type Tab = "firewall" | "forwards" | "routes" | "dhcp" | "dns" | "wifi";

export default function Network({ caps }: { caps: string[] }) {
  const [tab, setTab] = useState<Tab>("firewall");
  const all: { value: Tab; label: string; cap: string }[] = [
    { value: "firewall", label: "Firewall rules", cap: "firewall" }, { value: "forwards", label: "Port forwarding", cap: "port_forwards" },
    { value: "routes", label: "Static routes", cap: "routes" }, { value: "dhcp", label: "DHCP leases", cap: "leases" },
    { value: "dns", label: "DNS", cap: "dns" }, { value: "wifi", label: "Wi-Fi", cap: "wifi" },
  ];
  const tabs = caps.length ? all.filter((t) => caps.includes(t.cap)) : all;
  return (
    <div>
      <div className="page-head"><h1>Network & firewall</h1><span className="sub">changes are applied to the router immediately and recorded in the audit log</span></div>
      <Tabs value={tab} tabs={tabs} onChange={setTab} />
      {tab === "firewall" && <Firewall />}
      {tab === "forwards" && <Forwards />}
      {tab === "routes" && <Routes />}
      {tab === "dhcp" && <Dhcp />}
      {tab === "dns" && <Dns />}
      {tab === "wifi" && <WifiTab />}
    </div>
  );
}

function Field({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return <label className="field" style={wide ? { gridColumn: "1 / -1" } : undefined}>{label}{children}</label>;
}

function useForm<T extends Record<string, unknown>>(initial: T) {
  const [v, setV] = useState(initial);
  const bind = (k: keyof T) => ({
    value: String(v[k] ?? ""),
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setV({ ...v, [k]: e.target.value }),
  });
  return { v, setV, bind, reset: () => setV(initial) };
}

/** Strip empty strings so optional fields are sent as null/absent. */
function clean<T extends Record<string, unknown>>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, x]) => x !== "")) as Partial<T>;
}

function Firewall() {
  const rules = useApi<FirewallRule[]>("/firewall/rules");
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const [adding, setAdding] = useState(false);
  const f = useForm({ name: "", chain: "forward", action: "drop", proto: "any", src: "", src_port: "", dst: "", dst_port: "", src_mac: "" });

  const add = () => run(async () => {
    await post("/firewall/rules", clean(f.v));
    setAdding(false);
    f.reset();
    rules.reload();
  }, "Rule added");

  return (
    <Card title="Firewall rules" hint="rules created by rerouter (e.g. device blocks) are marked managed"
      actions={<button className="primary" onClick={() => setAdding(true)}>Add rule</button>}>
      {element}
      <ErrorBox error={rules.error} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>On</th><th>Name</th><th>Chain</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th /></tr></thead>
          <tbody>
            {rules.data?.map((r) => (
              <tr key={r.id}>
                <td><Toggle on={r.enabled} disabled={busy} label={`Enable ${r.name}`} onChange={(enabled) => run(async () => { await patch(`/firewall/rules/${encodeURIComponent(r.id)}`, { enabled }); rules.reload(); })} /></td>
                <td>{r.name} {r.managed && <span className="badge">managed</span>}</td>
                <td>{r.chain}</td>
                <td><span className={`badge ${r.action === "accept" ? "good" : "bad"}`}>{r.action}</span></td>
                <td>{r.proto}</td>
                <td className="mono small">{[r.src, r.src_port && `port ${r.src_port}`, r.src_mac].filter(Boolean).join(" · ") || "any"}</td>
                <td className="mono small">{[r.dst, r.dst_port && `port ${r.dst_port}`].filter(Boolean).join(" · ") || "any"}</td>
                <td className="right"><button className="small danger" disabled={busy} onClick={async () => {
                  if (await confirm(`Delete rule “${r.name}”?`, "The firewall will be reloaded.", "Delete")) run(async () => { await del(`/firewall/rules/${encodeURIComponent(r.id)}`); rules.reload(); }, "Rule deleted");
                }}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rules.data && !rules.data.length && <Empty>No rules.</Empty>}
      </div>
      {adding && (
        <Modal title="Add firewall rule" onClose={() => setAdding(false)}>
          <div className="form-grid">
            <Field label="Name" wide><input {...f.bind("name")} required placeholder="Block-telnet-out" /></Field>
            <Field label="Chain"><select {...f.bind("chain")}><option value="forward">forward (through router)</option><option value="input">input (to router)</option><option value="output">output (from router)</option></select></Field>
            <Field label="Action"><select {...f.bind("action")}><option value="drop">drop</option><option value="reject">reject</option><option value="accept">accept</option></select></Field>
            <Field label="Protocol"><select {...f.bind("proto")}><option value="any">any</option><option value="tcp">tcp</option><option value="udp">udp</option><option value="tcp+udp">tcp+udp</option><option value="icmp">icmp</option></select></Field>
            <Field label="Source CIDR"><input {...f.bind("src")} placeholder="192.168.1.0/24" /></Field>
            <Field label="Source port"><input {...f.bind("src_port")} placeholder="1024-65535" /></Field>
            <Field label="Source MAC"><input {...f.bind("src_mac")} placeholder="aa:bb:cc:dd:ee:ff" /></Field>
            <Field label="Destination CIDR"><input {...f.bind("dst")} placeholder="0.0.0.0/0" /></Field>
            <Field label="Destination port"><input {...f.bind("dst_port")} placeholder="23" /></Field>
          </div>
          <div className="row" style={{ justifyContent: "flex-end", marginTop: 16 }}>
            <button onClick={() => setAdding(false)}>Cancel</button>
            <button className="primary" disabled={busy || !f.v.name} onClick={add}>Add rule</button>
          </div>
        </Modal>
      )}
    </Card>
  );
}

function Forwards() {
  const list = useApi<PortForward[]>("/firewall/forwards");
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const f = useForm({ name: "", proto: "tcp", ext_port: "", int_ip: "", int_port: "", src: "" });
  const add = () => run(async () => {
    await post("/firewall/forwards", clean({ ...f.v, int_port: f.v.int_port || f.v.ext_port }));
    f.reset();
    list.reload();
  }, "Port forward added");
  return (
    <div className="stack">
      {element}
      <Card title="Port forwards" hint="inbound connections from the internet to a LAN host — each one is exposed attack surface">
        <ErrorBox error={list.error} />
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Protocol</th><th>External port</th><th>Internal host</th><th>Allowed sources</th><th>Status</th><th /></tr></thead>
            <tbody>
              {list.data?.map((p) => (
                <tr key={p.id}>
                  <td>{p.name}</td><td>{p.proto}</td><td className="mono">{p.ext_port}</td>
                  <td className="mono">{p.int_ip}:{p.int_port}</td><td className="mono small">{p.src ?? "anyone"}</td>
                  <td>{p.enabled ? <span className="badge good">active</span> : <span className="badge">disabled</span>}</td>
                  <td className="right"><button className="small danger" disabled={busy} onClick={async () => {
                    if (await confirm(`Remove forward “${p.name}”?`, `Port ${p.ext_port} will no longer reach ${p.int_ip}.`, "Remove")) run(async () => { await del(`/firewall/forwards/${encodeURIComponent(p.id)}`); list.reload(); }, "Removed");
                  }}>Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {list.data && !list.data.length && <Empty>No port forwards — nothing on your LAN is reachable from the internet.</Empty>}
        </div>
      </Card>
      <Card title="Add port forward">
        <div className="form-grid">
          <Field label="Name"><input {...f.bind("name")} placeholder="game-server" /></Field>
          <Field label="Protocol"><select {...f.bind("proto")}><option value="tcp">tcp</option><option value="udp">udp</option><option value="tcp+udp">tcp+udp</option></select></Field>
          <Field label="External port"><input {...f.bind("ext_port")} placeholder="8443 or 8000-8010" /></Field>
          <Field label="Internal IP"><input {...f.bind("int_ip")} placeholder="192.168.1.10" /></Field>
          <Field label="Internal port"><input {...f.bind("int_port")} placeholder="same as external" /></Field>
          <Field label="Restrict source (optional)"><input {...f.bind("src")} placeholder="198.51.100.0/24" /></Field>
          <button className="primary" disabled={busy || !f.v.name || !f.v.ext_port || !f.v.int_ip} onClick={add}>Add forward</button>
        </div>
      </Card>
    </div>
  );
}

function Routes() {
  const list = useApi<Route[]>("/routes");
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const f = useForm({ dst: "", gateway: "", iface: "", metric: "", comment: "" });
  const add = () => run(async () => {
    const body: Record<string, unknown> = clean(f.v);
    if (body.metric) body.metric = Number(body.metric);
    await post("/routes", body);
    f.reset();
    list.reload();
  }, "Route added");
  return (
    <div className="stack">
      {element}
      <Card title="Routing table">
        <ErrorBox error={list.error} />
        <div className="table-wrap">
          <table>
            <thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th className="num">Metric</th><th>Type</th><th>Comment</th><th /></tr></thead>
            <tbody>
              {list.data?.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.dst}</td><td className="mono">{r.gateway ?? "direct"}</td><td>{r.iface ?? "–"}</td>
                  <td className="num">{r.metric ?? "–"}</td>
                  <td>{r.static ? <span className="badge">static</span> : <span className="muted">kernel</span>}{!r.active && <span className="badge bad">inactive</span>}</td>
                  <td>{r.comment ?? ""}</td>
                  <td className="right">{r.static && <button className="small danger" disabled={busy} onClick={async () => {
                    if (await confirm(`Delete route to ${r.dst}?`, "Traffic for this network will follow the default route.", "Delete")) run(async () => { await del(`/routes/${encodeURIComponent(r.id)}`); list.reload(); }, "Route deleted");
                  }}>Delete</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Add static route">
        <div className="form-grid">
          <Field label="Destination CIDR"><input {...f.bind("dst")} placeholder="10.20.0.0/16" /></Field>
          <Field label="Gateway"><input {...f.bind("gateway")} placeholder="192.168.1.70" /></Field>
          <Field label="Interface"><input {...f.bind("iface")} placeholder="lan" /></Field>
          <Field label="Metric"><input {...f.bind("metric")} type="number" min={0} /></Field>
          <Field label="Comment"><input {...f.bind("comment")} /></Field>
          <button className="primary" disabled={busy || !f.v.dst || (!f.v.gateway && !f.v.iface)} onClick={add}>Add route</button>
        </div>
      </Card>
    </div>
  );
}

function Dhcp() {
  const leases = useApi<Lease[]>("/dhcp/leases", [], 30000);
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const f = useForm({ mac: "", ip: "", hostname: "" });
  const add = () => run(async () => { await post("/dhcp/static", clean(f.v)); f.reset(); leases.reload(); }, "Static lease added");
  const reserve = (l: Lease) => f.setV({ mac: l.mac, ip: l.ip, hostname: l.hostname ?? "" });
  return (
    <div className="stack">
      {element}
      <Card title="DHCP leases" hint="dynamic and static (reserved) addresses">
        <ErrorBox error={leases.error} />
        <div className="table-wrap">
          <table>
            <thead><tr><th>Hostname</th><th>IP</th><th>MAC</th><th>Type</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {leases.data?.map((l) => (
                <tr key={`${l.mac}-${l.ip}`}>
                  <td>{l.hostname ?? <span className="muted">unknown</span>}</td><td className="mono">{l.ip}</td><td className="mono small">{l.mac}</td>
                  <td>{l.static ? <span className="badge">static</span> : "dynamic"}</td>
                  <td className="small">{l.static ? "never" : until(l.expires)}</td>
                  <td className="right">
                    {l.static && l.id ? <button className="small danger" disabled={busy} onClick={async () => {
                      if (await confirm(`Remove reservation for ${l.hostname ?? l.mac}?`, "The device will get a dynamic address on its next renewal.", "Remove")) run(async () => { await del(`/dhcp/static/${encodeURIComponent(l.id!)}`); leases.reload(); }, "Reservation removed");
                    }}>Remove</button> : <button className="small" onClick={() => reserve(l)}>Reserve</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Add static lease (address reservation)">
        <div className="form-grid">
          <Field label="MAC"><input {...f.bind("mac")} placeholder="aa:bb:cc:dd:ee:ff" /></Field>
          <Field label="IP"><input {...f.bind("ip")} placeholder="192.168.1.50" /></Field>
          <Field label="Hostname"><input {...f.bind("hostname")} placeholder="optional" /></Field>
          <button className="primary" disabled={busy || !f.v.mac || !f.v.ip} onClick={add}>Reserve</button>
        </div>
      </Card>
    </div>
  );
}

function Dns() {
  const dns = useApi<{ servers: string[]; local_domain: string | null }>("/dns");
  const { run, busy } = useAction();
  const [text, setText] = useState<string | null>(null);
  const value = text ?? dns.data?.servers.join("\n") ?? "";
  const presets: Record<string, string[]> = {
    Cloudflare: ["1.1.1.1", "1.0.0.1"], Quad9: ["9.9.9.9", "149.112.112.112"], Google: ["8.8.8.8", "8.8.4.4"], "ISP (automatic)": [],
  };
  return (
    <Card title="Upstream DNS servers" hint={dns.data?.local_domain ? `local domain: ${dns.data.local_domain}` : ""}>
      <ErrorBox error={dns.error} />
      <div className="stack" style={{ maxWidth: 420 }}>
        <label className="field">One IP address per line (empty = use the ISP's servers)
          <textarea rows={4} className="mono" value={value} onChange={(e) => setText(e.target.value)} />
        </label>
        <div className="row">{Object.entries(presets).map(([k, v]) => <button key={k} className="small" onClick={() => setText(v.join("\n"))}>{k}</button>)}</div>
        <div><button className="primary" disabled={busy || text === null} onClick={() => run(async () => {
          await put("/dns", { servers: value.split(/\s+/).filter(Boolean) });
          setText(null);
          dns.reload();
        }, "DNS servers updated")}>Apply</button></div>
      </div>
    </Card>
  );
}

function WifiTab() {
  const nets = useApi<Wifi[]>("/wifi");
  const [editing, setEditing] = useState<Wifi | null>(null);
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const [form, setForm] = useState({ ssid: "", key: "", channel: "", hidden: false });
  const open = (w: Wifi) => { setEditing(w); setForm({ ssid: w.ssid, key: "", channel: w.channel ?? "", hidden: w.hidden }); };
  const save = () => run(async () => {
    const body: Record<string, unknown> = { ssid: form.ssid, hidden: form.hidden };
    if (form.key) body.key = form.key;
    if (form.channel && form.channel !== editing!.channel) body.channel = form.channel;
    await patch(`/wifi/${encodeURIComponent(editing!.id)}`, body);
    setEditing(null);
    nets.reload();
  }, "Wi-Fi updated — clients may reconnect");
  return (
    <Card title="Wireless networks">
      {element}
      <ErrorBox error={nets.error} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>On</th><th>SSID</th><th>Band</th><th>Channel</th><th>Security</th><th className="num">Clients</th><th /></tr></thead>
          <tbody>
            {nets.data?.map((w) => (
              <tr key={w.id}>
                <td><Toggle on={w.enabled} disabled={busy} label={`Enable ${w.ssid}`} onChange={async (enabled) => {
                  if (!enabled && !(await confirm(`Turn off ${w.ssid}?`, "Clients on this network will be disconnected — possibly including you.", "Turn off"))) return;
                  run(async () => { await patch(`/wifi/${encodeURIComponent(w.id)}`, { enabled }); nets.reload(); });
                }} /></td>
                <td>{w.ssid}{w.hidden && <span className="badge" style={{ marginLeft: 6 }}>hidden</span>}</td>
                <td>{w.band ?? "–"}</td><td>{w.channel ?? "auto"}</td><td>{w.encryption ?? "–"}</td>
                <td className="num">{w.clients ?? "–"}</td>
                <td className="right"><button className="small" onClick={() => open(w)}>Edit</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {nets.data && !nets.data.length && <Empty>No wireless interfaces found.</Empty>}
      </div>
      {editing && (
        <Modal title={`Edit ${editing.ssid}`} onClose={() => setEditing(null)}>
          <div className="form-grid">
            <Field label="SSID" wide><input value={form.ssid} maxLength={32} onChange={(e) => setForm({ ...form, ssid: e.target.value })} /></Field>
            <Field label="New password (leave empty to keep)" wide><input type="password" autoComplete="new-password" value={form.key} minLength={8} maxLength={63} onChange={(e) => setForm({ ...form, key: e.target.value })} /></Field>
            <Field label="Channel"><input value={form.channel} placeholder="auto" onChange={(e) => setForm({ ...form, channel: e.target.value })} /></Field>
            <label className="row small"><input type="checkbox" checked={form.hidden} onChange={(e) => setForm({ ...form, hidden: e.target.checked })} />Hide SSID</label>
          </div>
          {form.key && form.key.length < 8 && <div className="error-box" style={{ marginTop: 10 }}>Password must be at least 8 characters.</div>}
          <div className="row" style={{ justifyContent: "flex-end", marginTop: 16 }}>
            <button onClick={() => setEditing(null)}>Cancel</button>
            <button className="primary" disabled={busy || !form.ssid || (!!form.key && form.key.length < 8)} onClick={save}>Save & reload Wi-Fi</button>
          </div>
        </Modal>
      )}
    </Card>
  );
}
