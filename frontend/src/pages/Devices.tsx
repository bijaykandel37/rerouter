import { useMemo, useState } from "react";
import { patch, post, del, type Device, type Summary, type TimeSeries, type TopRow } from "../api";
import { DIRECTION_LABEL } from "../colors";
import { TimeChart } from "../components/charts";
import { Card, DirBar, DirLegend, Empty, ErrorBox, Seg, Sortable, Tile, sortRows, useConfirm } from "../components/ui";
import { ago, bytes, num, time } from "../format";
import { useAction, useApi } from "../hooks";
import { href, navigate, useRoute } from "../router";
import { TopTable } from "./Dashboard";

export default function Devices() {
  const { params } = useRoute();
  const [range, setRange] = useState<"1h" | "24h" | "7d">("24h");
  const [q, setQ] = useState("");
  const [onlyOnline, setOnlyOnline] = useState(false);
  const [sort, setSort] = useState({ k: "download", desc: true });
  const list = useApi<Device[]>(`/devices?range=${range}`, [], 30000);
  const selected = params.get("mac");

  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    const filtered = (list.data ?? []).filter((d) => (!onlyOnline || d.online) &&
      (!s || [d.name, d.ip ?? "", d.mac, d.vendor ?? ""].some((x) => x.toLowerCase().includes(s))));
    return sortRows(filtered.map((d) => ({ ...d, total: d.download + d.upload })), sort);
  }, [list.data, q, onlyOnline, sort]);
  const max = Math.max(1, ...rows.map((r) => r.download + r.upload));

  return (
    <div>
      <div className="page-head">
        <h1>Devices</h1>
        <span className="sub">{list.data ? `${list.data.filter((d) => d.online).length} online · ${list.data.length} known` : ""}</span>
      </div>
      <Card actions={<div className="row">
        <input placeholder="Search name, IP, MAC, vendor" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search devices" />
        <label className="row small"><input type="checkbox" checked={onlyOnline} onChange={(e) => setOnlyOnline(e.target.checked)} />Online only</label>
        <Seg label="Traffic period" value={range} onChange={setRange} options={[{ value: "1h", label: "1h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }]} />
        <DirLegend />
      </div>}>
        <ErrorBox error={list.error} />
        <div className="table-wrap">
          <table>
            <thead><tr>
              <Sortable label="Device" k="name" sort={sort} setSort={setSort} />
              <Sortable label="IP" k="ip" sort={sort} setSort={setSort} />
              <th>MAC / vendor</th>
              <th style={{ width: "18%" }}>Internet traffic ({range})</th>
              <Sortable label="↓ Down" k="download" sort={sort} setSort={setSort} className="num" />
              <Sortable label="↑ Up" k="upload" sort={sort} setSort={setSort} className="num" />
              <Sortable label="Peers" k="peers" sort={sort} setSort={setSort} className="num" />
              <Sortable label="Last seen" k="last_seen" sort={sort} setSort={setSort} />
            </tr></thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.mac} className="clickable" onClick={() => navigate("/devices", { mac: d.mac })}>
                  <td className="nowrap">
                    <span className="row" style={{ flexWrap: "nowrap" }}>
                      <span className={`dot ${d.blocked ? "bad" : d.online ? "on" : "off"}`} aria-hidden="true" />
                      <span>{d.name}</span>
                      {d.blocked ? <span className="badge bad">blocked</span> : null}
                    </span>
                  </td>
                  <td className="mono small">{d.ip ?? "–"}</td>
                  <td><span className="mono small">{d.mac}</span><div className="muted small">{d.vendor ?? "unknown vendor"}</div></td>
                  <td><DirBar down={d.download} up={d.upload} max={max} /></td>
                  <td className="num">{bytes(d.download)}</td>
                  <td className="num">{bytes(d.upload)}</td>
                  <td className="num">{num(d.peers)}</td>
                  <td className="nowrap">{d.online ? <span className="badge good">online</span> : ago(d.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {list.data && !rows.length && <Empty>No devices match.</Empty>}
        </div>
      </Card>
      {selected && <DeviceDrawer mac={selected} onClose={() => navigate("/devices")} onChanged={list.reload} />}
    </div>
  );
}

interface DeviceDetail extends Device {
  traffic: { summary: Summary; timeseries: TimeSeries; apps: TopRow[]; destinations: TopRow[] } | null;
}

function DeviceDrawer({ mac, onClose, onChanged }: { mac: string; onClose: () => void; onChanged: () => void }) {
  const [range, setRange] = useState<"1h" | "24h" | "7d">("24h");
  const d = useApi<DeviceDetail>(`/devices/${encodeURIComponent(mac)}?range=${range}`, [range]);
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const [alias, setAlias] = useState<string | null>(null);
  const [notes, setNotes] = useState<string | null>(null);
  const dev = d.data;
  const t = dev?.traffic;
  const series = useMemo(() => (t?.timeseries.series ?? []).map((s) => ({ ...s, label: DIRECTION_LABEL[s.key] ?? s.label })), [t]);

  const save = () => run(async () => {
    await patch(`/devices/${mac}`, { alias: alias ?? dev?.alias ?? "", notes: notes ?? dev?.notes ?? "" });
    d.reload();
    onChanged();
  }, "Device saved");

  const toggleBlock = async () => {
    if (!dev) return;
    const blocking = !dev.blocked;
    if (blocking && !(await confirm(`Block ${dev.name}?`, <>A firewall rule will reject all forwarded traffic from <code>{dev.mac}</code>. The device stays connected to the LAN but loses internet access.</>, "Block device"))) return;
    await run(async () => {
      await post(`/devices/${mac}/block`, { blocked: blocking });
      d.reload();
      onChanged();
    }, blocking ? "Device blocked" : "Device unblocked");
  };

  const forget = async () => {
    if (!(await confirm("Forget this device?", "It will be removed from the inventory until it is seen again. Recorded flows are kept.", "Forget"))) return;
    await run(async () => { await del(`/devices/${mac}`); onChanged(); onClose(); }, "Device forgotten");
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" aria-label="Device details">
        {element}
        <div className="page-head">
          <h1>{dev?.name ?? mac}</h1>
          {dev?.blocked ? <span className="badge bad">blocked</span> : null}
          <span className="spacer" />
          <button onClick={onClose} aria-label="Close">✕</button>
        </div>
        <ErrorBox error={d.error} />
        {dev && (
          <div className="stack">
            <Card>
              <dl className="kv">
                <dt>IP address</dt><dd className="mono">{dev.ip ?? "–"}</dd>
                <dt>MAC</dt><dd className="mono">{dev.mac}</dd>
                <dt>Vendor</dt><dd>{dev.vendor ?? "unknown"}</dd>
                <dt>DHCP hostname</dt><dd>{dev.hostname ?? "–"}</dd>
                <dt>First seen</dt><dd>{time(dev.first_seen, true)}</dd>
                <dt>Last seen</dt><dd>{time(dev.last_seen, true)} ({ago(dev.last_seen)})</dd>
              </dl>
              <div className="form-grid" style={{ marginTop: 14 }}>
                <label className="field">Alias<input value={alias ?? dev.alias ?? ""} placeholder={dev.hostname ?? ""} onChange={(e) => setAlias(e.target.value)} maxLength={64} /></label>
                <label className="field" style={{ gridColumn: "1 / -1" }}>Notes<textarea rows={2} value={notes ?? dev.notes ?? ""} onChange={(e) => setNotes(e.target.value)} maxLength={2000} /></label>
              </div>
              <div className="row" style={{ marginTop: 12 }}>
                <button className="primary" disabled={busy || (alias === null && notes === null)} onClick={save}>Save</button>
                <button className={dev.blocked ? "" : "danger"} disabled={busy} onClick={toggleBlock}>{dev.blocked ? "Unblock internet access" : "Block internet access"}</button>
                {dev.ip && <a className="btn" href={href("/traffic", { local_ip: dev.ip, range })}>Open in explorer</a>}
                <span className="spacer" />
                <button className="ghost danger" disabled={busy} onClick={forget}>Forget</button>
              </div>
            </Card>
            {t && (
              <>
                <div className="row"><Seg label="Period" value={range} onChange={setRange} options={[{ value: "1h", label: "1h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }]} /></div>
                <div className="tiles">
                  <Tile label="Download" swatch="--series-1" value={bytes(t.summary.download)} />
                  <Tile label="Upload" swatch="--series-2" value={bytes(t.summary.upload)} />
                  <Tile label="LAN" swatch="--series-3" value={bytes(t.summary.lan)} />
                  <Tile label="Remote hosts" value={num(t.summary.remote_hosts)} sub={`${num(t.summary.flows)} flows`} />
                </div>
                <Card title="Traffic">
                  {series.length ? <TimeChart timestamps={t.timeseries.timestamps} series={series} unit="rate" divideBy={t.timeseries.bucket} scope="direction" height={220} ariaLabel="Device traffic over time" /> : <Empty>No traffic in this period.</Empty>}
                </Card>
                <Card title="Applications" actions={<DirLegend />}><TopTable rows={t.apps} /></Card>
                <Card title="Top destinations" actions={<DirLegend />}><TopTable rows={t.destinations} linkTo={(r) => href("/traffic", { remote_ip: r.key, local_ip: dev.ip, range })} /></Card>
              </>
            )}
          </div>
        )}
      </aside>
    </>
  );
}
