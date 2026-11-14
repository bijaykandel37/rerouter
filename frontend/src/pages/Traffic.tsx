import { useMemo, useState } from "react";
import { qs, type Device, type Flow, type Summary, type TimeSeries, type TopRow } from "../api";
import { DIRECTION_LABEL } from "../colors";
import { Heatmap, Histogram, HostGraph, Sankey, TimeChart, type GraphData, type SankeyData } from "../components/charts";
import { Card, Empty, ErrorBox, Seg, Tabs, Tile } from "../components/ui";
import { bytes, compact, duration, num, rate, tcpFlags, time } from "../format";
import { useApi } from "../hooks";
import { navigate, useRoute } from "../router";
import { TopTable } from "./Dashboard";

const RANGES = ["5m", "15m", "1h", "6h", "24h", "7d", "30d"] as const;
const FILTER_KEYS = ["range", "local_ip", "remote_ip", "ip", "app", "direction", "port", "proto"] as const;
type Tab = "time" | "sankey" | "graph" | "rank" | "patterns" | "flows";

export default function Traffic() {
  const { params } = useRoute();
  const f = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""])) as Record<(typeof FILTER_KEYS)[number], string>;
  if (!f.range) f.range = "1h";
  const tab = (params.get("tab") as Tab) || "time";
  const filterQs = qs(f);
  const set = (patch: Record<string, string | number | null>) => {
    const next: Record<string, string | number | null> = { ...f, tab, ...patch };
    navigate("/traffic", next as Record<string, string>);
  };

  const devices = useApi<Device[]>("/devices?range=7d");
  const apps = useApi<string[]>("/traffic/apps");
  const summary = useApi<Summary>(`/traffic/summary${filterQs}`, [], 30000);
  const active = FILTER_KEYS.filter((k) => k !== "range" && f[k]);

  return (
    <div>
      <div className="page-head">
        <h1>Traffic explorer</h1>
        <span className="sub">Every flow to, from and through the router</span>
      </div>

      <div className="filters" role="search">
        <Seg label="Time range" value={f.range} options={RANGES.map((r) => ({ value: r, label: r }))} onChange={(v) => set({ range: v })} />
        <select aria-label="Device" value={f.local_ip} onChange={(e) => set({ local_ip: e.target.value })}>
          <option value="">All devices</option>
          {devices.data?.filter((d) => d.ip).map((d) => <option key={d.mac} value={d.ip!}>{d.name} ({d.ip})</option>)}
        </select>
        <select aria-label="Direction" value={f.direction} onChange={(e) => set({ direction: e.target.value })}>
          <option value="">All directions</option>
          {Object.entries(DIRECTION_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select aria-label="Application" value={f.app} onChange={(e) => set({ app: e.target.value })}>
          <option value="">All applications</option>
          {apps.data?.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select aria-label="Protocol" value={f.proto} onChange={(e) => set({ proto: e.target.value })}>
          <option value="">Any protocol</option>
          <option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option><option value="58">ICMPv6</option>
        </select>
        <DebouncedInput placeholder="Remote IP" value={f.remote_ip} onCommit={(v) => set({ remote_ip: v })} width={140} />
        <DebouncedInput placeholder="Any IP" value={f.ip} onCommit={(v) => set({ ip: v })} width={120} />
        <DebouncedInput placeholder="Port" value={f.port} onCommit={(v) => set({ port: v })} width={70} />
        {active.length > 0 && <button className="ghost" onClick={() => navigate("/traffic", { range: f.range, tab })}>Clear {active.length} filter{active.length > 1 ? "s" : ""}</button>}
        <span className="spacer" />
        <a className="btn" href={`/api/traffic/export${filterQs}&format=csv`} download>Export CSV</a>
        <a className="btn" href={`/api/traffic/export${filterQs}&format=jsonl`} download>JSONL</a>
      </div>

      <SummaryTiles s={summary.data} />
      <ErrorBox error={summary.error} />

      <div style={{ marginTop: 16 }}>
        <Tabs value={tab} onChange={(t) => set({ tab: t })} tabs={[
          { value: "time", label: "Over time" }, { value: "sankey", label: "Flow map" }, { value: "graph", label: "Host graph" },
          { value: "rank", label: "Rankings" }, { value: "patterns", label: "Patterns" }, { value: "flows", label: "Flow records" },
        ]} />
        {tab === "time" && <OverTime filterQs={filterQs} />}
        {tab === "sankey" && <FlowMap filterQs={filterQs} devices={devices.data ?? []} onFilter={set} />}
        {tab === "graph" && <Graph filterQs={filterQs} onFilter={set} />}
        {tab === "rank" && <Rankings filterQs={filterQs} />}
        {tab === "patterns" && <Patterns filterQs={filterQs} range={f.range} />}
        {tab === "flows" && <FlowTable filterQs={filterQs} onFilter={set} />}
      </div>
    </div>
  );
}

function DebouncedInput({ value, onCommit, placeholder, width }: { value: string; onCommit: (v: string) => void; placeholder: string; width: number }) {
  const [v, setV] = useState(value);
  const [prev, setPrev] = useState(value);
  if (value !== prev) {
    setPrev(value);
    setV(value);
  }
  return (
    <input aria-label={placeholder} placeholder={placeholder} value={v} style={{ width }} onChange={(e) => setV(e.target.value)}
      onBlur={() => v !== value && onCommit(v.trim())} onKeyDown={(e) => e.key === "Enter" && onCommit(v.trim())} />
  );
}

function SummaryTiles({ s }: { s: Summary | null }) {
  return (
    <div className="tiles">
      <Tile label="Total" value={bytes(s ? s.download + s.upload + s.lan + s.transit : null)} sub={s ? `${num(s.flows)} flows · ${compact(s.packets)} packets` : ""} />
      <Tile label="Download" swatch="--series-1" value={bytes(s?.download)} sub={s ? `avg ${rate(s.avg_download_rate)}` : ""} />
      <Tile label="Upload" swatch="--series-2" value={bytes(s?.upload)} sub={s ? `avg ${rate(s.avg_upload_rate)}` : ""} />
      <Tile label="LAN ↔ LAN" swatch="--series-3" value={bytes(s?.lan)} sub="internal traffic" />
      <Tile label="Hosts" value={s ? `${s.local_hosts} ↔ ${num(s.remote_hosts)}` : "–"} sub="local ↔ remote" />
      <Tile label="Top application" value={s?.top_app ?? "–"} />
    </div>
  );
}

const GROUPS = [
  { value: "direction", label: "Direction" }, { value: "app", label: "Application" }, { value: "local_ip", label: "Device" },
  { value: "remote_ip", label: "Destination" }, { value: "proto", label: "Protocol" }, { value: "remote_port", label: "Remote port" },
];

function OverTime({ filterQs }: { filterQs: string }) {
  const [group, setGroup] = useState("direction");
  const [metric, setMetric] = useState<"bytes" | "packets" | "flows">("bytes");
  const [stacked, setStacked] = useState(true);
  const ts = useApi<TimeSeries>(`/traffic/timeseries${filterQs}&group_by=${group}&metric=${metric}`, [], 30000);
  const series = useMemo(
    () => (ts.data?.series ?? []).map((s) => ({ ...s, label: group === "direction" ? DIRECTION_LABEL[s.key] ?? s.label : s.label })),
    [ts.data, group],
  );
  const bucket = ts.data?.bucket ?? 60;
  return (
    <Card title="Traffic over time" hint={ts.data ? (metric === "bytes" ? `average bit rate per ${duration(bucket)}` : `${metric} per ${duration(bucket)}`) : ""}
      actions={<div className="row">
        <Seg label="Group by" value={group} options={GROUPS} onChange={setGroup} />
        <Seg label="Metric" value={metric} options={[{ value: "bytes", label: "Rate" }, { value: "packets", label: "Packets" }, { value: "flows", label: "Flows" }]} onChange={setMetric} />
        <label className="row small"><input type="checkbox" checked={stacked} onChange={(e) => setStacked(e.target.checked)} />Stacked</label>
      </div>}>
      <ErrorBox error={ts.error} />
      <div className={ts.loading ? "loading" : ""}>
        {ts.data && (series.length ? (
          <TimeChart key={`${group}-${stacked}`} timestamps={ts.data.timestamps} series={series} unit={metric === "bytes" ? "rate" : "count"}
            divideBy={metric === "bytes" ? bucket : 1} stacked={stacked} height={340} scope={group} ariaLabel={`Traffic over time grouped by ${group}`} />
        ) : <Empty>No flows match these filters.</Empty>)}
      </div>
    </Card>
  );
}

function FlowMap({ filterQs, devices, onFilter }: { filterQs: string; devices: Device[]; onFilter: (p: Record<string, string>) => void }) {
  const data = useApi<SankeyData>(`/traffic/sankey${filterQs}`);
  return (
    <Card title="Device → application → destination" hint="internet traffic only; click a device or application to filter">
      <ErrorBox error={data.error} />
      <div className={data.loading ? "loading" : ""}>
        {data.data && (data.data.links.length ? (
          <Sankey data={data.data} height={Math.max(420, data.data.nodes.length * 22)} onNode={(layer, name) => {
            if (layer === "app" && name !== "other apps") onFilter({ app: name });
            if (layer === "dev") {
              const d = devices.find((x) => x.name === name || x.ip === name);
              if (d?.ip) onFilter({ local_ip: d.ip });
            }
          }} />
        ) : <Empty>No internet traffic in this period.</Empty>)}
      </div>
    </Card>
  );
}

function Graph({ filterQs, onFilter }: { filterQs: string; onFilter: (p: Record<string, string>) => void }) {
  const [limit, setLimit] = useState("80");
  const data = useApi<GraphData>(`/traffic/graph${filterQs}&limit=${limit}`);
  return (
    <Card title="Who talks to whom" hint="largest conversations; click a node to focus on it"
      actions={<Seg label="Edges" value={limit} onChange={setLimit} options={[{ value: "40", label: "40" }, { value: "80", label: "80" }, { value: "200", label: "200" }]} />}>
      <ErrorBox error={data.error} />
      {data.data && (data.data.edges.length ? <HostGraph data={data.data} onNode={(ip) => onFilter({ ip })} /> : <Empty>No conversations in this period.</Empty>)}
    </Card>
  );
}

const RANK_BY = [
  { value: "local_ip", label: "Devices" }, { value: "remote_ip", label: "Destinations" }, { value: "app", label: "Applications" },
  { value: "remote_port", label: "Remote ports" }, { value: "conversation", label: "Conversations" }, { value: "proto", label: "Protocols" },
];

function Rankings({ filterQs }: { filterQs: string }) {
  const [by, setBy] = useState("remote_ip");
  const rows = useApi<TopRow[]>(`/traffic/top${filterQs}&by=${by}&limit=50`);
  const link = (r: TopRow) => {
    const p: Record<string, string> = by === "local_ip" ? { local_ip: r.key } : by === "remote_ip" ? { remote_ip: r.key } : by === "app" ? { app: r.key }
      : by === "remote_port" ? { port: r.key } : by === "proto" ? { proto: r.key } : { local_ip: r.local_ip!, remote_ip: r.remote_ip! };
    const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
    Object.entries(p).forEach(([k, v]) => params.set(k, v));
    params.set("tab", "time");
    return `#/traffic?${params}`;
  };
  return (
    <Card title="Rankings" hint="by total bytes" actions={<Seg label="Rank" value={by} options={RANK_BY} onChange={setBy} />}>
      <ErrorBox error={rows.error} />
      <div className={rows.loading ? "loading" : ""}><TopTable rows={rows.data} linkTo={link} /></div>
      {rows.data && rows.data.length > 0 && (
        <div className="muted small" style={{ marginTop: 8 }}>
          {num(rows.data.reduce((s, r) => s + r.flows, 0))} flows · click a name to drill in
        </div>
      )}
    </Card>
  );
}

function Patterns({ filterQs, range }: { filterQs: string; range: string }) {
  const heatQs = ["5m", "15m", "1h", "6h", "24h"].includes(range) ? filterQs.replace(/range=[^&]+/, "range=7d") : filterQs;
  const heat = useApi<{ days: string[]; grid: number[][] }>(`/traffic/heatmap${heatQs}`);
  const dist = useApi<{ size: { label: string; flows: number; bytes: number }[]; duration: { label: string; flows: number; bytes: number }[] }>(`/traffic/distribution${filterQs}`);
  return (
    <div className="stack">
      <Card title="Weekly rhythm" hint={`bytes by weekday × hour (local time)${heatQs !== filterQs ? " · last 7 days" : ""}`}>
        <ErrorBox error={heat.error} />
        {heat.data && <Heatmap days={heat.data.days} grid={heat.data.grid} />}
      </Card>
      <div className="grid g2">
        <Card title="Flow size distribution" hint="number of flows per size bin (log scale bins)">
          {dist.data && (dist.data.size.length ? <Histogram labels={dist.data.size.map((d) => d.label)} values={dist.data.size.map((d) => d.flows)} unit="count" ariaLabel="Flow size histogram" /> : <Empty>No data</Empty>)}
        </Card>
        <Card title="Bytes by flow size" hint="where the volume actually is (heavy tail)">
          {dist.data && (dist.data.size.length ? <Histogram labels={dist.data.size.map((d) => d.label)} values={dist.data.size.map((d) => d.bytes)} unit="bytes" ariaLabel="Bytes per flow size bin" /> : <Empty>No data</Empty>)}
        </Card>
        <Card title="Flow duration" hint="number of flows per duration bin">
          {dist.data && (dist.data.duration.length ? <Histogram labels={dist.data.duration.map((d) => d.label)} values={dist.data.duration.map((d) => d.flows)} unit="count" ariaLabel="Flow duration histogram" /> : <Empty>No data</Empty>)}
        </Card>
        <Card title="Bytes by flow duration">
          {dist.data && (dist.data.duration.length ? <Histogram labels={dist.data.duration.map((d) => d.label)} values={dist.data.duration.map((d) => d.bytes)} unit="bytes" ariaLabel="Bytes per flow duration bin" /> : <Empty>No data</Empty>)}
        </Card>
      </div>
    </div>
  );
}

const ARROW: Record<string, string> = { download: "↓", upload: "↑", lan: "↔", transit: "→" };

function FlowTable({ filterQs, onFilter }: { filterQs: string; onFilter: (p: Record<string, string>) => void }) {
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState<{ k: string; desc: boolean }>({ k: "ts_end", desc: true });
  const size = 100;
  const data = useApi<{ total: number; rows: Flow[] }>(`/traffic/flows${filterQs}&limit=${size}&offset=${page * size}&sort=${sort.k}&desc=${sort.desc}`);
  const pages = Math.ceil((data.data?.total ?? 0) / size);
  const th = (label: string, k: string, cls = "") => (
    <th className={`sortable ${cls}`} onClick={() => { setSort({ k, desc: sort.k === k ? !sort.desc : true }); setPage(0); }}
      aria-sort={sort.k === k ? (sort.desc ? "descending" : "ascending") : "none"}>{label} {sort.k === k ? (sort.desc ? "↓" : "↑") : ""}</th>
  );
  const host = (ip: string, name: string | null, port: number, key: "local_ip" | "remote_ip") => (
    <span><a href="#" onClick={(e) => { e.preventDefault(); onFilter({ [key]: ip }); }}>{name ?? ip}</a>
      <span className="muted mono small">{name ? ` ${ip}` : ""}{port ? `:${port}` : ""}</span></span>
  );
  return (
    <Card title="Flow records" hint={data.data ? `${num(data.data.total)} flows match` : ""}
      actions={pages > 1 && <div className="row small">
        <button className="small" disabled={page === 0} onClick={() => setPage(page - 1)}>← Prev</button>
        <span className="num">{page + 1} / {pages}</span>
        <button className="small" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next →</button>
      </div>}>
      <ErrorBox error={data.error} />
      <div className={`table-wrap ${data.loading ? "loading" : ""}`}>
        <table>
          <thead><tr>{th("Ended", "ts_end")}<th /><th>Local</th><th>Remote</th><th>App</th><th>Proto</th>{th("Bytes", "bytes", "num")}{th("Packets", "packets", "num")}<th className="num">Duration</th><th>Flags</th><th>Source</th></tr></thead>
          <tbody>
            {data.data?.rows.map((r) => (
              <tr key={r.id}>
                <td className="nowrap num">{time(r.ts_end, true)}</td>
                <td title={r.direction} aria-label={r.direction}>{ARROW[r.direction]}</td>
                <td className="nowrap">{host(r.local_ip, r.local_name, r.local_port, "local_ip")}</td>
                <td className="nowrap">{host(r.remote_ip, r.remote_name, r.remote_port, "remote_ip")}</td>
                <td><a href="#" onClick={(e) => { e.preventDefault(); onFilter({ app: r.app }); }}>{r.app}</a></td>
                <td>{r.proto_name}</td>
                <td className="num">{bytes(r.bytes)}</td>
                <td className="num">{num(r.packets)}</td>
                <td className="num">{duration(r.ts_end - r.ts_start)}</td>
                <td className="mono small">{r.proto === 6 ? tcpFlags(r.tcp_flags) : ""}</td>
                <td className="muted small">{r.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.data && !data.data.rows.length && <Empty>No flows match these filters.</Empty>}
      </div>
    </Card>
  );
}
