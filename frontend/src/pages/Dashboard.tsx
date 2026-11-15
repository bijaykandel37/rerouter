import { Fragment, useMemo } from "react";
import type { Alert, Device, Status, Summary, TimeSeries, TopRow } from "../api";
import { DIRECTION_LABEL } from "../colors";
import { LiveRateChart, TimeChart } from "../components/charts";
import { Card, DirBar, DirLegend, Empty, ErrorBox, Severity, Tile } from "../components/ui";
import { ago, bytes, duration, pct, rate } from "../format";
import { useApi, useLive } from "../hooks";
import { href } from "../router";

export function wanName(rates: Record<string, { role: string | null }> | undefined): string | null {
  if (!rates) return null;
  const names = Object.keys(rates);
  return names.find((n) => rates[n].role === "wan") ?? names.find((n) => /wan|ether1|pppoe/.test(n)) ?? names[0] ?? null;
}

export default function Dashboard({ status }: { status: Status | null }) {
  const { history, system: liveSystem, flowsPerSec } = useLive();
  const summary = useApi<Summary>("/traffic/summary?range=24h", [], 60000);
  const series = useApi<TimeSeries>("/traffic/timeseries?range=24h&group_by=direction", [], 60000);
  const devices = useApi<TopRow[]>("/traffic/top?range=24h&by=local_ip&exclude_lan=true&limit=8", [], 60000);
  const apps = useApi<TopRow[]>("/traffic/top?range=24h&by=app&exclude_lan=true&limit=8", [], 60000);
  const alerts = useApi<Alert[]>("/alerts?limit=6&unacked=true", [], 30000);
  const devList = useApi<Device[]>("/devices?range=1h", [], 60000);

  const wan = wanName(history.at(-1)?.rates ?? status?.rates);
  const points = useMemo(
    () => history.filter((h) => wan && h.rates[wan]).map((h) => ({ ts: h.ts, rx: h.rates[wan!].rx_rate, tx: h.rates[wan!].tx_rate })),
    [history, wan],
  );
  const now = points.at(-1);
  const sys = liveSystem ?? status?.system;
  const online = devList.data?.filter((d) => d.online).length;
  const s = summary.data;

  const tsSeries = useMemo(
    () => (series.data?.series ?? []).map((x) => ({ ...x, label: DIRECTION_LABEL[x.key] ?? x.label })),
    [series.data],
  );

  return (
    <div className="stack">
      <div className="page-head">
        <h1>Dashboard</h1>
        <span className="sub">{sys ? `${sys.hostname} · ${sys.model}` : ""}</span>
      </div>
      {status && status.online === false && (
        <ErrorBox error={`Router unreachable: ${status.last_error ?? "unknown error"}. Showing stored data.`} />
      )}

      <div className="tiles">
        <Tile label="Download now" swatch="--series-1" value={rate(now?.rx)} sub={wan ? `on ${wan}` : "waiting for data"} />
        <Tile label="Upload now" swatch="--series-2" value={rate(now?.tx)} sub={wan ? `on ${wan}` : ""} />
        <Tile label="Last 24 h" value={bytes(s ? s.download + s.upload : null)} sub={s ? `↓ ${bytes(s.download)} · ↑ ${bytes(s.upload)}` : ""} />
        <Tile label="Devices online" value={online ?? "–"} sub={`${status?.counts.devices ?? "–"} known`} />
        <Tile label="Flows / s" value={flowsPerSec ? flowsPerSec.toFixed(1) : "–"} sub={`${status?.counts.flows_last_hour?.toLocaleString() ?? "–"} in last hour`} />
        <Tile label="Open alerts" value={status?.counts.open_alerts ?? "–"} sub={<a href={href("/alerts")}>Review</a>} />
      </div>

      <div className="grid g-21">
        <Card title="Live WAN throughput" hint="5 s samples from interface counters">
          {points.length > 1 ? <LiveRateChart points={points} /> : <Empty>Collecting samples…</Empty>}
        </Card>
        <Card title="Router health">
          {sys ? (
            <dl className="kv">
              <dt>Model</dt><dd>{sys.model}</dd>
              <dt>Firmware</dt><dd>{sys.firmware}</dd>
              <dt>Uptime</dt><dd>{duration(sys.uptime_s)}</dd>
              <dt>CPU</dt><dd>{pct(sys.cpu_percent)}{sys.load?.length ? <span className="muted"> · load {sys.load.join(" / ")}</span> : null}</dd>
              <dt>Memory</dt><dd>{sys.mem_total ? `${pct(100 * (1 - (sys.mem_free ?? 0) / sys.mem_total))} of ${bytes(sys.mem_total)}` : "–"}</dd>
              <dt>Temperature</dt><dd>{sys.temperature_c != null ? `${sys.temperature_c} °C` : "–"}</dd>
              {Object.entries((sys.extra ?? {}) as Record<string, string>).filter(([, v]) => v).map(([k, v]) => (<Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd>{v}</dd></Fragment>))}
            </dl>
          ) : <Empty>Waiting for router…</Empty>}
        </Card>
      </div>

      <Card title="Traffic over the last 24 hours" hint={series.data ? `average rate per ${duration(series.data.bucket)} bucket` : ""}
        actions={<a href={href("/traffic", { range: "24h" })}>Explore →</a>}>
        <ErrorBox error={series.error} />
        {series.data && (tsSeries.length ? (
          <TimeChart timestamps={series.data.timestamps} series={tsSeries} unit="rate" divideBy={series.data.bucket} scope="direction" ariaLabel="Traffic by direction, last 24 hours" />
        ) : <Empty>No flows recorded yet. Configure flow export under System.</Empty>)}
      </Card>

      <div className="grid g2">
        <Card title="Top devices · 24 h" actions={<DirLegend />}>
          <TopTable rows={devices.data} linkTo={(r) => href("/traffic", { range: "24h", local_ip: r.key })} />
        </Card>
        <Card title="Top applications · 24 h" actions={<DirLegend />}>
          <TopTable rows={apps.data} linkTo={(r) => href("/traffic", { range: "24h", app: r.key })} />
        </Card>
      </div>

      <Card title="Open alerts" actions={<a href={href("/alerts")}>All alerts →</a>}>
        {alerts.data?.length ? (
          <div className="table-wrap"><table><tbody>
            {alerts.data.map((a) => (
              <tr key={a.id}><td style={{ width: 110 }}><Severity level={a.severity} /></td><td>{a.message}</td><td className="muted nowrap right">{ago(a.ts)}</td></tr>
            ))}
          </tbody></table></div>
        ) : <Empty>No open alerts.</Empty>}
      </Card>
    </div>
  );
}

export function TopTable({ rows, linkTo }: { rows: TopRow[] | null; linkTo?: (r: TopRow) => string }) {
  if (!rows) return <Empty>Loading…</Empty>;
  if (!rows.length) return <Empty>No traffic in this period.</Empty>;
  const max = Math.max(...rows.map((r) => r.download + r.upload));
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Name</th><th style={{ width: "35%" }} /><th className="num">↓ Down</th><th className="num">↑ Up</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key}>
              <td>{linkTo ? <a href={linkTo(r)}>{r.label}</a> : r.label}{r.label !== r.key && <div className="muted small mono">{r.key}</div>}</td>
              <td><DirBar down={r.download} up={r.upload} max={max} /></td>
              <td className="num">{bytes(r.download)}</td>
              <td className="num">{bytes(r.upload)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
