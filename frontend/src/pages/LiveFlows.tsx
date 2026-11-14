import { useMemo, useRef, useState } from "react";
import { cssVar } from "../colors";
import { TimeChart } from "../components/charts";
import { Card, Empty } from "../components/ui";
import { bytes, rate, time } from "../format";
import { useLive, useTopic } from "../hooks";

interface LiveFlow {
  ts: number; src: string; dst: string; sport: number; dport: number; proto: string; bytes: number; packets: number;
  direction: string; app: string; local: string; remote: string; remote_name: string | null;
  host: string | null; fingerprint: string | null; tls_version: string | null;
}

const MAX = 500;
const ARROW: Record<string, string> = { download: "↓", upload: "↑", lan: "↔", transit: "→" };

export default function LiveFlows() {
  const { history, flowsPerSec, connected } = useLive();
  const [flows, setFlows] = useState<LiveFlow[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [hideSmall, setHideSmall] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useTopic("flows", (d: { sample: LiveFlow[] }) => {
    if (pausedRef.current) return;
    setFlows((prev) => [...d.sample.slice().reverse(), ...prev].slice(0, MAX));
  });

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return flows.filter((f) => (!hideSmall || f.bytes >= 10_000) && (!q ||
      [f.src, f.dst, f.app, f.remote_name ?? "", f.host ?? "", String(f.sport), String(f.dport), f.proto].some((x) => x.toLowerCase().includes(q))));
  }, [flows, filter, hideSmall]);

  const ifaces = Object.keys(history.at(-1)?.rates ?? {});
  const series = useMemo(() => {
    const names = Object.keys(history.at(-1)?.rates ?? {}).filter((n) => history.some((h) => (h.rates[n]?.rx_rate ?? 0) > 0));
    return names.slice(0, 7).map((n) => ({ key: n, label: `${n} (rx+tx)`, values: history.map((h) => (h.rates[n]?.rx_rate ?? 0) + (h.rates[n]?.tx_rate ?? 0)) }));
  }, [history]);

  return (
    <div className="stack">
      <div className="page-head">
        <h1>Live flows</h1>
        <span className="row sub"><span className={`live-dot ${connected && !paused ? "" : "off"}`} />{paused ? "Paused" : connected ? `${flowsPerSec.toFixed(1)} flows/s` : "Disconnected"}</span>
      </div>

      <Card title="Interface throughput" hint={`last ${Math.round((history.length * 5) / 60)} min · ${ifaces.length} interfaces`}>
        {series.length && history.length > 1 ? (
          <TimeChart timestamps={history.map((h) => h.ts)} series={series} unit="rate" height={220} scope="iface" ariaLabel="Throughput per interface" />
        ) : <Empty>Collecting samples…</Empty>}
      </Card>

      <Card title="Flow stream" hint={`newest first · keeping last ${MAX}`}
        actions={<div className="row">
          <input placeholder="Filter IP, app, port…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter flows" />
          <label className="row small"><input type="checkbox" checked={hideSmall} onChange={(e) => setHideSmall(e.target.checked)} />Hide &lt; 10 kB</label>
          <button onClick={() => setPaused(!paused)}>{paused ? "▶ Resume" : "❚❚ Pause"}</button>
          <button onClick={() => setFlows([])}>Clear</button>
        </div>}>
        <div className="table-wrap" style={{ maxHeight: 620, overflowY: "auto" }}>
          <table>
            <thead style={{ position: "sticky", top: 0, background: cssVar("--surface") }}>
              <tr><th>Time</th><th /><th>Source</th><th>Destination</th><th>App</th><th>Proto</th><th className="num">Bytes</th><th className="num">Pkts</th></tr>
            </thead>
            <tbody>
              {visible.map((f, i) => (
                <tr key={`${f.ts}-${f.src}-${f.sport}-${f.dst}-${f.dport}-${i}`}>
                  <td className="nowrap" style={{ fontVariantNumeric: "tabular-nums" }}>{time(f.ts)}</td>
                  <td title={f.direction}>{ARROW[f.direction]}</td>
                  <td className="mono small nowrap">{f.src}:{f.sport}</td>
                  <td className="mono small nowrap">{f.dst}:{f.dport}{(f.host || f.remote_name) ? <span className="muted"> {f.host || f.remote_name}</span> : null}</td>
                  <td>{f.app}{f.tls_version ? <span className="muted small"> · {f.tls_version}</span> : null}</td>
                  <td>{f.proto}</td>
                  <td className="num">{bytes(f.bytes)}</td>
                  <td className="num">{f.packets}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!visible.length && <Empty>{flows.length ? "No flows match the filter." : "Waiting for flows… (they arrive as collectors export them)"}</Empty>}
        </div>
        <div className="muted small" style={{ marginTop: 8 }}>Rate sample: {rate(series.reduce((s, x) => s + (x.values.at(-1) ?? 0), 0))} across shown interfaces.</div>
      </Card>
    </div>
  );
}
