import { useMemo, useState } from "react";
import { patch, type Iface } from "../api";
import { TimeChart } from "../components/charts";
import { Card, Empty, ErrorBox, Seg, Toggle, useConfirm } from "../components/ui";
import { bytes, compact, rate } from "../format";
import { useAction, useApi, useLive } from "../hooks";

interface History { iface: string; bucket: number; points: { b: number; rx: number; tx: number; rx_max: number; tx_max: number; rx_errors: number; tx_errors: number }[] }

export default function Interfaces() {
  const list = useApi<Iface[]>("/interfaces", [], 10000);
  const { history } = useLive();
  const [selected, setSelected] = useState<string | null>(null);
  const [range, setRange] = useState<"1h" | "6h" | "24h" | "7d" | "30d">("24h");
  const { run, busy } = useAction();
  const { confirm, element } = useConfirm();
  const current = selected ?? list.data?.find((i) => i.role === "wan")?.name ?? list.data?.[0]?.name ?? null;
  const hist = useApi<History>(current ? `/interfaces/${encodeURIComponent(current)}/history?range=${range}` : null, [], 60000);
  const latest = history.at(-1)?.rates ?? {};

  const series = useMemo(() => {
    const pts = hist.data?.points ?? [];
    return [
      { key: "download", label: "Receive (rx)", values: pts.map((p) => p.rx) },
      { key: "upload", label: "Transmit (tx)", values: pts.map((p) => p.tx) },
    ];
  }, [hist.data]);

  const toggle = async (i: Iface, enabled: boolean) => {
    const critical = i.role === "wan" || i.role === "lan" || i.kind === "bridge";
    if (!enabled && !(await confirm(`Disable ${i.name}?`, critical
      ? <>This is a <b>{i.role ?? i.kind}</b> interface. Disabling it can cut off internet access{i.role === "lan" || i.kind === "bridge" ? " and your connection to the router and to rerouter" : ""}.</>
      : "Traffic on this interface will stop.", "Disable"))) return;
    await run(async () => { await patch(`/interfaces/${encodeURIComponent(i.name)}`, { enabled }); list.reload(); }, `${i.name} ${enabled ? "enabled" : "disabled"}`);
  };

  return (
    <div className="stack">
      {element}
      <div className="page-head"><h1>Interfaces</h1><span className="sub">physical, bridge, wireless and tunnel interfaces</span></div>
      <ErrorBox error={list.error} />
      <Card>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Interface</th><th>Role</th><th>Status</th><th>Addresses</th><th className="num">Rx now</th><th className="num">Tx now</th><th className="num">Rx total</th><th className="num">Tx total</th><th className="num">Errors</th><th>Enabled</th></tr></thead>
            <tbody>
              {list.data?.map((i) => {
                const r = latest[i.name] ?? i.rate;
                return (
                  <tr key={i.name} className="clickable" onClick={() => setSelected(i.name)} style={i.name === current ? { outline: "2px solid var(--accent)", outlineOffset: -2 } : undefined}>
                    <td><b>{i.name}</b><div className="muted small">{i.kind}{i.speed_mbps ? ` · ${i.speed_mbps} Mb/s` : ""}{i.comment ? ` · ${i.comment}` : ""}</div></td>
                    <td>{i.role ?? "–"}</td>
                    <td><span className="row" style={{ flexWrap: "nowrap" }}><span className={`dot ${i.up ? "on" : i.enabled ? "bad" : "off"}`} />{i.up ? "up" : i.enabled ? "down" : "disabled"}</span></td>
                    <td className="mono small">{i.addresses.join(", ") || "–"}{i.mac && <div className="muted">{i.mac}</div>}</td>
                    <td className="num">{rate(r?.rx_rate)}</td>
                    <td className="num">{rate(r?.tx_rate)}</td>
                    <td className="num">{bytes(i.rx_bytes)}<div className="muted small">{compact(i.rx_packets)} pkts</div></td>
                    <td className="num">{bytes(i.tx_bytes)}<div className="muted small">{compact(i.tx_packets)} pkts</div></td>
                    <td className="num">{i.rx_errors + i.tx_errors}<div className="muted small">{i.rx_dropped + i.tx_dropped} dropped</div></td>
                    <td onClick={(e) => e.stopPropagation()}><Toggle on={i.enabled} disabled={busy} label={`Enable ${i.name}`} onChange={(v) => toggle(i, v)} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
      {current && (
        <Card title={`${current} history`} hint={hist.data ? `average per ${Math.round(hist.data.bucket / 60) || hist.data.bucket + "s"}${hist.data.bucket >= 60 ? " min" : ""} · from 30 s counter samples` : ""}
          actions={<Seg label="Range" value={range} onChange={setRange} options={(["1h", "6h", "24h", "7d", "30d"] as const).map((v) => ({ value: v, label: v }))} />}>
          <ErrorBox error={hist.error} />
          {hist.data && (hist.data.points.length > 1
            ? <TimeChart timestamps={hist.data.points.map((p) => p.b)} series={series} unit="rate" scope="direction" height={280} ariaLabel={`${current} throughput history`} />
            : <Empty>Not enough samples yet — history builds up every 30 seconds.</Empty>)}
        </Card>
      )}
    </div>
  );
}
