import { useCallback, useMemo, useState } from "react";
import { Chart, axisStyle, tooltipStyle, type ChartTheme } from "./Chart";
import { axisTime, bytes, compact, rate } from "../format";
import { colorFor, cssVar, seqRamp } from "../colors";

export type Unit = "rate" | "bytes" | "count";

export interface TSeries { key: string; label: string; values: number[] }

const fmt = (unit: Unit) => (v: number) => (unit === "rate" ? rate(v) : unit === "bytes" ? bytes(v) : compact(v));

/** Line / stacked-area time series with a crosshair tooltip and an HTML legend. */
export function TimeChart({ timestamps, series, unit, stacked = false, height = 260, scope = "default",
  ariaLabel, divideBy = 1 }: {
  timestamps: number[]; series: TSeries[]; unit: Unit; stacked?: boolean; height?: number; scope?: string;
  ariaLabel: string; divideBy?: number;
}) {
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const span = timestamps.length > 1 ? timestamps[timestamps.length - 1] - timestamps[0] : 0;
  const f = useMemo(() => fmt(unit), [unit]);
  const visible = useMemo(() => series.filter((s) => !hidden.has(s.key)), [series, hidden]);

  const option = useCallback((t: ChartTheme) => ({
    grid: { left: 8, right: 12, top: 12, bottom: 4, containLabel: true },
    tooltip: {
      trigger: "axis", ...tooltipStyle(t),
      axisPointer: { type: "line", lineStyle: { color: t.axis } },
      formatter: (params: any[]) => {
        if (!params.length) return "";
        const ts = timestamps[params[0].dataIndex];
        const rows = [...params].sort((a, b) => b.value[1] - a.value[1]).map((p) =>
          `<div style="display:flex;gap:8px;align-items:center;justify-content:space-between">
             <span style="display:flex;gap:6px;align-items:center"><span style="width:8px;height:8px;border-radius:2px;background:${p.color}"></span>${escapeHtml(p.seriesName)}</span>
             <b style="font-variant-numeric:tabular-nums">${f(p.value[1])}</b></div>`).join("");
        return `<div style="min-width:180px"><div style="color:${t.muted};margin-bottom:4px">${new Date(ts * 1000).toLocaleString()}</div>${rows}</div>`;
      },
    },
    xAxis: { type: "time", ...axisStyle(t), splitLine: { show: false },
      axisLabel: { color: t.muted, fontSize: 11, hideOverlap: true, formatter: (v: number) => axisTime(v / 1000, span) } },
    yAxis: { type: "value", ...axisStyle(t), axisLine: { show: false }, axisLabel: { color: t.muted, fontSize: 11, formatter: f } },
    series: visible.map((s) => {
      const color = colorFor(s.key, scope);
      return {
        name: s.label, type: "line", showSymbol: false, symbolSize: 8, smooth: false, stack: stacked ? "all" : undefined,
        data: s.values.map((v, i) => [timestamps[i] * 1000, v / divideBy]),
        lineStyle: { width: stacked ? 1 : 2, color: stacked ? t.surface : color },
        itemStyle: { color, borderColor: t.surface, borderWidth: 2 },
        areaStyle: stacked ? { color, opacity: 0.9 } : { color, opacity: 0.08 },
        emphasis: { focus: "none" },
      };
    }),
  }), [visible, timestamps, stacked, scope, f, span, divideBy]);

  return (
    <div>
      <Chart option={option} height={height} ariaLabel={ariaLabel} />
      {series.length > 1 && (
        <div className="chart-legend">
          {series.map((s) => (
            <button key={s.key} className={hidden.has(s.key) ? "off" : ""} aria-pressed={!hidden.has(s.key)}
              onClick={() => setHidden((h) => { const n = new Set(h); n.has(s.key) ? n.delete(s.key) : n.add(s.key); return n; })}>
              <span className="swatch" style={{ background: colorFor(s.key, scope) }} />{s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** Vertical bar histogram, single series. */
export function Histogram({ labels, values, unit, height = 220, ariaLabel }: {
  labels: string[]; values: number[]; unit: Unit; height?: number; ariaLabel: string;
}) {
  const f = useMemo(() => fmt(unit), [unit]);
  const option = useCallback((t: ChartTheme) => ({
    grid: { left: 8, right: 8, top: 12, bottom: 4, containLabel: true },
    tooltip: { trigger: "item", ...tooltipStyle(t), formatter: (p: any) => `${escapeHtml(p.name)}<br/><b>${f(p.value)}</b>` },
    xAxis: { type: "category", data: labels, ...axisStyle(t), splitLine: { show: false },
      axisLabel: { color: t.muted, fontSize: 10.5, interval: 0, rotate: labels.length > 8 ? 35 : 0 } },
    yAxis: { type: "value", ...axisStyle(t), axisLine: { show: false }, axisLabel: { color: t.muted, fontSize: 11, formatter: f } },
    series: [{ type: "bar", data: values, barMaxWidth: 28, barCategoryGap: "20%",
      itemStyle: { color: cssVar("--series-1"), borderRadius: [4, 4, 0, 0] } }],
  }), [labels, values, f]);
  return <Chart option={option} height={height} ariaLabel={ariaLabel} />;
}

export interface SankeyData { nodes: { id: string; name: string; layer: string }[]; links: { source: string; target: string; value: number }[] }
const LAYER_COLOR: Record<string, string> = { dev: "--series-1", app: "--series-3", dst: "--series-7" };

export function Sankey({ data, height = 520, onNode }: { data: SankeyData; height?: number; onNode?: (layer: string, name: string) => void }) {
  const option = useCallback((t: ChartTheme) => ({
    tooltip: { trigger: "item", ...tooltipStyle(t), formatter: (p: any) => p.dataType === "edge"
      ? `${escapeHtml(strip(p.data.source))} → ${escapeHtml(strip(p.data.target))}<br/><b>${bytes(p.data.value)}</b>`
      : `${escapeHtml(p.name)}<br/><b>${bytes(p.value)}</b>` },
    series: [{
      type: "sankey", left: 8, right: 150, top: 8, bottom: 8, nodeGap: 10, nodeWidth: 12, draggable: true,
      layoutIterations: 64, emphasis: { focus: "adjacency" },
      data: data.nodes.map((n) => ({ name: n.id, itemStyle: { color: cssVar(LAYER_COLOR[n.layer] ?? "--series-other"), borderWidth: 0 },
        label: { formatter: () => n.name } })),
      links: data.links.map((l) => ({ ...l })),
      lineStyle: { color: "gradient", opacity: 0.28, curveness: 0.5 },
      label: { color: t.ink2, fontSize: 11.5 },
    }],
  }), [data]);
  return <Chart option={option} height={height} ariaLabel="Sankey diagram: devices to applications to destinations"
    onClick={(p) => p.dataType === "node" && onNode?.(p.name.split(":")[0], p.name.slice(p.name.indexOf(":") + 1))} />;
}

const strip = (id: string) => id.slice(id.indexOf(":") + 1);

export interface GraphData { nodes: { id: string; label: string; local: boolean; bytes: number }[];
  edges: { source: string; target: string; bytes: number; flows: number; apps: string[] }[] }

export function HostGraph({ data, height = 560, onNode }: { data: GraphData; height?: number; onNode?: (ip: string) => void }) {
  const option = useCallback((t: ChartTheme) => {
    const max = Math.max(1, ...data.nodes.map((n) => n.bytes));
    const emax = Math.max(1, ...data.edges.map((e) => e.bytes));
    const local = cssVar("--series-1");
    const remote = cssVar("--series-2");
    return {
      tooltip: { trigger: "item", ...tooltipStyle(t), formatter: (p: any) => p.dataType === "edge"
        ? `${escapeHtml(p.data.sl)} ↔ ${escapeHtml(p.data.tl)}<br/><b>${bytes(p.data.bytes)}</b> · ${p.data.flows} flows<br/><span style="color:${t.muted}">${escapeHtml(p.data.apps.join(", "))}</span>`
        : `<b>${escapeHtml(p.data.label)}</b><br/>${escapeHtml(p.data.id)}<br/>${bytes(p.data.bytes)} · ${p.data.local ? "local" : "remote"}` },
      series: [{
        type: "graph", layout: "force", roam: true, draggable: true,
        force: { repulsion: 140, edgeLength: [40, 140], gravity: 0.08 },
        label: { show: true, position: "right", color: t.ink2, fontSize: 10.5,
          formatter: (p: any) => (p.data.bytes / max > 0.02 || p.data.local ? p.data.label : "") },
        emphasis: { focus: "adjacency", lineStyle: { opacity: 0.9 } },
        data: data.nodes.map((n) => ({ ...n, name: n.id, symbolSize: 8 + 34 * Math.sqrt(n.bytes / max),
          itemStyle: { color: n.local ? local : remote, borderColor: t.surface, borderWidth: 2 } })),
        edges: data.edges.map((e) => {
          const s = data.nodes.find((n) => n.id === e.source);
          const tt = data.nodes.find((n) => n.id === e.target);
          return { ...e, sl: s?.label ?? e.source, tl: tt?.label ?? e.target,
            lineStyle: { width: 0.5 + 5 * Math.sqrt(e.bytes / emax), color: t.axis, opacity: 0.6 } };
        }),
      }],
    };
  }, [data]);
  return (
    <div>
      <Chart option={option} height={height} ariaLabel="Host communication graph" onClick={(p) => p.dataType === "node" && onNode?.(p.data.id)} />
      <div className="chart-legend">
        <span><span className="swatch" style={{ background: cssVar("--series-1"), borderRadius: "50%" }} />Local device</span>
        <span><span className="swatch" style={{ background: cssVar("--series-2"), borderRadius: "50%" }} />Remote endpoint</span>
        <span className="muted">Node size ∝ √bytes · drag to rearrange · scroll to zoom</span>
      </div>
    </div>
  );
}

export function Heatmap({ days, grid, height = 260 }: { days: string[]; grid: number[][]; height?: number }) {
  const max = useMemo(() => Math.max(1, ...grid.flat()), [grid]);
  const option = useCallback((t: ChartTheme) => ({
    grid: { left: 8, right: 8, top: 8, bottom: 40, containLabel: true },
    tooltip: { ...tooltipStyle(t), formatter: (p: any) => `${days[p.value[1]]} ${String(p.value[0]).padStart(2, "0")}:00–${String(p.value[0] + 1).padStart(2, "0")}:00<br/><b>${bytes(p.value[2])}</b>` },
    xAxis: { type: "category", data: [...Array(24).keys()].map((h) => String(h).padStart(2, "0")), ...axisStyle(t), splitLine: { show: false }, axisLine: { show: false } },
    yAxis: { type: "category", data: days, inverse: true, ...axisStyle(t), splitLine: { show: false }, axisLine: { show: false } },
    visualMap: { min: 0, max, calculable: false, orient: "horizontal", left: "center", bottom: 0, itemHeight: 160, itemWidth: 10,
      inRange: { color: seqRamp() }, textStyle: { color: t.muted, fontSize: 11 }, text: [bytes(max), "0 B"], textGap: 8 },
    series: [{ type: "heatmap", data: grid.flatMap((row, d) => row.map((v, h) => [h, d, v])),
      itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: 3 } }],
  }), [days, grid, max]);
  return <Chart option={option} height={height} ariaLabel="Traffic by weekday and hour heatmap" />;
}

/** Live throughput (two series) built from WebSocket rate history. */
export function LiveRateChart({ points, height = 240 }: { points: { ts: number; rx: number; tx: number }[]; height?: number }) {
  const series: TSeries[] = [
    { key: "download", label: "Download", values: points.map((p) => p.rx) },
    { key: "upload", label: "Upload", values: points.map((p) => p.tx) },
  ];
  return <TimeChart timestamps={points.map((p) => p.ts)} series={series} unit="rate" height={height} scope="direction" ariaLabel="Live WAN throughput" />;
}

export function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}
