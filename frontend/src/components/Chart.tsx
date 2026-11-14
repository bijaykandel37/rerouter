import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, GraphChart, HeatmapChart, LineChart, SankeyChart } from "echarts/charts";
import { GridComponent, TooltipComponent, VisualMapComponent, MarkLineComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { cssVar } from "../colors";
import { useThemeVersion } from "../hooks";

echarts.use([LineChart, BarChart, SankeyChart, GraphChart, HeatmapChart, GridComponent, TooltipComponent,
  VisualMapComponent, MarkLineComponent, CanvasRenderer]);

export type Option = echarts.EChartsCoreOption;

interface Props {
  option: (theme: ChartTheme) => Option;
  height?: number;
  onClick?: (params: any) => void;
  className?: string;
  ariaLabel: string;
}

export interface ChartTheme {
  ink: string; ink2: string; muted: string; grid: string; axis: string; surface: string; border: string;
}

export function chartTheme(): ChartTheme {
  return {
    ink: cssVar("--ink"), ink2: cssVar("--ink-2"), muted: cssVar("--muted"), grid: cssVar("--grid"),
    axis: cssVar("--axis"), surface: cssVar("--surface"), border: cssVar("--border"),
  };
}

export function tooltipStyle(t: ChartTheme) {
  return {
    backgroundColor: t.surface, borderColor: t.border, borderWidth: 1, padding: [8, 10],
    textStyle: { color: t.ink, fontSize: 12, fontFamily: "system-ui, sans-serif" },
    extraCssText: "box-shadow: 0 4px 16px rgba(0,0,0,.12); border-radius: 8px;",
  };
}

export function axisStyle(t: ChartTheme) {
  return {
    axisLine: { lineStyle: { color: t.axis } },
    axisTick: { show: false },
    axisLabel: { color: t.muted, fontSize: 11 },
    splitLine: { lineStyle: { color: t.grid, type: "solid" as const } },
  };
}

export function Chart({ option, height = 260, onClick, className, ariaLabel }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);
  const themeV = useThemeVersion();
  const clickRef = useRef(onClick);
  clickRef.current = onClick;

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: "canvas" });
    inst.current = chart;
    chart.on("click", (p) => clickRef.current?.(p));
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      chart.dispose();
      inst.current = null;
    };
  }, []);

  useEffect(() => {
    const t = chartTheme();
    inst.current?.setOption({ animationDuration: 300, textStyle: { fontFamily: "system-ui, sans-serif" }, ...option(t) }, true);
  }, [option, themeV]);

  return <div ref={ref} className={`chart ${className ?? ""}`} style={{ height }} role="img" aria-label={ariaLabel} />;
}
