const UNITS = ["B", "kB", "MB", "GB", "TB", "PB"];

export function bytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !isFinite(n)) return "–";
  let i = 0;
  let v = Math.abs(n);
  while (v >= 1000 && i < UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${n < 0 ? "-" : ""}${i === 0 ? Math.round(v) : v.toFixed(v >= 100 ? 0 : digits)} ${UNITS[i]}`;
}

/** Bytes/second rendered as bits/second, the way network gear reports it. */
export function rate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec == null || !isFinite(bytesPerSec)) return "–";
  let v = bytesPerSec * 8;
  const units = ["bps", "kbps", "Mbps", "Gbps", "Tbps"];
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? Math.round(v) : v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function num(n: number | null | undefined): string {
  if (n == null) return "–";
  return n.toLocaleString();
}

export function compact(n: number): string {
  return Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function pct(n: number | null | undefined): string {
  return n == null ? "–" : `${n.toFixed(0)}%`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return "–";
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return m ? `${h}h ${m}m` : `${h}h`;
  if (m) return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
  return `${s}s`;
}

export function ago(ts: number | null | undefined): string {
  if (!ts) return "–";
  const s = Date.now() / 1000 - ts;
  if (s < 5) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function time(ts: number | null | undefined, withDate = false): string {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  return withDate
    ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function axisTime(ts: number, span: number): string {
  const d = new Date(ts * 1000);
  if (span > 2 * 86400) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " +
    d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  if (span < 1800) return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function tcpFlags(f: number): string {
  const names: [number, string][] = [[1, "F"], [2, "S"], [4, "R"], [8, "P"], [16, "A"], [32, "U"]];
  return names.filter(([b]) => f & b).map(([, n]) => n).join("") || "–";
}

export function until(ts: number | null | undefined): string {
  if (!ts) return "–";
  const s = ts - Date.now() / 1000;
  if (s <= 0) return "expired";
  return `in ${duration(s)}`;
}
