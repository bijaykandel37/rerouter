export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function detail(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d))
      return d.map((e) => `${(e.loc ?? []).slice(1).join(".")}: ${e.msg}`).join("; ");
  }
  return fallback;
}

export async function api<T = unknown>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, ...rest } = init;
  const res = await fetch(`/api${path}`, {
    credentials: "same-origin",
    ...rest,
    headers: { ...(json !== undefined ? { "Content-Type": "application/json" } : {}), ...rest.headers },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  if (res.status === 401 && !path.startsWith("/auth/login")) onUnauthorized();
  const text = await res.text();
  const body = text ? safeJson(text) : null;
  if (!res.ok) throw new ApiError(res.status, detail(body, `${res.status} ${res.statusText}`));
  return body as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export const get = <T,>(path: string) => api<T>(path);
export const post = <T,>(path: string, json?: unknown) => api<T>(path, { method: "POST", json: json ?? {} });
export const put = <T,>(path: string, json: unknown) => api<T>(path, { method: "PUT", json });
export const patch = <T,>(path: string, json: unknown) => api<T>(path, { method: "PATCH", json });
export const del = <T,>(path: string) => api<T>(path, { method: "DELETE" });

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

// ---- types ----
export interface Rate { rx_rate: number; tx_rate: number; rx_pps: number; tx_pps: number; up: boolean; role: string | null }
export interface SystemInfo {
  hostname: string; model: string; firmware: string; uptime_s: number; load: number[];
  cpu_percent: number | null; mem_total: number | null; mem_free: number | null; temperature_c: number | null;
  extra: Record<string, string>;
}
export interface Status {
  driver: string; router_host: string | null; capabilities: string[]; online: boolean | null;
  last_error: string | null; simulation: boolean; live_subscribers: number;
  collectors: {
    netflow: { listening: boolean; bind: string; port: number; error: string | null;
      exporters: Record<string, { packets: number; flows: number; last_seen: number }>; parser: Record<string, number> } | null;
    capture: { interface: string; packets: number; active_flows: number; l7_observed: number; error: string | null; running: boolean } | null;
    sink: { received: number; stored: number; dropped: number; last_flush: number; by_source: Record<string, number> };
    http_ingest: { enabled: boolean; received: number; last_ts: number };
  };
  counts: { devices: number; open_alerts: number; flows_last_hour: number };
  system: SystemInfo | null; rates: Record<string, Rate>; router_ips: string[];
}
export interface Summary {
  flows: number; bytes: number; packets: number; download: number; upload: number; lan: number; transit: number;
  local_hosts: number; remote_hosts: number; start: number; end: number; top_app: string | null;
  avg_download_rate: number; avg_upload_rate: number;
}
export interface Series { key: string; label: string; values: number[] }
export interface TimeSeries { bucket: number; metric: string; group_by: string; timestamps: number[]; series: Series[] }
export interface TopRow {
  key: string; label: string; bytes: number; packets: number; flows: number; download: number; upload: number;
  lan: number; transit: number; first_seen: number; last_seen: number; apps: number; mac?: string; vendor?: string;
  local_ip?: string; remote_ip?: string;
}
export interface Flow {
  id: number; ts_start: number; ts_end: number; src_ip: string; dst_ip: string; src_port: number; dst_port: number;
  proto: number; proto_name: string; bytes: number; packets: number; tcp_flags: number; direction: string;
  local_ip: string; remote_ip: string; local_port: number; remote_port: number; app: string; source: string;
  local_name: string | null; remote_name: string | null;
  host: string | null; fingerprint: string | null; tls_version: string | null;
}
export interface HttpTxn {
  id: number; ts: number; client_ip: string | null; client_port: number | null; method: string | null;
  scheme: string | null; host: string | null; path: string | null; status: number | null;
  req_type: string | null; req_bytes: number | null; resp_type: string | null; resp_bytes: number | null;
  duration_ms: number | null; note: string | null; source: string; client_name: string | null;
}
export interface Device {
  mac: string; ip: string | null; hostname: string | null; alias: string | null; vendor: string | null;
  first_seen: number; last_seen: number; blocked: number; notes: string | null; name: string; online: boolean;
  download: number; upload: number; lan: number; flows: number; peers: number; last_flow: number | null;
}
export interface Iface {
  name: string; kind: string; role: string | null; mac: string | null; mtu: number | null; up: boolean; enabled: boolean;
  addresses: string[]; speed_mbps: number | null; comment: string | null; rx_bytes: number; tx_bytes: number;
  rx_packets: number; tx_packets: number; rx_errors: number; tx_errors: number; rx_dropped: number; tx_dropped: number;
  rate: Rate | null;
}
export interface Alert {
  id: number; ts: number; severity: "info" | "warning" | "serious" | "critical"; kind: string; subject: string | null;
  message: string; details: Record<string, unknown>; acknowledged: boolean;
}
export interface FirewallRule {
  id: string; name: string; enabled: boolean; chain: string; action: string; proto: string; src: string | null;
  src_port: string | null; dst: string | null; dst_port: string | null; src_mac: string | null; managed: boolean;
}
export interface PortForward { id: string; name: string; enabled: boolean; proto: string; ext_port: string; int_ip: string; int_port: string; src: string | null }
export interface Route { id: string; dst: string; gateway: string | null; iface: string | null; metric: number | null; static: boolean; active: boolean; comment: string | null }
export interface Lease { id: string | null; mac: string; ip: string; hostname: string | null; expires: number | null; static: boolean }
export interface Wifi { id: string; ssid: string; band: string | null; channel: string | null; encryption: string | null; enabled: boolean; hidden: boolean; clients: number | null }
export interface LogEntry { ts: number | null; level: string; source: string | null; message: string }
export interface CommandResult { ok: boolean; output: string }
export interface AuditEntry { id: number; ts: number; username: string | null; action: string; details: Record<string, unknown>; ok: boolean }
export interface RuntimeSettings {
  lan_networks: string[]; router_ips: string[]; flow_retention_days: number; sample_retention_days: number;
  http_retention_days: number; reverse_dns: boolean;
  alerts: { spike_sigma: number; spike_min_bytes: number; scan_targets: number; upload_bytes_10m: number;
    risky_ports: number[]; new_device: boolean; interface_errors: number };
}
