import { useState } from "react";
import { del, qs, type Device, type HttpTxn } from "../api";
import { Card, Empty, ErrorBox, Seg, Tile } from "../components/ui";
import { ago, bytes, num, time } from "../format";
import { useAction, useApi } from "../hooks";

const RANGES = ["15m", "1h", "6h", "24h", "7d"] as const;

interface Status { enabled: boolean; received_this_run: number; stored: number; last_ts: number | null; clients: number }
interface Top { key: string; label: string; requests: number; bytes: number; clients: number }

export default function DecryptedHttp() {
  const status = useApi<Status>("/http/status", [], 15000);
  const s = status.data;

  return (
    <div className="stack">
      <div className="page-head">
        <h1>Decrypted HTTP</h1>
        <span className="sub">Request-level detail from TLS-intercepted devices (mitmproxy)</span>
      </div>

      {s && !s.enabled && (
        <Card>
          <div className="note">
            <b>HTTP ingest is disabled.</b> This view shows decrypted request metadata from
            devices you route through <code>mitmproxy</code> with its CA installed — a path you
            enable deliberately, per device, for devices you administer. To turn it on, set an
            ingest token (<code>REROUTER_INGEST_TOKEN</code>) on rerouter and run the
            mitmproxy addon. Full steps are in <code>docs/mitmproxy.md</code>.
          </div>
        </Card>
      )}

      {s && s.enabled && (
        <>
          <div className="tiles">
            <Tile label="Transactions stored" value={num(s.stored)} sub={s.last_ts ? `last ${ago(s.last_ts)}` : "none yet"} />
            <Tile label="Instrumented clients" value={num(s.clients)} />
            <Tile label="Ingest" value={<span className="row"><span className={`dot ${s.last_ts && Date.now() / 1000 - s.last_ts < 120 ? "on" : "off"}`} />{s.received_this_run ? "active" : "idle"}</span>} sub={`${num(s.received_this_run)} this session`} />
          </div>
          {s.stored === 0
            ? <Card><Empty>Ingest is enabled but nothing has arrived yet. Start the mitmproxy addon and route a device through it — see <code>docs/mitmproxy.md</code>.</Empty></Card>
            : <Transactions onCleared={status.reload} />}
        </>
      )}
      <ErrorBox error={status.error} />
    </div>
  );
}

function Transactions({ onCleared }: { onCleared: () => void }) {
  const [range, setRange] = useState<(typeof RANGES)[number]>("6h");
  const [filters, setFilters] = useState({ client_ip: "", host: "", method: "", status: "", q: "" });
  const [page, setPage] = useState(0);
  const { run, busy } = useAction();
  const devices = useApi<Device[]>("/devices?range=7d");
  const size = 100;
  const query = qs({ range, ...filters, limit: size, offset: page * size });
  const data = useApi<{ total: number; rows: HttpTxn[] }>(`/http${query}`, [], 10000);
  const topHosts = useApi<Top[]>(`/http/top${qs({ range, by: "host", limit: 12 })}`);
  const pages = Math.ceil((data.data?.total ?? 0) / size);
  const set = (patch: Partial<typeof filters>) => { setFilters({ ...filters, ...patch }); setPage(0); };

  return (
    <div className="stack">
      <div className="filters">
        <Seg label="Range" value={range} onChange={(v) => { setRange(v); setPage(0); }} options={RANGES.map((r) => ({ value: r, label: r }))} />
        <select aria-label="Client" value={filters.client_ip} onChange={(e) => set({ client_ip: e.target.value })}>
          <option value="">All clients</option>
          {devices.data?.filter((d) => d.ip).map((d) => <option key={d.mac} value={d.ip!}>{d.name} ({d.ip})</option>)}
        </select>
        <select aria-label="Method" value={filters.method} onChange={(e) => set({ method: e.target.value })}>
          <option value="">Any method</option>
          {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <input placeholder="Host" value={filters.host} onChange={(e) => set({ host: e.target.value })} style={{ width: 160 }} aria-label="Host" />
        <input placeholder="Status" value={filters.status} onChange={(e) => set({ status: e.target.value.replace(/\D/g, "") })} style={{ width: 72 }} aria-label="Status code" />
        <input placeholder="Path or host contains…" value={filters.q} onChange={(e) => set({ q: e.target.value })} style={{ width: 200 }} aria-label="Search path" />
        <span className="spacer" />
        <button className="danger" disabled={busy} onClick={() => run(async () => { await del("/http"); onCleared(); data.reload(); }, "Cleared")}>Clear all</button>
      </div>

      <div className="grid g-21">
        <Card title="Transactions" hint={data.data ? `${num(data.data.total)} match` : ""}
          actions={pages > 1 && <div className="row small">
            <button className="small" disabled={page === 0} onClick={() => setPage(page - 1)}>← Prev</button>
            <span className="num">{page + 1} / {pages}</span>
            <button className="small" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next →</button>
          </div>}>
          <ErrorBox error={data.error} />
          <div className={`table-wrap ${data.loading ? "loading" : ""}`}>
            <table>
              <thead><tr><th>Time</th><th>Client</th><th>Request</th><th className="num">Status</th><th>Type</th><th className="num">Size</th><th className="num">ms</th></tr></thead>
              <tbody>
                {data.data?.rows.map((r) => (
                  <tr key={r.id}>
                    <td className="nowrap num small">{time(r.ts, true)}</td>
                    <td className="nowrap small">{r.client_name ?? r.client_ip ?? "–"}</td>
                    <td className="mono small" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      title={`${r.method ?? ""} ${r.scheme ?? "https"}://${r.host ?? ""}${r.path ?? ""}`}>
                      <b>{r.method}</b> {r.host}<span className="muted">{r.path}</span>
                    </td>
                    <td className="num"><StatusBadge code={r.status} /></td>
                    <td className="small muted nowrap">{(r.resp_type ?? "").split(";")[0]}</td>
                    <td className="num">{r.resp_bytes != null ? bytes(r.resp_bytes) : "–"}</td>
                    <td className="num">{r.duration_ms != null ? r.duration_ms.toFixed(0) : "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.data && !data.data.rows.length && <Empty>No transactions match.</Empty>}
          </div>
        </Card>

        <Card title="Top hosts" hint="by requests">
          <ErrorBox error={topHosts.error} />
          <div className="table-wrap">
            <table>
              <thead><tr><th>Host</th><th className="num">Reqs</th><th className="num">Bytes</th></tr></thead>
              <tbody>
                {topHosts.data?.map((h) => (
                  <tr key={h.key} className="clickable" onClick={() => set({ host: h.key })}>
                    <td className="nowrap">{h.key}</td>
                    <td className="num">{num(h.requests)}</td>
                    <td className="num">{bytes(h.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {topHosts.data && !topHosts.data.length && <Empty>No data.</Empty>}
          </div>
        </Card>
      </div>
    </div>
  );
}

function StatusBadge({ code }: { code: number | null }) {
  if (code == null) return <span className="muted">–</span>;
  const cls = code >= 500 ? "bad" : code >= 400 ? "bad" : code >= 300 ? "" : "good";
  return <span className={`badge ${cls}`}>{code}</span>;
}
