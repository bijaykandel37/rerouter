import { useMemo, useState } from "react";
import { post, type CommandResult, type LogEntry } from "../api";
import { Card, Empty, ErrorBox, Seg } from "../components/ui";
import { time } from "../format";
import { useApi } from "../hooks";

type Tool = "ping" | "traceroute" | "lookup";

export default function Diagnostics() {
  const [tool, setTool] = useState<Tool>("ping");
  const [host, setHost] = useState("1.1.1.1");
  const [count, setCount] = useState(4);
  const [output, setOutput] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const runTool = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setOutput(null);
    try {
      if (tool === "lookup") {
        const r = await post<Record<string, unknown>>("/diagnostics/lookup", { host });
        setOutput(JSON.stringify(r, null, 2));
      } else {
        const r = await post<CommandResult>(`/diagnostics/${tool}`, { host, count });
        setOutput(r.output);
        if (!r.ok) setError(`${tool} reported a failure`);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <div className="page-head"><h1>Diagnostics & logs</h1></div>
      <Card title="Network tools" hint={tool === "lookup" ? "resolved from the rerouter host, plus names learned from observed DNS" : "executed on the router"}>
        <form className="row" onSubmit={runTool}>
          <Seg label="Tool" value={tool} onChange={setTool} options={[{ value: "ping", label: "Ping" }, { value: "traceroute", label: "Traceroute" }, { value: "lookup", label: "DNS lookup" }]} />
          <input aria-label="Host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="host or IP" style={{ width: 220 }} />
          {tool === "ping" && <label className="row small">count <input type="number" min={1} max={20} value={count} onChange={(e) => setCount(Number(e.target.value))} style={{ width: 64 }} /></label>}
          <button className="primary" disabled={busy || !host}>{busy ? "Running…" : "Run"}</button>
        </form>
        <div style={{ marginTop: 12 }}>
          <ErrorBox error={error} />
          {output !== null && <pre className="output" style={{ marginTop: 8 }}>{output}</pre>}
        </div>
      </Card>
      <RouterLog />
    </div>
  );
}

const LEVELS = ["all", "error", "warning", "notice", "info"] as const;

function RouterLog() {
  const [limit, setLimit] = useState("200");
  const logs = useApi<LogEntry[]>(`/logs?limit=${limit}`, [], 15000);
  const [level, setLevel] = useState<(typeof LEVELS)[number]>("all");
  const [q, setQ] = useState("");
  const rows = useMemo(() => {
    const s = q.toLowerCase();
    const rank: Record<string, number> = { emerg: 0, alert: 0, crit: 0, critical: 0, err: 1, error: 1, warn: 2, warning: 2, notice: 3, info: 4, debug: 5 };
    const max = level === "all" ? 9 : rank[level];
    return (logs.data ?? []).filter((l) => (rank[l.level] ?? 4) <= max && (!s || `${l.source} ${l.message}`.toLowerCase().includes(s)));
  }, [logs.data, level, q]);
  return (
    <Card title="Router log" hint="refreshes every 15 s" actions={<div className="row">
      <input placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search log" />
      <select aria-label="Minimum level" value={level} onChange={(e) => setLevel(e.target.value as (typeof LEVELS)[number])}>{LEVELS.map((l) => <option key={l} value={l}>{l === "all" ? "all levels" : `${l} and above`}</option>)}</select>
      <select aria-label="Lines" value={limit} onChange={(e) => setLimit(e.target.value)}><option>200</option><option>500</option><option>2000</option></select>
    </div>}>
      <ErrorBox error={logs.error} />
      <div className="table-wrap" style={{ maxHeight: 520, overflowY: "auto" }}>
        <table>
          <tbody>
            {rows.map((l, i) => (
              <tr key={i}>
                <td className="nowrap num small">{time(l.ts, true)}</td>
                <td className="small"><span className={`badge ${/err|crit|alert|emerg/.test(l.level) ? "bad" : ""}`}>{l.level}</span></td>
                <td className="small muted">{l.source}</td>
                <td className="mono small">{l.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {logs.data && !rows.length && <Empty>No log lines match.</Empty>}
      </div>
    </Card>
  );
}
