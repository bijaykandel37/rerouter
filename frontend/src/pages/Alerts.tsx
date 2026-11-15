import { useState } from "react";
import { post, type Alert } from "../api";
import { Card, Empty, ErrorBox, Seg, Severity } from "../components/ui";
import { ago, time } from "../format";
import { useAction, useApi, useTopic } from "../hooks";
import { href } from "../router";

const KIND_LABEL: Record<string, string> = {
  inbound_scan: "Inbound port scan", outbound_scan: "Outbound scanning", risky_port: "Risky port", traffic_spike: "Traffic spike",
  bulk_upload: "Bulk upload", new_device: "New device", interface_state: "Interface state", interface_errors: "Interface errors",
  router_unreachable: "Router unreachable",
};

export default function Alerts({ onChange }: { onChange: () => void }) {
  const [view, setView] = useState<"open" | "all">("open");
  const alerts = useApi<Alert[]>(`/alerts?limit=500${view === "open" ? "&unacked=true" : ""}`);
  const { run, busy } = useAction();
  useTopic("alert", () => alerts.reload());

  const ack = (id: number) => run(async () => { await post(`/alerts/${id}/ack`); alerts.reload(); onChange(); });
  const ackAll = () => run(async () => { await post("/alerts/ack-all"); alerts.reload(); onChange(); }, "All alerts acknowledged");

  const drill = (a: Alert) => {
    const subj = a.subject ?? "";
    const ip = subj.split(":")[0];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) || ip.includes("::")) return href("/traffic", { ip, range: "1h", tab: "flows" });
    return null;
  };

  return (
    <div>
      <div className="page-head">
        <h1>Alerts</h1>
        <span className="sub">anomaly detection over flows · checked every minute</span>
      </div>
      <Card actions={<div className="row">
        <Seg label="Show" value={view} onChange={setView} options={[{ value: "open", label: "Open" }, { value: "all", label: "All" }]} />
        <button disabled={busy || !alerts.data?.some((a) => !a.acknowledged)} onClick={ackAll}>Acknowledge all</button>
      </div>}>
        <ErrorBox error={alerts.error} />
        <div className="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Type</th><th>Message</th><th>When</th><th /></tr></thead>
            <tbody>
              {alerts.data?.map((a) => {
                const link = drill(a);
                return (
                  <tr key={a.id} style={a.acknowledged ? { opacity: 0.55 } : undefined}>
                    <td><Severity level={a.severity} /></td>
                    <td className="nowrap">{KIND_LABEL[a.kind] ?? a.kind}</td>
                    <td>{a.message}</td>
                    <td className="nowrap" title={time(a.ts, true)}>{ago(a.ts)}</td>
                    <td className="right nowrap">
                      {link && <a className="btn small" href={link}>Investigate</a>}{" "}
                      {!a.acknowledged && <button className="small" disabled={busy} onClick={() => ack(a.id)}>Acknowledge</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {alerts.data && !alerts.data.length && <Empty>{view === "open" ? "No open alerts. Thresholds can be tuned under System → Settings." : "No alerts recorded."}</Empty>}
        </div>
      </Card>
    </div>
  );
}
