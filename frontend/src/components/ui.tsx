import { useState, type ReactNode } from "react";
import type { Alert } from "../api";
import { cssVar } from "../colors";
import { bytes } from "../format";

export function Card({ title, hint, actions, children, className }: {
  title?: ReactNode; hint?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className ?? ""}`}>
      {(title || actions) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {hint && <span className="hint">{hint}</span>}
          <span className="spacer" />
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Tile({ label, value, sub, swatch }: { label: ReactNode; value: ReactNode; sub?: ReactNode; swatch?: string }) {
  return (
    <div className="tile">
      <div className="tile-label">{swatch && <span className="swatch" style={{ background: cssVar(swatch) }} />}{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}

export function Seg<T extends string>({ value, options, onChange, label }: {
  value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} className={o.value === value ? "on" : ""} aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return <button className={`toggle ${on ? "on" : ""}`} role="switch" aria-checked={on} aria-label={label} disabled={disabled} onClick={() => onChange(!on)} />;
}

export function Tabs<T extends string>({ value, tabs, onChange }: { value: T; tabs: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.value} role="tab" aria-selected={t.value === value} className={t.value === value ? "on" : ""} onClick={() => onChange(t.value)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorBox({ error }: { error: string | null | undefined }) {
  return error ? <div className="error-box" role="alert">{error}</div> : null;
}

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h2 style={{ fontSize: 16, marginBottom: 12 }}>{title}</h2>
        {children}
      </div>
    </>
  );
}

/** Two-step confirmation for destructive or disruptive actions. */
export function useConfirm() {
  const [state, setState] = useState<{ title: string; body: ReactNode; action: string; danger: boolean; resolve: (v: boolean) => void } | null>(null);
  const confirm = (title: string, body: ReactNode, action = "Confirm", danger = true) =>
    new Promise<boolean>((resolve) => setState({ title, body, action, danger, resolve }));
  const close = (v: boolean) => {
    state?.resolve(v);
    setState(null);
  };
  const element = state ? (
    <Modal title={state.title} onClose={() => close(false)}>
      <div className="ink2" style={{ marginBottom: 16 }}>{state.body}</div>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={() => close(false)}>Cancel</button>
        <button className={state.danger ? "danger solid" : "primary"} onClick={() => close(true)} autoFocus>{state.action}</button>
      </div>
    </Modal>
  ) : null;
  return { confirm, element };
}

const SEV: Record<Alert["severity"], { color: string; label: string; icon: ReactNode }> = {
  info: { color: "--series-1", label: "Info", icon: <path d="M8 7v4M8 5h.01" /> },
  warning: { color: "--warning", label: "Warning", icon: <path d="M8 5v3.5M8 11h.01" /> },
  serious: { color: "--serious", label: "Serious", icon: <path d="M8 5v3.5M8 11h.01" /> },
  critical: { color: "--critical", label: "Critical", icon: <path d="M6 6l4 4M10 6l-4 4" /> },
};

/** Status is never color alone: icon + label + color. */
export function Severity({ level }: { level: Alert["severity"] }) {
  const s = SEV[level] ?? SEV.info;
  const c = cssVar(s.color);
  return (
    <span className="sev">
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        {level === "warning" ? <path d="M8 1.5L15 14H1z" fill={c} /> : level === "critical" ? <rect x="1.5" y="1.5" width="13" height="13" rx="3" fill={c} /> : <circle cx="8" cy="8" r="7" fill={c} />}
        <g stroke={level === "warning" ? "#0b0b0b" : "#fff"} strokeWidth="1.8" strokeLinecap="round" fill="none">{s.icon}</g>
      </svg>
      {s.label}
    </span>
  );
}

/** Inline two-segment bar (download / upload) for table rows. */
export function DirBar({ down, up, max }: { down: number; up: number; max: number }) {
  const total = down + up;
  const w = max > 0 ? (total / max) * 100 : 0;
  return (
    <div className="bar-cell" title={`↓ ${bytes(down)} · ↑ ${bytes(up)}`}>
      <div className="bar-track">
        <div style={{ width: `${w}%`, display: "flex", gap: 2, height: "100%" }}>
          {down > 0 && <div className="bar-seg" style={{ flex: down, background: cssVar("--series-1") }} />}
          {up > 0 && <div className="bar-seg" style={{ flex: up, background: cssVar("--series-2") }} />}
        </div>
      </div>
    </div>
  );
}

export function DirLegend() {
  return (
    <div className="chart-legend" style={{ marginTop: 0 }}>
      <span><span className="swatch" style={{ background: cssVar("--series-1") }} />Download</span>
      <span><span className="swatch" style={{ background: cssVar("--series-2") }} />Upload</span>
    </div>
  );
}

export function Sortable({ label, k, sort, setSort, className }: {
  label: string; k: string; sort: { k: string; desc: boolean }; setSort: (s: { k: string; desc: boolean }) => void; className?: string;
}) {
  const on = sort.k === k;
  return (
    <th className={`sortable ${className ?? ""}`} aria-sort={on ? (sort.desc ? "descending" : "ascending") : "none"}
      onClick={() => setSort({ k, desc: on ? !sort.desc : true })}>
      {label} {on ? (sort.desc ? "↓" : "↑") : ""}
    </th>
  );
}

export function sortRows<T>(rows: T[], sort: { k: string; desc: boolean }): T[] {
  return [...rows].sort((a: any, b: any) => {
    const x = a[sort.k], y = b[sort.k];
    const r = typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true });
    return sort.desc ? -r : r;
  });
}
