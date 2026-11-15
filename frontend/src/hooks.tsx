import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { get } from "./api";

/** Fetch JSON; keeps showing previous data while a refetch is in flight. */
export function useApi<T>(path: string | null, deps: unknown[] = [], refreshMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!path) return;
    let cancelled = false;
    setLoading(true);
    get<T>(path)
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setError(null);
        }
      })
      .catch((e: Error) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick, ...deps]);

  useEffect(() => {
    if (!refreshMs) return;
    const id = setInterval(reload, refreshMs);
    return () => clearInterval(id);
  }, [refreshMs, reload]);

  return { data, error, loading, reload, setData };
}

/** Bumps whenever the color scheme changes so charts re-read CSS tokens. */
export function useThemeVersion(): number {
  const [v, setV] = useState(0);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const bump = () => setV((x) => x + 1);
    mq.addEventListener("change", bump);
    const obs = new MutationObserver(bump);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => {
      mq.removeEventListener("change", bump);
      obs.disconnect();
    };
  }, []);
  return v;
}

// ---------------------------------------------------------------------------
// Live stream (one WebSocket shared by the whole app)
// ---------------------------------------------------------------------------
type Listener = (data: any) => void;
export interface RatePoint { ts: number; rates: Record<string, { rx_rate: number; tx_rate: number; up: boolean; role: string | null }> }

interface LiveCtx {
  connected: boolean;
  subscribe: (topic: string, fn: Listener) => () => void;
  history: RatePoint[];
  system: any;
  flowsPerSec: number;
}

const Ctx = createContext<LiveCtx | null>(null);
const HISTORY = 300; // 5 s polls -> 25 min

export function LiveProvider({ children }: { children: ReactNode }) {
  const listeners = useRef(new Map<string, Set<Listener>>());
  const [connected, setConnected] = useState(false);
  const [history, setHistory] = useState<RatePoint[]>([]);
  const [system, setSystem] = useState<any>(null);
  const [flowsPerSec, setFlowsPerSec] = useState(0);
  const flowCounter = useRef<{ ts: number; n: number }[]>([]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 1000;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;

    const emit = (topic: string, data: unknown) => listeners.current.get(topic)?.forEach((fn) => fn(data));

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/api/live`);
      ws.onopen = () => {
        setConnected(true);
        retry = 1000;
      };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.topic === "hello") {
          if (msg.data.system) setSystem(msg.data.system);
        } else if (msg.topic === "rates") {
          setHistory((h) => [...h.slice(-HISTORY + 1), { ts: msg.data.ts, rates: msg.data.interfaces }]);
        } else if (msg.topic === "system") {
          setSystem(msg.data);
        } else if (msg.topic === "flows") {
          const now = Date.now() / 1000;
          const arr = flowCounter.current.filter((x) => now - x.ts < 30);
          arr.push({ ts: now, n: msg.data.count });
          flowCounter.current = arr;
          setFlowsPerSec(arr.reduce((s, x) => s + x.n, 0) / 30);
        }
        emit(msg.topic, msg.data);
      };
      ws.onclose = (ev) => {
        setConnected(false);
        if (stopped || ev.code === 4401) return;
        timer = setTimeout(connect, retry);
        retry = Math.min(retry * 2, 15000);
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, []);

  const subscribe = useCallback((topic: string, fn: Listener) => {
    const set = listeners.current.get(topic) ?? new Set();
    set.add(fn);
    listeners.current.set(topic, set);
    return () => {
      set.delete(fn);
    };
  }, []);

  return <Ctx.Provider value={{ connected, subscribe, history, system, flowsPerSec }}>{children}</Ctx.Provider>;
}

export function useLive(): LiveCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useLive outside LiveProvider");
  return ctx;
}

export function useTopic(topic: string, fn: Listener) {
  const { subscribe } = useLive();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => subscribe(topic, (d) => ref.current(d)), [subscribe, topic]);
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------
interface Toast { id: number; text: string; kind: "ok" | "error" }
const ToastCtx = createContext<(text: string, kind?: "ok" | "error") => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: "ok" | "error" = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 7000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind === "error" ? "error" : ""}`}>{t.text}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

/** Wrap an async action: shows a toast on success/failure, tracks busy state. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, ok?: string): Promise<T | undefined> => {
      setBusy(true);
      try {
        const r = await fn();
        if (ok) toast(ok);
        return r;
      } catch (e) {
        toast((e as Error).message, "error");
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [toast],
  );
  return { run, busy };
}
