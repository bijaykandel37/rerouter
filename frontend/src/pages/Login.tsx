import { useState } from "react";
import { post } from "../api";

export default function Login({ onLogin }: { onLogin: (user: string) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ username: string }>("/auth/login", { username, password });
      onLogin(r.username);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login stack" onSubmit={submit}>
        <div className="brand" style={{ padding: 0 }}>
          <span className="brand-mark"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"><path d="M3 15h5l3-8 3 12 2-5h5" /></svg></span>
          rerouter
        </div>
        <div className="muted small" style={{ marginTop: -8 }}>Router administration & traffic analytics</div>
        <label className="field">Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
        <label className="field">Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required /></label>
        {error && <div className="error-box" role="alert">{error}</div>}
        <button className="primary" disabled={busy} type="submit" style={{ justifyContent: "center" }}>{busy ? "Signing in…" : "Sign in"}</button>
        <div className="muted small">First run? The initial admin password is printed in the server log, or set it with <code>REROUTER_ADMIN_PASSWORD</code>.</div>
      </form>
    </div>
  );
}
