import { useEffect, useState } from "react";
const API =
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== "undefined" ? window.location.origin : "");

export default function App() {
  const [me, setMe] = useState(null);
  const [orders, setOrders] = useState(null);

  const login = () => (window.location.href = `${API}/auth/github`);
  const logout = async () => {
    await fetch(`${API}/auth/logout`, { method: "POST", credentials: "include" });
    setMe(null);
    setOrders(null);
  };

  const loadMe = async () => {
    const res = await fetch(`${API}/api/me`, { credentials: "include" });
    if (res.ok) setMe(await res.json());
  };
  const loadOrders = async () => {
    const res = await fetch(`${API}/api/orders`, { credentials: "include" });
    setOrders(res.ok ? await res.json() : null);
  };

  useEffect(() => {
    loadMe();
  }, []);

  return (
    <div style={{ maxWidth: 640, margin: "40px auto", fontFamily: "system-ui" }}>
      <h2>OAuth2 + JWT · Demo</h2>
      {!me ? (
        <button onClick={login}>用 GitHub 登录</button>
      ) : (
        <>
          <div>你好，{me.user?.name || me.user?.login}（GitHub）</div>
          <button onClick={loadOrders} style={{ marginRight: 8 }}>
            请求 /api/orders
          </button>
          <button onClick={logout}>退出</button>
        </>
      )}
      <pre style={{ background: "#f6f8fa", padding: 12, marginTop: 16 }}>
        {me ? JSON.stringify(me, null, 2) : "未登录"}
      </pre>
      {orders && <pre style={{ background: "#f6f8fa", padding: 12 }}>{JSON.stringify(orders, null, 2)}</pre>}
    </div>
  );
}