/* API client — attaches JWT, handles 401 -> login redirect. */
const API = (() => {
  const base = "/api";
  const tokenKey = "wm_token";

  function getToken() { return localStorage.getItem(tokenKey); }
  function setToken(t) {
    if (t) localStorage.setItem(tokenKey, t);
    else localStorage.removeItem(tokenKey);
  }

  async function req(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    const t = getToken();
    if (t) headers["Authorization"] = `Bearer ${t}`;
    const res = await fetch(base + path, { ...options, headers });
    if (res.status === 401 && !path.startsWith("/auth/")) {
      setToken(null);
      location.hash = "#/login";
      throw new Error("Session expired — sign in again");
    }
    let data = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) data = await res.json();
    else data = await res.text();
    if (!res.ok) {
      const msg = (data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `${res.status} ${res.statusText}`;
      throw new Error(msg);
    }
    return data;
  }

  return {
    get: (p) => req(p),
    post: (p, body) => req(p, { method: "POST", body: JSON.stringify(body ?? {}) }),
    setToken, getToken,
  };
})();
