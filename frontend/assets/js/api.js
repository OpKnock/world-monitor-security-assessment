/* API client — JWT header, 401 → login, structured errors. */
const API = (() => {
  const base = "/api";
  const tokenKey = "wm_token";

  function getToken(){ return localStorage.getItem(tokenKey); }
  function setToken(t){
    if(t) localStorage.setItem(tokenKey, t);
    else localStorage.removeItem(tokenKey);
  }

  async function req(path, options = {}){
    const headers = Object.assign({ "Content-Type":"application/json" }, options.headers || {});
    const t = getToken();
    if(t) headers["Authorization"] = `Bearer ${t}`;
    const res = await fetch(base + path, { ...options, headers });
    if(res.status === 401 && !path.startsWith("/auth/")){
      setToken(null);
      location.hash = "#/login";
      throw new Error("Session expired — sign in again.");
    }
    let data = null;
    const ct = res.headers.get("content-type") || "";
    if(ct.includes("application/json")) data = await res.json().catch(()=> null);
    else {
      const txt = await res.text().catch(()=> "");
      data = txt || null;
    }
    if(!res.ok){
      let msg = `${res.status} ${res.statusText}`;
      if(data){
        if(typeof data.detail === "string") msg = data.detail;
        else if(Array.isArray(data.detail)) msg = data.detail.map(d=> d.msg || JSON.stringify(d)).join("; ");
        else if(typeof data.detail === "object") msg = JSON.stringify(data.detail);
        else if(data.message) msg = data.message;
      }
      throw new Error(msg);
    }
    return data;
  }

  return {
    get:  (p)        => req(p),
    post: (p, body)  => req(p, { method:"POST", body: JSON.stringify(body ?? {}) }),
    put:  (p, body)  => req(p, { method:"PUT",  body: JSON.stringify(body ?? {}) }),
    del:  (p)        => req(p, { method:"DELETE" }),
    setToken, getToken,
  };
})();
