/* 病歷編碼工作台：登入與解密（與 tools/coder/build.mjs 使用相同格式） */
const CC = (() => {
  const subtle = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
  const MAGIC = [0x49, 0x43, 0x44, 0x43, 0x01];
  const SKEY = "coder.session";
  const b64 = u8 => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const rnd = n => crypto.getRandomValues(new Uint8Array(n));
  async function uidOf(name){ const h = new Uint8Array(await subtle.digest("SHA-256", enc.encode("icd-coder|" + String(name).trim().toLowerCase()))); return [...h].map(b => b.toString(16).padStart(2, "0")).join(""); }
  async function kek(pass, salt, iter){
    const base = await subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey({name:"PBKDF2", hash:"SHA-256", salt, iterations:iter}, base, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }
  async function gcmEnc(key, data){ const iv = rnd(12); const ct = new Uint8Array(await subtle.encrypt({name:"AES-GCM", iv}, key, data)); const o = new Uint8Array(12 + ct.length); o.set(iv); o.set(ct, 12); return o; }
  async function gcmDec(key, blob){ return new Uint8Array(await subtle.decrypt({name:"AES-GCM", iv:blob.slice(0, 12)}, key, blob.slice(12))); }
  const importK = raw => subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
  async function gunzip(u8){ const s = new Blob([u8]).stream().pipeThrough(new DecompressionStream("gzip")); return new Uint8Array(await new Response(s).arrayBuffer()); }

  async function fetchUsers(){
    const r = await fetch("users.json?t=" + Date.now(), {cache:"no-store"});
    if (!r.ok) throw new Error("無法取得帳號資料（" + r.status + "）");
    return r.json();
  }
  async function login(name, pass, U){
    const uid = await uidOf(name), e = U.users[uid];
    // 帳號不存在時仍執行一次金鑰推導，避免由回應時間判斷帳號是否存在
    const salt = e ? unb64(e.s) : rnd(16);
    const k = await kek(pass, salt, U.kdf.iter);
    if (!e) throw new Error("帳號或密碼錯誤");
    let rawK;
    try { rawK = await gcmDec(k, unb64(e.w)); } catch { throw new Error("帳號或密碼錯誤"); }
    const K = await importK(rawK);
    const me = JSON.parse(dec.decode(await gcmDec(K, unb64(e.m))));
    return {rawK, K, uid, me};
  }
  async function resume(U){
    const s = readSession(); if (!s) return null;
    const e = U.users[s.u]; if (!e){ clearSession(); return null; }
    try {
      const rawK = unb64(s.k), K = await importK(rawK);
      const me = JSON.parse(dec.decode(await gcmDec(K, unb64(e.m))));
      return {rawK, K, uid:s.u, me};
    } catch { clearSession(); return null; }
  }
  function readSession(){
    for (const st of [sessionStorage, localStorage]){
      try { const s = JSON.parse(st.getItem(SKEY) || "null"); if (s && (!s.exp || s.exp > Date.now())) return s; if (s) st.removeItem(SKEY); } catch {}
    }
    return null;
  }
  function saveSession(rawK, uid, remember){
    const s = JSON.stringify({k:b64(rawK), u:uid, exp: remember ? Date.now() + 7 * 864e5 : 0});
    try { (remember ? localStorage : sessionStorage).setItem(SKEY, s); } catch {}
  }
  function clearSession(){ try { sessionStorage.removeItem(SKEY); } catch {} try { localStorage.removeItem(SKEY); } catch {} }
  async function openBin(K, buf){
    const u = new Uint8Array(buf);
    if (MAGIC.some((b, i) => u[i] !== b)) throw new Error("檔案格式不符");
    return gunzip(await gcmDec(K, u.slice(MAGIC.length)));
  }
  async function makeEntry(name, pass, role, rawK, K, iter, created){
    const salt = rnd(16);
    const w = await gcmEnc(await kek(pass, salt, iter), rawK);
    const m = await gcmEnc(K, enc.encode(JSON.stringify({name:String(name).trim(), role, created: created || new Date().toISOString().slice(0, 10)})));
    return [await uidOf(name), {s:b64(salt), w:b64(w), m:b64(m)}];
  }
  async function readMeta(K, e){ return JSON.parse(dec.decode(await gcmDec(K, unb64(e.m)))); }
  async function seal(K, text){ return b64(await gcmEnc(K, enc.encode(text))); }
  async function open(K, s){ return dec.decode(await gcmDec(K, unb64(s))); }
  return {uidOf, fetchUsers, login, resume, saveSession, clearSession, openBin, makeEntry, readMeta, seal, open, dec};
})();
