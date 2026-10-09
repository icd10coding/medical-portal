#!/usr/bin/env node
// 病歷編碼工作台：加密打包工具（Node 18 以上）
//
// 網頁與資料檔用一把隨機內容金鑰（AES-256-GCM）加密後才放進公開的 repo；
// 每個帳號用自己的密碼（PBKDF2-SHA256）包裝同一把內容金鑰，寫在 coder/users.json。
//
// 用法：
//   第一次建立（產生內容金鑰與管理員帳號）：
//     CODER_PASS='管理員密碼' node tools/coder/build.mjs init --admin admin
//   加密網頁與資料（之後更新內容時執行）：
//     CODER_USER=admin CODER_PASS='管理員密碼' node tools/coder/build.mjs build --src <來源資料夾>
//       來源資料夾需有：app.html、data/twdrg.json.gz、data/icdref.json.gz、data/refs.json.gz
//   新增帳號（也可在網站的「帳號管理」頁操作）：
//     CODER_USER=admin CODER_PASS='管理員密碼' NEW_PASS='新帳號密碼' node tools/coder/build.mjs adduser <帳號> [--role admin|user]
//   列出帳號：
//     CODER_USER=admin CODER_PASS='管理員密碼' node tools/coder/build.mjs list
import { webcrypto as wc } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const subtle = wc.subtle;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const OUT = join(ROOT, "coder");
const USERS = join(OUT, "users.json");
const ITER = 600000;
const MAGIC = new Uint8Array([0x49, 0x43, 0x44, 0x43, 0x01]); // "ICDC" v1
const DATA = ["twdrg", "icdref", "refs"];

const b64 = u => Buffer.from(u).toString("base64");
const unb64 = s => new Uint8Array(Buffer.from(s, "base64"));
const rnd = n => wc.getRandomValues(new Uint8Array(n));
const enc = new TextEncoder(), dec = new TextDecoder();

async function uidOf(name){ const h = await subtle.digest("SHA-256", enc.encode("icd-coder|" + name.trim().toLowerCase())); return Buffer.from(h).toString("hex"); }
async function kek(pass, salt, iter){
  const base = await subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({name:"PBKDF2", hash:"SHA-256", salt, iterations:iter}, base, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
async function gcmEnc(key, data){ const iv = rnd(12); const ct = new Uint8Array(await subtle.encrypt({name:"AES-GCM", iv}, key, data)); const o = new Uint8Array(12 + ct.length); o.set(iv); o.set(ct, 12); return o; }
async function gcmDec(key, blob){ return new Uint8Array(await subtle.decrypt({name:"AES-GCM", iv:blob.slice(0,12)}, key, blob.slice(12))); }
const importK = raw => subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);

async function makeEntry(name, pass, role, rawK, K){
  const salt = rnd(16);
  const w = await gcmEnc(await kek(pass, salt, ITER), rawK);
  const m = await gcmEnc(K, enc.encode(JSON.stringify({name:name.trim(), role, created:new Date().toISOString().slice(0,10)})));
  return [await uidOf(name), {s:b64(salt), w:b64(w), m:b64(m)}];
}
function loadUsers(){ if (!existsSync(USERS)) throw new Error("找不到 coder/users.json，請先執行 init。"); return JSON.parse(readFileSync(USERS, "utf8")); }
async function unlock(U){
  const name = process.env.CODER_USER, pass = process.env.CODER_PASS;
  if (!name || !pass) throw new Error("請設定 CODER_USER 與 CODER_PASS。");
  const e = U.users[await uidOf(name)];
  if (!e) throw new Error("帳號或密碼錯誤。");
  let rawK;
  try { rawK = await gcmDec(await kek(pass, unb64(e.s), U.kdf.iter), unb64(e.w)); } catch { throw new Error("帳號或密碼錯誤。"); }
  const K = await importK(rawK);
  const me = JSON.parse(dec.decode(await gcmDec(K, unb64(e.m))));
  if (me.role !== "admin") throw new Error("此帳號不是管理員。");
  return {rawK, K};
}
function save(U){ writeFileSync(USERS, JSON.stringify(U, null, 1) + "\n"); }
function stamp(){ const d = new Date(), p = n => String(n).padStart(2, "0"); return `${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}`; }
async function sealFile(K, bytes){ const c = await gcmEnc(K, gzipSync(bytes, {level:9})); const o = new Uint8Array(MAGIC.length + c.length); o.set(MAGIC); o.set(c, MAGIC.length); return o; }

const [cmd, ...rest] = process.argv.slice(2);
const opt = k => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i+1] : undefined; };
try {
  if (cmd === "init"){
    if (existsSync(USERS)) throw new Error("coder/users.json 已存在；若要重建請先手動移除（會讓所有帳號失效）。");
    const name = opt("admin") || "admin", pass = process.env.CODER_PASS;
    if (!pass || pass.length < 8) throw new Error("請用 CODER_PASS 設定至少 8 碼的管理員密碼。");
    const rawK = rnd(32), K = await importK(rawK);
    const [id, e] = await makeEntry(name, pass, "admin", rawK, K);
    mkdirSync(OUT, {recursive:true});
    save({v:1, build:stamp(), kdf:{alg:"PBKDF2-SHA256", iter:ITER}, users:{[id]:e}});
    console.log(`已建立 coder/users.json，管理員帳號：${name}`);
  } else if (cmd === "build"){
    const src = opt("src"); if (!src) throw new Error("請用 --src 指定來源資料夾。");
    const U = loadUsers(), {K} = await unlock(U);
    mkdirSync(join(OUT, "data"), {recursive:true});
    writeFileSync(join(OUT, "app.bin"), await sealFile(K, readFileSync(join(src, "app.html"))));
    for (const d of DATA){
      const p = join(src, "data", d + ".json.gz");
      const raw = gunzipSync(readFileSync(p));
      JSON.parse(raw.toString("utf8"));
      writeFileSync(join(OUT, "data", d + ".bin"), await sealFile(K, raw));
    }
    U.build = stamp(); save(U);
    console.log(`已加密 app.bin 與 ${DATA.length} 個資料檔，版本 ${U.build}`);
  } else if (cmd === "adduser"){
    const name = rest[0], role = opt("role") || "user", pass = process.env.NEW_PASS;
    if (!name || name.startsWith("--")) throw new Error("請指定帳號名稱。");
    if (!pass || pass.length < 8) throw new Error("請用 NEW_PASS 設定至少 8 碼的密碼。");
    const U = loadUsers(), {rawK, K} = await unlock(U);
    const [id, e] = await makeEntry(name, pass, role === "admin" ? "admin" : "user", rawK, K);
    if (U.users[id]) throw new Error("此帳號已存在。");
    U.users[id] = e; save(U);
    console.log(`已新增帳號 ${name}（${role}）`);
  } else if (cmd === "list"){
    const U = loadUsers(), {K} = await unlock(U);
    for (const e of Object.values(U.users)){ const m = JSON.parse(dec.decode(await gcmDec(K, unb64(e.m)))); console.log(`${m.name}\t${m.role}\t${m.created}`); }
  } else {
    console.log("指令：init | build | adduser | list（說明見檔案開頭）");
  }
} catch (err){ console.error("錯誤：" + err.message); process.exit(1); }
