/*
 * نافذة الأسرة — الخادم على Cloudflare Workers
 * ------------------------------------------------
 * - الصفحات (public/) تُقدَّم مباشرة من شبكة Cloudflare دون تشغيل هذا الملف.
 * - هذا الملف يعالج مسارات /api/* فقط.
 * - التخزين: قاعدة بيانات D1 (مجانية، دون بطاقة) للمحتوى والملفات معًا.
 *   القيم الكبيرة والملفات تُقسَّم إلى أجزاء أصغر من حد الصف في D1 (٢ ميجابايت).
 * - كلمة مرور المالكة: سرّ (Secret) باسم ADMIN_PASSWORD في إعدادات الـ Worker فقط.
 * - الجلسة: ملف تعريف ارتباط HttpOnly موقّع بمفتاح سري يُولَّد ويُحفظ في القاعدة.
 * - كل عمليات الإضافة والتعديل والحذف والرفع والنشر تتحقق من الصلاحية هنا على الخادم.
 */

const COOKIE = "nafidha_admin";
const SESSION_DAYS = 14;
const MAX_CONTENT_BYTES = 3 * 1024 * 1024;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const CHUNK_BYTES = 1_500_000;          // أقل من حد الصف في D1 (2,000,000 بايت)
const TEXT_CHUNK_CHARS = 400_000;       // العربية حتى 3 بايت للحرف → 1.2MB كحد أقصى للجزء
const MAX_FAILS = 5, LOCK_MINUTES = 15, HISTORY_KEEP = 20;

const isZip = (b) => b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04;
const FILE_TYPES = {
  "image/jpeg": (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  "image/png": (b) => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47,
  "image/gif": (b) => b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38,
  "image/webp": (b) => b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50,
  "application/pdf": (b) => b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46,
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": isZip,
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": isZip,
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": isZip,
};
const INLINE_TYPES = new Set(["image/jpeg", "image/png", "image/gif", "image/webp", "application/pdf"]);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=31536000",
};
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...SECURITY_HEADERS, ...headers },
  });
}
const fail = (status, error, extra = {}) => json({ error, ...extra }, status);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = new TextEncoder();

/* ---------- أدوات التشفير (WebCrypto) ---------- */
async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function b64url(bytes) {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function safeEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
function randomHex(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return [...a].map((x) => x.toString(16).padStart(2, "0")).join(""); }

/* ---------- قاعدة البيانات ---------- */
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS kv_chunks (k TEXT NOT NULL, idx INTEGER NOT NULL, v TEXT NOT NULL, PRIMARY KEY (k, idx))"),
    db.prepare("CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, size INTEGER NOT NULL, chunks INTEGER NOT NULL, created_at TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS file_chunks (file_id TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (file_id, idx))"),
  ]);
  schemaReady = true;
}
async function getText(db, key) {
  const { results } = await db.prepare("SELECT v FROM kv_chunks WHERE k = ? ORDER BY idx").bind(key).all();
  if (!results || !results.length) return null;
  return results.map((r) => r.v).join("");
}
async function getJSON(db, key) { const t = await getText(db, key); return t == null ? null : JSON.parse(t); }
function putTextStmts(db, key, text) {
  const stmts = [db.prepare("DELETE FROM kv_chunks WHERE k = ?").bind(key)];
  for (let i = 0, n = 0; i < text.length || n === 0; i += TEXT_CHUNK_CHARS, n++) {
    stmts.push(db.prepare("INSERT INTO kv_chunks (k, idx, v) VALUES (?, ?, ?)").bind(key, n, text.slice(i, i + TEXT_CHUNK_CHARS)));
  }
  return stmts;
}
const putJSONStmts = (db, key, obj) => putTextStmts(db, key, JSON.stringify(obj));
const delStmt = (db, key) => db.prepare("DELETE FROM kv_chunks WHERE k = ?").bind(key);

/* ---------- الجلسات ---------- */
const passwordConfigured = (env) => String(env.ADMIN_PASSWORD || "").length >= 10;
async function passwordFingerprint(env) { return (await sha256hex("nafidha:" + String(env.ADMIN_PASSWORD || ""))).slice(0, 16); }
async function hmacKey(env) {
  let s = await getText(env.DB, "auth:secret");
  if (!s) {
    s = randomHex(48);
    await env.DB.prepare("INSERT OR IGNORE INTO kv_chunks (k, idx, v) VALUES ('auth:secret', 0, ?)").bind(s).run();
    s = await getText(env.DB, "auth:secret");
  }
  return crypto.subtle.importKey("raw", enc.encode(s), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function signToken(env, payload) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(body)));
  return body + "." + b64url(mac);
}
async function verifyToken(env, token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, mac] = token.split(".");
  let ok = false;
  try { ok = await crypto.subtle.verify("HMAC", await hmacKey(env), fromB64url(mac || ""), enc.encode(body)); } catch { return null; }
  if (!ok) return null;
  let p; try { p = JSON.parse(new TextDecoder().decode(fromB64url(body))); } catch { return null; }
  if (!p || typeof p.exp !== "number" || p.exp < Date.now() || p.fp !== (await passwordFingerprint(env))) return null;
  return p;
}
function readCookie(req, name) {
  for (const part of (req.headers.get("cookie") || "").split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}
async function isAdmin(req, env) { return passwordConfigured(env) && !!(await verifyToken(env, readCookie(req, COOKIE))); }
const sessionCookie = (value, maxAge) => `${COOKIE}=${value}; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
function sameOrigin(req) {
  if (req.headers.get("x-requested-with") !== "nafidha") return false;
  const origin = req.headers.get("origin");
  if (!origin) return true;
  try { return new URL(origin).host === new URL(req.url).host; } catch { return false; }
}
async function clientKey(req) {
  const ip = req.headers.get("cf-connecting-ip") || (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "unknown";
  return "fail:" + (await sha256hex(ip)).slice(0, 24);
}

async function login(req, env) {
  if (!passwordConfigured(env)) return fail(503, "not_configured");
  const db = env.DB, key = await clientKey(req);
  let rec = (await getJSON(db, key)) || { n: 0, until: 0 };
  if (rec.until && rec.until <= Date.now()) rec = { n: 0, until: 0 };
  if (rec.until > Date.now()) return fail(429, "locked", { minutes: Math.ceil((rec.until - Date.now()) / 60000) });
  let body; try { body = await req.json(); } catch { return fail(400, "bad_request"); }
  const given = await sha256hex(String((body && body.password) || ""));
  const real = await sha256hex(String(env.ADMIN_PASSWORD));
  if (!safeEqual(given, real)) {
    rec.n += 1;
    if (rec.n >= MAX_FAILS) rec = { n: 0, until: Date.now() + LOCK_MINUTES * 60000 };
    await db.batch(putJSONStmts(db, key, rec));
    await sleep(400);
    if (rec.until) return fail(429, "locked", { minutes: LOCK_MINUTES });
    return fail(401, "wrong_password", { left: MAX_FAILS - rec.n });
  }
  await delStmt(db, key).run();
  const token = await signToken(env, { exp: Date.now() + SESSION_DAYS * 864e5, fp: await passwordFingerprint(env), iat: Date.now() });
  return json({ ok: true }, 200, { "set-cookie": sessionCookie(token, SESSION_DAYS * 86400) });
}

/* ---------- المحتوى ---------- */
function cleanContent(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new Error("invalid");
  if (!Array.isArray(c.sections) || !c.site || typeof c.site !== "object") throw new Error("invalid");
  if (c.sections.length > 60) throw new Error("invalid");
  for (const s of c.sections) if (!s || typeof s !== "object" || typeof s.id !== "string" || !Array.isArray(s.items)) throw new Error("invalid");
  delete c.editorPin; delete c.recoveryHash; delete c.locked;
  return c;
}
async function readJSONBody(req, limit) {
  const text = await req.text();
  if (enc.encode(text).length > limit) { const e = new Error("too_large"); e.code = 413; throw e; }
  try { return JSON.parse(text); } catch { const e = new Error("bad_request"); e.code = 400; throw e; }
}
async function historyKeys(db) {
  const { results } = await db.prepare("SELECT DISTINCT k FROM kv_chunks WHERE k LIKE 'h:%' ORDER BY k DESC").all();
  return (results || []).map((r) => r.k);
}

/* ---------- الملفات ---------- */
async function upload(req, env) {
  const type = String(req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  const check = FILE_TYPES[type];
  if (!check) return fail(415, "unsupported_type");
  if (Number(req.headers.get("content-length") || 0) > MAX_FILE_BYTES) return fail(413, "too_large");
  const buf = new Uint8Array(await req.arrayBuffer());
  if (!buf.length) return fail(400, "empty");
  if (buf.length > MAX_FILE_BYTES) return fail(413, "too_large");
  if (!check(buf)) return fail(415, "content_mismatch");
  let name = "ملف";
  try { name = decodeURIComponent(req.headers.get("x-file-name") || "ملف"); } catch {}
  name = name.replace(/[\u0000-\u001f\\/:*?"<>|]+/g, " ").trim().slice(0, 120) || "ملف";
  const id = crypto.randomUUID(), db = env.DB;
  const n = Math.ceil(buf.length / CHUNK_BYTES);
  const stmts = [];
  for (let i = 0; i < n; i++) {
    stmts.push(db.prepare("INSERT INTO file_chunks (file_id, idx, data) VALUES (?, ?, ?)").bind(id, i, buf.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES)));
  }
  stmts.push(db.prepare("INSERT INTO files (id, name, type, size, chunks, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(id, name, type, buf.length, n, new Date().toISOString()));
  await db.batch(stmts);
  return json({ url: `/api/file/${id}`, name, type, size: buf.length });
}
async function serveFile(env, id) {
  if (!/^[0-9a-f-]{36}$/.test(id)) return fail(404, "not_found");
  const meta = await env.DB.prepare("SELECT name, type, size, chunks FROM files WHERE id = ?").bind(id).first();
  if (!meta) return fail(404, "not_found");
  const type = FILE_TYPES[meta.type] ? meta.type : "application/octet-stream";
  const db = env.DB;
  let i = 0;
  const stream = new ReadableStream({
    async pull(ctrl) {
      if (i >= meta.chunks) { ctrl.close(); return; }
      const row = await db.prepare("SELECT data FROM file_chunks WHERE file_id = ? AND idx = ?").bind(id, i++).first();
      if (!row) { ctrl.error(new Error("missing chunk")); return; }
      const d = row.data;
      ctrl.enqueue(d instanceof Uint8Array ? d : new Uint8Array(Array.isArray(d) ? d : d));
    },
  });
  const disp = INLINE_TYPES.has(type) ? "inline" : "attachment";
  return new Response(stream, {
    status: 200,
    headers: {
      "content-type": type,
      "content-length": String(meta.size),
      "cache-control": "public, max-age=31536000, immutable",
      "content-security-policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox",
      "content-disposition": `${disp}; filename*=UTF-8''${encodeURIComponent(meta.name || "file")}`,
      ...SECURITY_HEADERS,
    },
  });
}

/* ---------- الموجّه ---------- */
async function handleApi(req, env) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/+$/, "");
  const method = req.method.toUpperCase();
  if (!env.DB) return fail(503, "no_database");
  await ensureSchema(env.DB);
  if (method !== "GET" && method !== "HEAD" && !sameOrigin(req)) return fail(403, "forbidden");

  /* عامة */
  if (path === "session" && method === "GET") return json({ admin: await isAdmin(req, env), configured: passwordConfigured(env) });
  if (path === "login" && method === "POST") return login(req, env);
  if (path === "logout" && method === "POST") return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  if (path === "content" && method === "GET") {
    const pub = await getJSON(env.DB, "published");
    return json(pub || { content: null, publishedAt: null }, 200, { "cache-control": "public, max-age=0, must-revalidate" });
  }
  if (path.startsWith("file/") && method === "GET") return serveFile(env, path.slice(5));

  /* للمالكة فقط — التحقق على الخادم */
  if (!(await isAdmin(req, env))) return fail(401, "unauthorized");
  const db = env.DB;

  if (path === "draft" && method === "GET") {
    const [draft, pub] = await Promise.all([getJSON(db, "draft"), getJSON(db, "published")]);
    return json({
      content: (draft && draft.content) || (pub && pub.content) || null,
      savedAt: (draft && draft.savedAt) || null,
      publishedAt: (pub && pub.publishedAt) || null,
      hasDraft: !!draft,
    });
  }
  if (path === "draft" && method === "PUT") {
    const body = await readJSONBody(req, MAX_CONTENT_BYTES);
    const content = cleanContent(body && body.content);
    const current = await getJSON(db, "draft");
    if (current && !body.force && (body.baseSavedAt || null) !== current.savedAt) return fail(409, "conflict", { savedAt: current.savedAt });
    const savedAt = new Date().toISOString();
    await db.batch(putJSONStmts(db, "draft", { content, savedAt }));
    return json({ ok: true, savedAt });
  }
  if (path === "draft" && method === "DELETE") { await delStmt(db, "draft").run(); return json({ ok: true }); }
  if (path === "publish" && method === "POST") {
    const draftText = await getText(db, "draft");
    if (!draftText) return fail(400, "nothing_to_publish");
    const draft = JSON.parse(draftText);
    const pubText = await getText(db, "published");
    const publishedAt = new Date().toISOString();
    const stmts = [];
    if (pubText) { const old = JSON.parse(pubText); if (old.publishedAt) stmts.push(...putTextStmts(db, "h:" + old.publishedAt, pubText)); }
    stmts.push(...putJSONStmts(db, "published", { content: draft.content, publishedAt }), delStmt(db, "draft"));
    await db.batch(stmts);   // عملية واحدة: إما تنجح كلها أو لا يتغير شيء
    const keys = await historyKeys(db);
    if (keys.length > HISTORY_KEEP) await db.batch(keys.slice(HISTORY_KEEP).map((k) => delStmt(db, k)));
    return json({ ok: true, publishedAt });
  }
  if (path === "history" && method === "GET") {
    return json({ items: (await historyKeys(db)).map((k) => ({ key: k, publishedAt: k.slice(2) })) });
  }
  if (path === "restore" && method === "POST") {
    const body = await readJSONBody(req, 4096);
    const key = String((body && body.key) || "");
    if (!/^h:[0-9TZ:.\-]+$/.test(key)) return fail(400, "bad_request");
    const old = await getJSON(db, key);
    if (!old) return fail(404, "not_found");
    const savedAt = new Date().toISOString();
    await db.batch(putJSONStmts(db, "draft", { content: old.content, savedAt }));
    return json({ ok: true, savedAt, content: old.content });
  }
  if (path === "upload" && method === "POST") return upload(req, env);
  return fail(404, "not_found");
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      try { return await handleApi(req, env); }
      catch (e) {
        if (e && e.code) return fail(e.code, e.message);
        if (e && e.message === "invalid") return fail(400, "invalid_content");
        console.error(e);
        return fail(500, "server_error");
      }
    }
    if (url.pathname === "/admin") return Response.redirect(url.origin + "/admin/" + url.search, 308);
    return new Response("الصفحة غير موجودة — نافذة الأسرة", { status: 404, headers: { "content-type": "text/plain; charset=utf-8", ...SECURITY_HEADERS } });
  },
};
