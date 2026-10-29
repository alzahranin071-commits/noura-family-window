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
const GLOBAL_MAX_FAILS = 30, GLOBAL_WINDOW_MIN = 60;   // حد عام لكل المحاولات الخاطئة من أي جهاز
const MAX_LOGIN_BODY = 2048, LOG_KEEP = 60, FILE_GRACE_MS = 60 * 60 * 1000;
const HEX_COLOR = /^#[0-9a-f]{6}$/i, FONT_KEYS = new Set(["Tajawal", "Cairo", "system"]);

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
async function hmacHex(env, text) {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(text)));
  return [...mac].map((x) => x.toString(16).padStart(2, "0")).join("");
}
/* بصمة كلمة المرور داخل الجلسة: HMAC بالمفتاح السري، فلا يمكن تخمين كلمة المرور منها خارج الخادم */
async function passwordFingerprint(env) { return (await hmacHex(env, "pw:" + String(env.ADMIN_PASSWORD || ""))).slice(0, 32); }
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
  if (!p || typeof p.exp !== "number" || p.exp < Date.now() || typeof p.sid !== "string" || p.fp !== (await passwordFingerprint(env))) return null;
  /* الجلسة يجب أن تكون مسجّلة على الخادم؛ الخروج يحذفها فتبطل فورًا */
  const row = await env.DB.prepare("SELECT 1 AS ok FROM kv_chunks WHERE k = ? LIMIT 1").bind("sess:" + p.sid).first();
  if (!row) return null;
  return p;
}
function readCookie(req, name) {
  for (const part of (req.headers.get("cookie") || "").split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}
async function currentSession(req, env) { return passwordConfigured(env) ? await verifyToken(env, readCookie(req, COOKIE)) : null; }
async function isAdmin(req, env) { return !!(await currentSession(req, env)); }
/* سجل أمان مختصر (آخر ٦٠ حدثًا): الوقت والحدث والدولة فقط، دون عناوين IP */
async function logEvent(env, req, e) {
  try {
    const log = (await getJSON(env.DB, "log")) || [];
    log.unshift({ t: new Date().toISOString(), e, c: (req.cf && req.cf.country) || req.headers.get("cf-ipcountry") || "" });
    await env.DB.batch(putJSONStmts(env.DB, "log", log.slice(0, LOG_KEEP)));
  } catch (err) { console.warn("log failed", err && err.message); }
}
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
  if (Number(req.headers.get("content-length") || 0) > MAX_LOGIN_BODY) return fail(413, "too_large");
  const db = env.DB, key = await clientKey(req), now = Date.now();
  /* حد عام: يمنع التخمين الموزّع من أجهزة كثيرة */
  let glob = (await getJSON(db, "fail:global")) || { n: 0, start: now };
  if (now - glob.start > GLOBAL_WINDOW_MIN * 60000) glob = { n: 0, start: now };
  if (glob.n >= GLOBAL_MAX_FAILS) return fail(429, "locked", { minutes: Math.ceil((glob.start + GLOBAL_WINDOW_MIN * 60000 - now) / 60000) });
  let rec = (await getJSON(db, key)) || { n: 0, until: 0 };
  if (rec.until && rec.until <= now) rec = { n: 0, until: 0 };
  if (rec.until > now) return fail(429, "locked", { minutes: Math.ceil((rec.until - now) / 60000) });
  const raw = await req.text();
  if (enc.encode(raw).length > MAX_LOGIN_BODY) return fail(413, "too_large");
  let body; try { body = JSON.parse(raw); } catch { return fail(400, "bad_request"); }
  const given = await sha256hex(String((body && body.password) || ""));
  const real = await sha256hex(String(env.ADMIN_PASSWORD));
  if (!safeEqual(given, real)) {
    rec.n += 1; glob.n += 1;
    if (rec.n >= MAX_FAILS) rec = { n: 0, until: now + LOCK_MINUTES * 60000 };
    await db.batch([...putJSONStmts(db, key, rec), ...putJSONStmts(db, "fail:global", glob)]);
    await logEvent(env, req, rec.until ? "login_locked" : "login_fail");
    await sleep(400);
    if (rec.until) return fail(429, "locked", { minutes: LOCK_MINUTES });
    return fail(401, "wrong_password", { left: MAX_FAILS - rec.n });
  }
  const sid = randomHex(24), exp = now + SESSION_DAYS * 864e5;
  /* تنظيف الجلسات المنتهية ثم تسجيل الجلسة الجديدة */
  const { results } = await db.prepare("SELECT k, v FROM kv_chunks WHERE k LIKE 'sess:%'").all();
  const expired = (results || []).filter((r) => { try { return JSON.parse(r.v).exp < now; } catch { return true; } }).map((r) => delStmt(db, r.k));
  await db.batch([delStmt(db, key), ...expired, ...putJSONStmts(db, "sess:" + sid, { exp, iat: now })]);
  const token = await signToken(env, { sid, exp, fp: await passwordFingerprint(env), iat: now });
  await logEvent(env, req, "login_ok");
  return json({ ok: true }, 200, { "set-cookie": sessionCookie(token, SESSION_DAYS * 86400) });
}

/* ---------- المحتوى ---------- */
function cleanContent(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new Error("invalid");
  if (!Array.isArray(c.sections) || !c.site || typeof c.site !== "object") throw new Error("invalid");
  if (c.sections.length > 60) throw new Error("invalid");
  for (const s of c.sections) if (!s || typeof s !== "object" || typeof s.id !== "string" || !Array.isArray(s.items)) throw new Error("invalid");
  delete c.editorPin; delete c.recoveryHash; delete c.locked;
  /* الألوان والخطوط: قيم محددة فقط، لمنع حقن CSS */
  if (c.theme && typeof c.theme === "object") {
    const t = c.theme;
    for (const k of ["mauve", "rose", "sky"]) if (k in t && !HEX_COLOR.test(String(t[k]))) delete t[k];
    for (const k of ["font", "headFont"]) if (k in t && !FONT_KEYS.has(t[k])) delete t[k];
    if ("scale" in t) { const n = Number(t.scale); if (!(n >= 13 && n <= 24)) delete t.scale; else t.scale = n; }
  } else delete c.theme;
  return c;
}
/* النسخة العامة: تُحذف منها الأقسام والعناصر والإعلانات المخفية قبل وصولها للزوار */
function publicView(content) {
  const c = JSON.parse(JSON.stringify(content));
  c.sections = (c.sections || []).filter((s) => s.type === "home" || !s.hidden);
  for (const s of c.sections) s.items = (s.items || []).filter((it) => it && !it.hidden);
  if (Array.isArray(c.announcements)) c.announcements = c.announcements.filter((a) => a && !a.hidden);
  return c;
}
const fileRefs = (text) => new Set([...String(text || "").matchAll(/\/api\/file\/([0-9a-f-]{36})/g)].map((m) => m[1]));
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
  if (path === "logout" && method === "POST") {
    const s = await currentSession(req, env);
    if (s) { await delStmt(env.DB, "sess:" + s.sid).run(); await logEvent(env, req, "logout"); }
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }
  if (path === "content" && method === "GET") {
    let out = await getText(env.DB, "public");
    if (!out) { const pub = await getJSON(env.DB, "published"); out = JSON.stringify(pub ? { content: publicView(pub.content), publishedAt: pub.publishedAt } : { content: null, publishedAt: null }); }
    return new Response(out, { status: 200, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=0, must-revalidate", ...SECURITY_HEADERS } });
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
    stmts.push(...putJSONStmts(db, "published", { content: draft.content, publishedAt }),
      ...putJSONStmts(db, "public", { content: publicView(draft.content), publishedAt }), delStmt(db, "draft"));
    await db.batch(stmts);   // عملية واحدة: إما تنجح كلها أو لا يتغير شيء
    const keys = await historyKeys(db);
    if (keys.length > HISTORY_KEEP) await db.batch(keys.slice(HISTORY_KEEP).map((k) => delStmt(db, k)));
    await logEvent(env, req, "publish");
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
    await logEvent(env, req, "restore");
    return json({ ok: true, savedAt, content: old.content });
  }
  if (path === "upload" && method === "POST") { const r = await upload(req, env); if (r.ok) await logEvent(env, req, "upload"); return r; }
  if (path === "logout-all" && method === "POST") {
    await db.prepare("DELETE FROM kv_chunks WHERE k LIKE 'sess:%'").run();
    await logEvent(env, req, "logout_all");
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }
  if (path === "log" && method === "GET") return json({ items: (await getJSON(db, "log")) || [] });
  if (path === "files" && method === "GET") {
    const r = await db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM files").first();
    return json({ count: r.n, bytes: r.bytes });
  }
  if (path === "files/cleanup" && method === "POST") {
    /* يحذف فقط الملفات غير المستخدمة في المسودة أو المنشور أو أي نسخة سابقة، والتي مضى على رفعها ساعة */
    const used = new Set();
    for (const k of ["draft", "published", ...(await historyKeys(db))]) for (const id of fileRefs(await getText(db, k))) used.add(id);
    const { results } = await db.prepare("SELECT id, size, created_at FROM files").all();
    const cutoff = Date.now() - Number(env.FILE_GRACE_MS ?? FILE_GRACE_MS);
    const victims = (results || []).filter((f) => !used.has(f.id) && Date.parse(f.created_at) < cutoff);
    for (let i = 0; i < victims.length; i += 20) {
      const part = victims.slice(i, i + 20);
      await db.batch(part.flatMap((f) => [db.prepare("DELETE FROM file_chunks WHERE file_id = ?").bind(f.id), db.prepare("DELETE FROM files WHERE id = ?").bind(f.id)]));
    }
    if (victims.length) await logEvent(env, req, "files_cleanup");
    return json({ ok: true, deleted: victims.length, bytes: victims.reduce((a, f) => a + f.size, 0) });
  }
  return fail(404, "not_found");
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.protocol === "http:" && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(url.hostname)) {
      url.protocol = "https:"; return Response.redirect(url.toString(), 308);
    }
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      try { return await handleApi(req, env); }
      catch (e) {
        if (e && Number.isInteger(e.code) && e.code >= 400 && e.code < 600) return fail(e.code, e.message);
        if (e && e.message === "invalid") return fail(400, "invalid_content");
        console.error(e);
        return fail(500, "server_error");
      }
    }
    if (url.pathname === "/admin") return Response.redirect(url.origin + "/admin/" + url.search, 308);
    return new Response("الصفحة غير موجودة — نافذة الأسرة", { status: 404, headers: { "content-type": "text/plain; charset=utf-8", ...SECURITY_HEADERS } });
  },
};
