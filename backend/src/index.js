// The account service: the apps sign in and report use here, users see and
// change their account on the website, the administrator manages everyone.
import {
  DAY, accountOf, checkPassword, checkUsername, hashPassword, randomPassword, rollPeriod, safeEqual, sign, tag, verify, verifyPassword,
} from "./lib.js";

const SESSION = 30 * DAY; // an app or browser session
const ADMIN_SESSION = 8 * 3600;
const MAX_BODY = 8 * 1024;

const DEFAULTS = {
  signup_open: "0",
  default_quota_bytes: String(5 * 1024 ** 3),
  default_max_seconds: "0",
  default_valid_days: "0",
  default_reset_days: "0", // allowances renew only when the admin recharges them
  download_windows: "",
  download_android: "",
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  });

const now = () => Math.floor(Date.now() / 1000);

function randomUsernameSuffix() {
  const range = 1_000_000;
  const limit = Math.floor(0x1_0000_0000 / range) * range;
  const value = new Uint32Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0] >= limit);
  return String(value[0] % range).padStart(6, "0");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/list/")) return mirror(url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    try {
      if (!env.TOKEN_SECRET || env.TOKEN_SECRET.length < 24) throw new HttpError(503, "The service is not configured yet.");
      return await route(request, env, url);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e && e.stack ? e.stack : e);
      return json({ error: "Something went wrong. Try again." }, 500);
    }
  },
};

async function route(request, env, url) {
  const path = url.pathname.replace(/^\/api\/v1\/?/, "");
  const key = `${request.method} ${path}`;
  const admin = path.match(/^admin\/users\/(\d+)(?:\/([a-z-]+))?$/);

  switch (key) {
    case "GET public": return publicInfo(env);
    case "POST login": return login(request, env);
    case "POST signup": return signup(request, env);
    case "GET me": return me(request, env);
    case "POST usage": return usage(request, env);
    case "POST password": return changePassword(request, env);
    case "POST admin/login": return adminLogin(request, env);
    case "GET admin/stats": return adminStats(request, env);
    case "GET admin/users": return adminList(request, env, url);
    case "POST admin/users": return adminCreate(request, env);
    case "POST admin/users/bulk": return adminBulk(request, env);
    case "GET admin/settings": return adminSettings(request, env);
    case "PUT admin/settings": return adminSaveSettings(request, env);
    case "POST stats": return crowdReport(request, env);
    case "GET stats": return crowdSummary(request, env, url);
  }
  if (admin) {
    const id = Number(admin[1]);
    if (request.method === "PATCH" && !admin[2]) return adminUpdate(request, env, id);
    if (request.method === "DELETE" && !admin[2]) return adminDelete(request, env, id);
  }
  throw new HttpError(404, "Not found.");
}

// ---------- Helpers ----------

async function body(request) {
  const text = await request.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "Request too large.");
  try {
    const v = text ? JSON.parse(text) : {};
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
  } catch {}
  throw new HttpError(400, "Bad request.");
}

async function settings(env) {
  const out = { ...DEFAULTS };
  const { results } = await env.DB.prepare("SELECT key, value FROM settings").all();
  for (const r of results) if (r.key in DEFAULTS) out[r.key] = r.value;
  return out;
}

const clientTag = (request, env) => tag(env.TOKEN_SECRET, request.headers.get("CF-Connecting-IP") || "unknown");

/** True when `key` has used up `max` attempts within the window. */
async function blocked(env, key, max, window) {
  const row = await env.DB.prepare("SELECT count, since FROM attempts WHERE key = ?1").bind(key).first();
  return !!row && now() - row.since <= window && row.count >= max;
}

async function count(env, key, window) {
  const t = now();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO attempts (key, count, since) VALUES (?1, 1, ?2)
       ON CONFLICT (key) DO UPDATE SET
         count = CASE WHEN ?2 - since > ?3 THEN 1 ELSE count + 1 END,
         since = CASE WHEN ?2 - since > ?3 THEN ?2 ELSE since END`,
    ).bind(key, t, window),
    // Old entries are dropped as new ones come in.
    env.DB.prepare("DELETE FROM attempts WHERE since < ?1").bind(t - DAY),
  ]);
}

const forget = (env, key) => env.DB.prepare("DELETE FROM attempts WHERE key = ?1").bind(key).run();

const tooMany = () => new HttpError(429, "Too many attempts. Wait a few minutes and try again.");

async function userByName(env, name) {
  return env.DB.prepare("SELECT * FROM users WHERE username = ?1").bind(String(name).trim().toLowerCase()).first();
}

const userById = (env, id) => env.DB.prepare("SELECT * FROM users WHERE id = ?1").bind(id).first();

const session = (env, user, ttl = SESSION) =>
  sign({ u: user.id, v: user.token_version, exp: now() + ttl }, env.TOKEN_SECRET);

async function authUser(request, env) {
  const m = /^Bearer (.+)$/.exec(request.headers.get("Authorization") || "");
  const p = m && (await verify(m[1], env.TOKEN_SECRET, now()));
  const user = p && p.u && (await userById(env, p.u));
  if (!user || user.token_version !== p.v) throw new HttpError(401, "Sign in again.");
  return { user, token: m[1], payload: p };
}

async function authAdmin(request, env) {
  const m = /^Bearer (.+)$/.exec(request.headers.get("Authorization") || "");
  const p = m && (await verify(m[1], env.TOKEN_SECRET, now()));
  if (!p || p.adm !== 1) throw new HttpError(401, "Sign in again.");
}

// A fixed hash to spend the same time on an unknown username as on a known one.
const DUMMY = "pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ---------- Public ----------

async function publicInfo(env) {
  const s = await settings(env);
  return json({
    name: env.SITE_NAME || "Albatross",
    company: env.COMPANY_NAME || "",
    address: env.COMPANY_ADDRESS || "",
    contact: env.CONTACT_EMAIL || "",
    signup_open: s.signup_open === "1",
    turnstile_sitekey: env.TURNSTILE_SITEKEY || "",
    downloads: { windows: s.download_windows, android: s.download_android },
  });
}

// ---------- Users ----------

async function login(request, env) {
  const { username, password } = await body(request);
  if (typeof username !== "string" || typeof password !== "string" || password.length > 200 || username.length > 64) {
    throw new HttpError(400, "Enter your username and password.");
  }
  const name = username.trim().toLowerCase();
  const ip = "login:ip:" + (await clientTag(request, env));
  const who = "login:user:" + name;
  if ((await blocked(env, ip, 40, 900)) || (await blocked(env, who, 8, 900))) throw tooMany();

  const user = await userByName(env, name);
  const ok = await verifyPassword(password, user ? user.pass_hash : DUMMY);
  if (!user || !ok) {
    await count(env, ip, 900);
    await count(env, who, 900);
    throw new HttpError(401, "Wrong username or password.");
  }
  await forget(env, who);
  return json({ token: await session(env, user), account: accountOf(user, now()) });
}

async function verifyTurnstile(request, env, token) {
  if (!env.TURNSTILE_SECRET) return;
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET);
  form.append("response", String(token || ""));
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.append("remoteip", ip);
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  const out = await res.json().catch(() => ({}));
  if (!out.success) throw new HttpError(400, "Verification failed. Reload the page and try again.");
}

async function signup(request, env) {
  const s = await settings(env);
  if (s.signup_open !== "1") throw new HttpError(403, "Sign-ups are closed.");
  const { username, password, turnstile } = await body(request);
  const ip = "signup:ip:" + (await clientTag(request, env));
  if (await blocked(env, ip, 5, 3600)) throw tooMany();
  await verifyTurnstile(request, env, turnstile);
  if (!checkUsername(username)) throw new HttpError(400, "Choose a username of 3 to 32 letters, digits, dots, dashes or underscores.");
  if (!checkPassword(password)) throw new HttpError(400, "Choose a password of at least 8 characters.");

  const t = now();
  const days = Number(s.default_valid_days);
  try {
    await env.DB.prepare(
      `INSERT INTO users (username, pass_hash, created_at, quota_bytes, max_seconds, expires_at, reset_days, period_start)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?3)`,
    ).bind(username.trim().toLowerCase(), await hashPassword(password), t, Number(s.default_quota_bytes), Number(s.default_max_seconds),
      days > 0 ? t + days * DAY : 0, Number(s.default_reset_days)).run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e))) throw new HttpError(409, "That username is taken.");
    throw e;
  }
  await count(env, ip, 3600);
  const user = await userByName(env, username);
  return json({ token: await session(env, user), account: accountOf(user, t) }, 201);
}

async function me(request, env) {
  const { user } = await authUser(request, env);
  return json({ account: accountOf(user, now()), created_at: user.created_at, total_bytes: user.total_bytes, total_seconds: user.total_seconds });
}

const MAX_BYTES_PER_REPORT = 100 * 1024 ** 3;
const MAX_SECONDS_PER_REPORT = 7 * DAY;

/** The app reports data and time used since its last report and learns whether the user may go on. */
async function usage(request, env) {
  const { user, token, payload } = await authUser(request, env);
  const b = await body(request);
  const bytes = b.bytes ?? 0;
  const seconds = b.seconds ?? 0;
  if (!Number.isSafeInteger(bytes) || !Number.isSafeInteger(seconds) || bytes < 0 || seconds < 0 ||
      bytes > MAX_BYTES_PER_REPORT || seconds > MAX_SECONDS_PER_REPORT) {
    throw new HttpError(400, "Bad usage report.");
  }
  const t = now();
  const p = rollPeriod(user, t);
  if (p.rolled) {
    // A new period: only one of several devices reporting at once wins this update.
    await env.DB.prepare("UPDATE users SET period_start = ?1, used_bytes = 0, used_seconds = 0 WHERE id = ?2 AND period_start = ?3")
      .bind(p.period_start, user.id, user.period_start).run();
  }
  await env.DB.prepare(
    `UPDATE users SET used_bytes = used_bytes + ?1, used_seconds = used_seconds + ?2,
       total_bytes = total_bytes + ?1, total_seconds = total_seconds + ?2, last_seen = ?3 WHERE id = ?4`,
  ).bind(bytes, seconds, t, user.id).run();
  const fresh = await userById(env, user.id);
  // Sessions are renewed while they are in use.
  const renewed = payload.exp - t < SESSION / 2 ? await session(env, fresh) : token;
  return json({ token: renewed, account: accountOf(fresh, t) });
}

async function changePassword(request, env) {
  const { user } = await authUser(request, env);
  const { old_password, new_password } = await body(request);
  const key = "login:user:" + user.username.toLowerCase();
  if (await blocked(env, key, 8, 900)) throw tooMany();
  if (typeof old_password !== "string" || !(await verifyPassword(old_password, user.pass_hash))) {
    await count(env, key, 900);
    throw new HttpError(403, "The current password is wrong.");
  }
  if (!checkPassword(new_password)) throw new HttpError(400, "Choose a password of at least 8 characters.");
  // Raising the version signs out every other device.
  await env.DB.prepare("UPDATE users SET pass_hash = ?1, token_version = token_version + 1 WHERE id = ?2")
    .bind(await hashPassword(new_password), user.id).run();
  const fresh = await userById(env, user.id);
  return json({ token: await session(env, fresh), account: accountOf(fresh, now()) });
}

// ---------- Administrator ----------

async function adminLogin(request, env) {
  if (!env.ADMIN_USER || !env.ADMIN_PASSWORD) throw new HttpError(503, "The administrator account is not set up.");
  const { username, password } = await body(request);
  const ip = "admin:ip:" + (await clientTag(request, env));
  if (await blocked(env, ip, 10, 900)) throw tooMany();
  // Both checks always run, so the answer does not say which one was wrong.
  const [a, b] = await Promise.all([safeEqual(username ?? "", env.ADMIN_USER), safeEqual(password ?? "", env.ADMIN_PASSWORD)]);
  if (!(a && b)) {
    await count(env, ip, 900);
    throw new HttpError(401, "Wrong username or password.");
  }
  await forget(env, ip);
  return json({ token: await sign({ adm: 1, exp: now() + ADMIN_SESSION }, env.TOKEN_SECRET) });
}

/** A user as the administrator sees them. */
function adminView(u, t) {
  const a = accountOf(u, t);
  return {
    id: u.id, username: u.username, created_at: u.created_at, disabled: !!u.disabled, note: u.note,
    quota_bytes: u.quota_bytes, max_seconds: u.max_seconds, expires_at: u.expires_at, reset_days: u.reset_days,
    used_bytes: a.used_bytes, used_seconds: a.used_seconds, resets_at: a.resets_at, status: a.allowed ? "active" : a.reason,
    total_bytes: u.total_bytes, total_seconds: u.total_seconds, last_seen: u.last_seen,
  };
}

async function adminStats(request, env) {
  await authAdmin(request, env);
  const t = now();
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS users, COALESCE(SUM(disabled), 0) AS disabled,
       COALESCE(SUM(CASE WHEN last_seen > ?1 THEN 1 ELSE 0 END), 0) AS active_day,
       COALESCE(SUM(CASE WHEN last_seen > ?2 THEN 1 ELSE 0 END), 0) AS active_month,
       COALESCE(SUM(total_bytes), 0) AS total_bytes, COALESCE(SUM(total_seconds), 0) AS total_seconds FROM users`,
  ).bind(t - DAY, t - 30 * DAY).first();
  return json(row);
}

async function adminList(request, env, url) {
  await authAdmin(request, env);
  const q = (url.searchParams.get("q") || "").trim().toLowerCase().replace(/[\\%_]/g, "\\$&");
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 25, 1), 100);
  const offset = Math.max(Number(url.searchParams.get("offset")) || 0, 0);
  const like = `%${q}%`;
  const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE username LIKE ?1 ESCAPE '\\' OR note LIKE ?1 ESCAPE '\\'").bind(like).first();
  const { results } = await env.DB.prepare(
    "SELECT * FROM users WHERE username LIKE ?1 ESCAPE '\\' OR note LIKE ?1 ESCAPE '\\' ORDER BY id DESC LIMIT ?2 OFFSET ?3",
  ).bind(like, limit, offset).all();
  const t = now();
  return json({ total: total.n, users: results.map((u) => adminView(u, t)) });
}

/** Limits from a request, as the values stored. */
function limitsFrom(b, base = {}) {
  const out = {};
  const num = (k, max) => {
    if (b[k] === undefined) return;
    const v = Number(b[k]);
    if (!Number.isSafeInteger(v) || v < 0 || v > max) throw new HttpError(400, `Bad value for ${k}.`);
    out[k] = v;
  };
  num("quota_bytes", 1024 ** 5);
  num("max_seconds", 10 * 365 * DAY);
  num("expires_at", 4102444800);
  num("reset_days", 3650);
  if (b.note !== undefined) out.note = String(b.note).slice(0, 200);
  return { ...base, ...out };
}

async function createUser(env, name, password, limits, t) {
  if (!checkUsername(name)) throw new HttpError(400, "Usernames have 3 to 32 letters, digits, dots, dashes or underscores.");
  try {
    await env.DB.prepare(
      `INSERT INTO users (username, pass_hash, created_at, quota_bytes, max_seconds, expires_at, reset_days, period_start, note)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?3, ?8)`,
    ).bind(name.trim().toLowerCase(), await hashPassword(password), t, limits.quota_bytes ?? 0, limits.max_seconds ?? 0,
      limits.expires_at ?? 0, limits.reset_days ?? 0, limits.note ?? "").run();
  } catch (e) {
    if (/UNIQUE/i.test(String(e))) throw new HttpError(409, `The username "${name}" is taken.`);
    throw e;
  }
}

async function adminCreate(request, env) {
  await authAdmin(request, env);
  const b = await body(request);
  const password = b.password ? String(b.password) : randomPassword();
  if (!checkPassword(password)) throw new HttpError(400, "A password has at least 8 characters.");
  await createUser(env, String(b.username || ""), password, limitsFrom(b), now());
  const user = await userByName(env, b.username);
  return json({ user: adminView(user, now()), password }, 201);
}

async function adminBulk(request, env) {
  await authAdmin(request, env);
  const b = await body(request);
  const n = Number(b.count);
  const prefix = String(b.prefix || "user").toLowerCase();
  if (!Number.isInteger(n) || n < 1 || n > 200) throw new HttpError(400, "Create between 1 and 200 users at a time.");
  if (!/^[a-z0-9][a-z0-9._-]{0,20}$/.test(prefix)) throw new HttpError(400, "The prefix has up to 21 letters, digits, dots, dashes or underscores.");
  const limits = limitsFrom(b);
  const made = [];
  for (let i = 0; i < n; i++) {
    for (let tries = 0; tries < 5; tries++) {
      const name = `${prefix}${randomUsernameSuffix()}`;
      const password = randomPassword();
      try {
        await createUser(env, name, password, limits, now());
        made.push({ username: name, password });
        break;
      } catch (e) {
        if (!(e instanceof HttpError && e.status === 409)) throw e;
      }
    }
  }
  return json({ users: made }, 201);
}

async function adminUpdate(request, env, id) {
  await authAdmin(request, env);
  const user = await userById(env, id);
  if (!user) throw new HttpError(404, "No such user.");
  const b = await body(request);
  const limits = limitsFrom(b);
  const sets = [];
  const vals = [];
  const set = (col, v) => { vals.push(v); sets.push(`${col} = ?${vals.length}`); };
  for (const [k, v] of Object.entries(limits)) set(k, v);
  if (b.disabled !== undefined) set("disabled", b.disabled ? 1 : 0);
  if (b.password !== undefined) {
    if (!checkPassword(b.password)) throw new HttpError(400, "A password has at least 8 characters.");
    set("pass_hash", await hashPassword(String(b.password)));
    sets.push("token_version = token_version + 1");
  }
  if (b.reset_usage) {
    set("used_bytes", 0);
    set("used_seconds", 0);
    set("period_start", now());
  }
  if (b.sign_out) sets.push("token_version = token_version + 1");
  if (!sets.length) throw new HttpError(400, "Nothing to change.");
  vals.push(id);
  await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?${vals.length}`).bind(...vals).run();
  return json({ user: adminView(await userById(env, id), now()) });
}

async function adminDelete(request, env, id) {
  await authAdmin(request, env);
  const r = await env.DB.prepare("DELETE FROM users WHERE id = ?1").bind(id).run();
  if (!r.meta.changes) throw new HttpError(404, "No such user.");
  return json({ ok: true });
}

async function adminSettings(request, env) {
  await authAdmin(request, env);
  return json(await settings(env));
}

async function adminSaveSettings(request, env) {
  await authAdmin(request, env);
  const b = await body(request);
  const stmts = [];
  for (const k of Object.keys(DEFAULTS)) {
    if (b[k] === undefined) continue;
    let v = String(b[k]).slice(0, 500);
    if (k === "signup_open") v = b[k] === true || v === "1" ? "1" : "0";
    else if (k.startsWith("download_")) {
      if (v && !/^https:\/\//.test(v)) throw new HttpError(400, "Download links must start with https://");
    } else if (!/^\d{1,16}$/.test(v)) throw new HttpError(400, `Bad value for ${k}.`);
    stmts.push(env.DB.prepare("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2").bind(k, v));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json(await settings(env));
}

// ---------- Crowd learning ----------
//
// Apps whose users turned on "Share anonymous connection stats" report, a
// few times a day, how many tests of each kind of connection passed on their
// operator's network. A new install on that operator then starts with the
// order that works there. Reports carry no device or server details, and no
// address is stored: the rate limit keeps only a keyed hash of it, for a day.

const CROWD_KINDS = { proto: 16, style: 32, hello: 16, port: 8 };
const CROWD_DAYS = 14;
// An operator's numbers are published only once this many reports came in,
// so no one report can be told apart.
const CROWD_MIN_REPORTS = 3;

async function crowdReport(request, env) {
  const b = await body(request);
  const asn = b.asn;
  if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) throw new HttpError(400, "Bad request.");
  const rows = [];
  for (const [kind, size] of Object.entries(CROWD_KINDS)) {
    const list = b[kind] ?? [];
    if (!Array.isArray(list) || list.length > size) throw new HttpError(400, "Bad request.");
    for (const r of list) {
      if (!Array.isArray(r) || r.length !== 3 || !r.every(Number.isInteger)) throw new HttpError(400, "Bad request.");
      const [code, ok, n] = r;
      if (code < 0 || code >= size || n < 1 || ok < 0 || ok > n) throw new HttpError(400, "Bad request.");
      // One report counts for at most 500 tests of a kind.
      const scale = Math.min(1, 500 / n);
      rows.push([kind, code, Math.round(ok * scale), Math.round(n * scale)]);
    }
  }
  const limit = "stats:" + (await clientTag(request, env));
  if (await blocked(env, limit, 6, DAY)) throw new HttpError(429, "Too many reports.");
  await count(env, limit, DAY);
  const day = Math.floor(now() / DAY);
  const stmts = rows.map(([kind, code, ok, n]) =>
    env.DB.prepare(
      `INSERT INTO crowd (asn, kind, code, day, ok, n) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT (asn, kind, code, day) DO UPDATE SET ok = ok + ?5, n = n + ?6`,
    ).bind(asn, kind, code, day, ok, n));
  stmts.push(
    env.DB.prepare(
      `INSERT INTO crowd_reports (asn, day, reports) VALUES (?1, ?2, 1)
       ON CONFLICT (asn, day) DO UPDATE SET reports = reports + 1`,
    ).bind(asn, day),
    env.DB.prepare("DELETE FROM crowd WHERE day < ?1").bind(day - CROWD_DAYS),
    env.DB.prepare("DELETE FROM crowd_reports WHERE day < ?1").bind(day - CROWD_DAYS),
  );
  await env.DB.batch(stmts);
  return json({ ok: true });
}

// GET stats lists what passes on each network (by ASN) that enough
// installs reported. With ?asn=self it gives only the asker's own network,
// and says which one that is (an app cannot tell its ASN by itself).
async function crowdSummary(request, env, url) {
  const self = request.cf?.asn ?? 0;
  const only = url.searchParams.get("asn") === "self" ? self : 0;
  const since = Math.floor(now() / DAY) - CROWD_DAYS;
  const { results: enough } = await env.DB.prepare(
    "SELECT asn FROM crowd_reports WHERE day >= ?1 GROUP BY asn HAVING SUM(reports) >= ?2",
  ).bind(since, CROWD_MIN_REPORTS).all();
  const keep = new Set(enough.map((r) => r.asn));
  const { results } = await env.DB.prepare(
    "SELECT asn, kind, code, SUM(ok) AS ok, SUM(n) AS n FROM crowd WHERE day >= ?1 GROUP BY asn, kind, code",
  ).bind(since).all();
  const out = {};
  for (const r of results) {
    if (!keep.has(r.asn) || (only && r.asn !== only)) continue;
    const a = (out[r.asn] ??= {});
    (a[r.kind] ??= []).push([r.code, r.ok, r.n]);
  }
  return json({ asn: self, asns: out });
}

// mirror serves the app's own server lists and update file from GitHub, one
// more way to reach them when GitHub and its CDNs are filtered. Only those
// files, cached at the edge for ten minutes.
const MIRRORED = /^\/list\/(servers\/(hot\.txt|new\.txt|fresh\.txt|all-[1-8]\.txt|tor\.json|meta\.json)|main\/update\.json|rules\/geosite-ads\.srs)$/;
async function mirror(url) {
  const m = MIRRORED.exec(url.pathname);
  if (!m) return new Response("Not found", { status: 404 });
  const up = await fetch("https://raw.githubusercontent.com/cezomagoanlace29861-jpg/Albatross/" + m[1], { cf: { cacheTtl: 600, cacheEverything: true } });
  return new Response(up.body, {
    status: up.status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=600" },
  });
}
