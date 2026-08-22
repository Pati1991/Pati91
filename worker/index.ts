/** Cloudflare Worker entry point for the Leitstelle Tirol training game. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  DB?: D1Database;
  INVITE_CODE?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const COOKIE_NAME = "leitstelle_session";
const SESSION_DAYS = 30;
const encoder = new TextEncoder();

function json(data: unknown, status = 200, headers?: HeadersInit) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function randomToken(size = 32) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function sha256(value: string) {
  return bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

async function derivePassword(password: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(salt), iterations: 100_000 },
    key,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

function safeEqual(left: string, right: string) {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index++) difference |= (a[index % Math.max(a.length, 1)] ?? 0) ^ (b[index % Math.max(b.length, 1)] ?? 0);
  return difference === 0;
}

function cookieValue(request: Request, name: string) {
  const cookies = request.headers.get("cookie") ?? "";
  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function sessionCookie(token: string, request: Request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearSessionCookie(request: Request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=0`;
}

async function ensureSchema(db: D1Database) {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, created_at INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    db.prepare("CREATE TABLE IF NOT EXISTS user_state (user_id TEXT PRIMARY KEY, active_incidents TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL)"),
    db.prepare("CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at)"),
  ]);
}

function validSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return origin === new URL(request.url).origin;
}

async function requestBody(request: Request) {
  if ((Number(request.headers.get("content-length")) || 0) > 8192) throw new Error("too-large");
  return await request.json<Record<string, unknown>>();
}

async function createSession(db: D1Database, userId: string, request: Request) {
  const token = randomToken();
  const now = Date.now();
  await db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256(token), userId, now + SESSION_DAYS * 86400_000, now).run();
  return sessionCookie(token, request);
}

async function authenticatedUser(request: Request, db?: D1Database) {
  const token = cookieValue(request, COOKIE_NAME);
  if (!token || !db) return null;
  const row = await db.prepare("SELECT users.id, users.email FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?")
    .bind(await sha256(token), Date.now()).first<{ id: string; email: string }>();
  return row ?? null;
}

async function authApi(request: Request, env: Env) {
  if (!env.DB) return json({ error: "Die Cloudflare-D1-Datenbank ist noch nicht mit dem Namen DB verbunden." }, 503);
  await ensureSchema(env.DB);
  const url = new URL(request.url);

  if (url.pathname === "/api/auth/me" && request.method === "GET") {
    const user = await authenticatedUser(request, env.DB);
    return user ? json({ user }) : json({ error: "Nicht angemeldet" }, 401);
  }

  if (request.method !== "POST" || !validSameOrigin(request)) return json({ error: "Ungültige Anfrage" }, 403);

  if (url.pathname === "/api/auth/logout") {
    const token = cookieValue(request, COOKIE_NAME);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie(request) });
  }

  let body: Record<string, unknown>;
  try { body = await requestBody(request); } catch { return json({ error: "Ungültige Eingabe" }, 400); }
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: "Bitte eine gültige E-Mail-Adresse eingeben." }, 400);
  if (password.length < 1 || password.length > 128) return json({ error: "Das Passwort muss mindestens 10 Zeichen lang sein." }, 400);

  if (url.pathname === "/api/auth/register") {
    if (password.length < 10 || password.length > 128)
  return json({ error: "Das Passwort muss mindestens 10 Zeichen lang sein." }, 400);
    
    const inviteCode = String(body.inviteCode ?? "");
    if (!env.INVITE_CODE) return json({ error: "Der Einladungscode wurde auf Cloudflare noch nicht eingerichtet." }, 503);
    if (!safeEqual(inviteCode, env.INVITE_CODE)) return json({ error: "Der Einladungscode ist nicht richtig." }, 403);
    const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
    if (existing) return json({ error: "Für diese E-Mail-Adresse besteht bereits ein Konto." }, 409);
    const salt = randomToken(18);
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(id, email, await derivePassword(password, salt), salt, Date.now()).run();
    return json({ ok: true }, 201, { "set-cookie": await createSession(env.DB, id, request) });
  }

  if (url.pathname === "/api/auth/login") {
    const user = await env.DB.prepare("SELECT id, password_hash, password_salt FROM users WHERE email = ?")
      .bind(email).first<{ id: string; password_hash: string; password_salt: string }>();
    const salt = user?.password_salt ?? "ungültige-anmeldung-sicherheitssalz";
    const candidate = await derivePassword(password, salt);
    if (!user || !safeEqual(candidate, user.password_hash)) return json({ error: "E-Mail-Adresse oder Passwort ist nicht richtig." }, 401);
    return json({ ok: true }, 200, { "set-cookie": await createSession(env.DB, user.id, request) });
  }

  return json({ error: "Nicht gefunden" }, 404);
}

function authPage(request: Request, configured: boolean) {
  const local = ["localhost", "127.0.0.1"].includes(new URL(request.url).hostname);
  const hint = local && !configured ? '<p class="hint">Lokal: Lege INVITE_CODE in deiner Entwicklungsumgebung fest.</p>' : "";
  return new Response(`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#0c1114"><title>Anmeldung · Leitstelle Tirol</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:max(20px,env(safe-area-inset-top)) max(16px,env(safe-area-inset-right)) max(20px,env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-left));background:radial-gradient(circle at 50% 0,#1d2b31,#090d0f 62%);color:#e8eef2;font-family:system-ui,-apple-system,sans-serif}.card{width:min(440px,100%);padding:28px;border:1px solid #34464e;background:#11191d;box-shadow:0 24px 80px #000b}.brand{display:flex;gap:13px;align-items:center;margin-bottom:24px}.brand b{display:grid;place-items:center;width:48px;height:48px;background:#d23b35;font-size:19px}.brand strong{display:block;letter-spacing:.08em}.brand small{color:#63bed0;font:10px monospace}.tabs{display:grid;grid-template-columns:1fr 1fr;margin-bottom:20px;border:1px solid #33444b}.tabs button{min-height:46px;border:0;background:#0b1114;color:#8d9ba1;font-weight:800}.tabs button.active{background:#24343b;color:#fff}form{display:grid;gap:13px}label{display:grid;gap:6px;color:#a7b3b8;font-size:12px}input{width:100%;min-height:48px;border:1px solid #3b4b52;border-radius:0;background:#090e10;color:#fff;padding:0 13px;font-size:16px}button[type=submit]{min-height:50px;border:0;background:#55bed2;color:#071014;font-weight:900;letter-spacing:.04em;cursor:pointer}.error{min-height:20px;color:#ff938c;font-size:12px;line-height:1.45}.info,.hint{color:#84949b;font-size:11px;line-height:1.5}.hidden{display:none}@media(max-width:390px){.card{padding:22px 18px}.brand strong{font-size:14px}}</style></head><body><main class="card"><div class="brand"><b>LT</b><span><strong>LEITSTELLE TIROL</strong><small>GESCHÜTZTER SPIELZUGANG</small></span></div><div class="tabs"><button id="loginTab" class="active" type="button">ANMELDEN</button><button id="registerTab" type="button">KONTO ANLEGEN</button></div><form id="form" autocomplete="on"><label>E-Mail-Adresse<input id="email" name="email" type="email" autocomplete="email" required></label><label>Passwort<input id="password" name="password" type="password" autocomplete="current-password" minlength="1" required></label><label id="inviteWrap" class="hidden">Einladungscode<input id="invite" name="invite-code" type="text" autocomplete="off"></label><div id="error" class="error" role="alert"></div><button type="submit">ANMELDEN</button></form><p class="info">Deine Anmeldung bleibt auf diesem Gerät bis zu 30 Tage gespeichert. Passwörter werden nicht lesbar gespeichert.</p>${hint}</main><script>
  const form=document.getElementById('form'),loginTab=document.getElementById('loginTab'),registerTab=document.getElementById('registerTab'),inviteWrap=document.getElementById('inviteWrap'),password=document.getElementById('password'),error=document.getElementById('error'),submit=form.querySelector('button[type=submit]');let mode='login';
  function setMode(next){mode=next;const register=mode==='register';loginTab.classList.toggle('active',!register);registerTab.classList.toggle('active',register);inviteWrap.classList.toggle('hidden',!register);password.autocomplete=register?'new-password':'current-password';submit.textContent=register?'KONTO ERSTELLEN':'ANMELDEN';error.textContent=''}
  loginTab.onclick=()=>setMode('login');registerTab.onclick=()=>setMode('register');form.onsubmit=async event=>{event.preventDefault();error.textContent='';submit.disabled=true;try{const response=await fetch('/api/auth/'+mode,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:document.getElementById('email').value,password:password.value,inviteCode:document.getElementById('invite').value})});const result=await response.json();if(!response.ok)throw new Error(result.error||'Anmeldung fehlgeschlagen');location.replace('/')}catch(reason){error.textContent=reason.message||'Anmeldung fehlgeschlagen'}finally{submit.disabled=false}};
  fetch('/api/auth/me',{cache:'no-store'}).then(response=>{if(response.ok)location.replace('/')});
  </script></body></html>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer" } });
}

function isPublicAsset(pathname: string) {
  return pathname.startsWith("/_next/") || pathname.startsWith("/_vinext/") || pathname === "/favicon.svg" || /\.(?:css|js|mjs|map|svg|png|jpg|jpeg|webp|woff2?)$/i.test(pathname);
}

const worker = {
  async fetch(request: Request, env: Env | undefined, ctx: ExecutionContext): Promise<Response> {
    const runtimeEnv = env ?? ({} as Env);
    const url = new URL(request.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(request, {
        fetchAsset: (path) => runtimeEnv.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await runtimeEnv.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    }

    if (url.pathname.startsWith("/api/auth/")) return authApi(request, runtimeEnv);
    if (url.pathname === "/auth") return authPage(request, Boolean(runtimeEnv.INVITE_CODE));
    if (!isPublicAsset(url.pathname)) {
      if (!runtimeEnv.DB) return Response.redirect(new URL("/auth", request.url), 302);
      await ensureSchema(runtimeEnv.DB);
      const user = await authenticatedUser(request, runtimeEnv.DB);
      if (!user) return Response.redirect(new URL("/auth", request.url), 302);
    }

    return handler.fetch(request, runtimeEnv, ctx);
  },
};

export default worker;
