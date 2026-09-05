// 博客账号系统 API：邮箱注册 / 登录 / 会话 / 私人内容解锁
// - 数据存 D1 (firefly-users)
// - 管理员 = 邮箱在 ADMIN_EMAILS 名单中（wrangler.jsonc vars）
// - 非静态路径 /api/* 进入本 Worker，其余全部回落到静态资源

interface Env {
	DB: any;
	ASSETS: { fetch: (req: Request) => Promise<Response> };
	ADMIN_EMAILS: string;
	PRIVATE_PASSWORD: string;
}

const COOKIE = "ff_session";
const SESSION_DAYS = 30;
const ITERATIONS = 100000;

function json(data: any, status = 200, headers: Record<string, string> = {}) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
	});
}

function hex(buf: Uint8Array): string {
	return Array.from(buf)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
		"raw",
		enc.encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt: salt as BufferSource, iterations: ITERATIONS, hash: "SHA-256" },
		keyMaterial,
		256,
	);
	return new Uint8Array(bits);
}

async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const key = await deriveKey(password, salt);
	return `pbkdf2$${ITERATIONS}$${hex(salt)}$${hex(key)}`;
}

// 常数时间比较，避免时序侧信道
function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
	const parts = stored.split("$");
	if (parts.length !== 4) return false;
	const iterations = parseInt(parts[1], 10);
	const salt = new Uint8Array(parts[2].match(/.{2}/g)!.map((h) => parseInt(h, 16)));
	const keyMaterial = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
		keyMaterial,
		256,
	);
	return safeEqual(hex(new Uint8Array(bits)), parts[3]);
}

function newSessionToken(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return hex(bytes);
}

function parseCookies(request: Request): Record<string, string> {
	const header = request.headers.get("Cookie") || "";
	const out: Record<string, string> = {};
	for (const pair of header.split(";")) {
		const idx = pair.indexOf("=");
		if (idx > 0) out[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
	}
	return out;
}

function sessionCookie(token: string): string {
	return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearCookie(): string {
	return `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function isAdminEmail(env: Env, email: string): boolean {
	return (env.ADMIN_EMAILS || "")
		.split(",")
		.map((e) => e.trim().toLowerCase())
		.includes(email.toLowerCase());
}

async function getSessionUser(env: Env, request: Request): Promise<{ email: string; isAdmin: boolean } | null> {
	const token = parseCookies(request)[COOKIE];
	if (!token) return null;
	try {
		const row: any = await env.DB.prepare(
			`SELECT u.email AS email FROM sessions s JOIN users u ON u.id = s.user_id
			 WHERE s.token = ?1 AND s.expires_at > datetime('now')`,
		)
			.bind(token)
			.first();
		if (!row) return null;
		return { email: row.email, isAdmin: isAdminEmail(env, row.email) };
	} catch {
		return null;
	}
}

async function createSession(env: Env, userId: number): Promise<string> {
	// 顺手清理过期会话
	await env.DB.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`).run();
	const token = newSessionToken();
	await env.DB.prepare(
		`INSERT INTO sessions (token, user_id, expires_at) VALUES (?1, ?2, datetime('now', '+${SESSION_DAYS} days'))`,
	)
		.bind(token, userId)
		.run();
	return token;
}

function validEmail(email: string): boolean {
	return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function handleApi(request: Request, env: Env, url: URL): Promise<Response> {
	const path = url.pathname;
	const method = request.method;

	// ---- 注册 ----
	if (path === "/api/auth/register" && method === "POST") {
		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const email = String(body.email || "").trim().toLowerCase();
		const password = String(body.password || "");
		if (!validEmail(email)) return json({ error: "邮箱格式不正确" }, 400);
		if (password.length < 6) return json({ error: "密码至少 6 位" }, 400);
		if (password.length > 128) return json({ error: "密码过长" }, 400);

		const exists: any = await env.DB.prepare(`SELECT id FROM users WHERE email = ?1`).bind(email).first();
		if (exists) return json({ error: "该邮箱已注册，请直接登录" }, 409);

		const hash = await hashPassword(password);
		let result: any;
		try {
			result = await env.DB.prepare(`INSERT INTO users (email, password_hash) VALUES (?1, ?2)`)
				.bind(email, hash)
				.run();
		} catch {
			return json({ error: "注册失败，请稍后再试" }, 500);
		}
		const userId = result.meta.last_row_id;
		const token = await createSession(env, userId);
		return json(
			{ user: { email, isAdmin: isAdminEmail(env, email) } },
			200,
			{ "Set-Cookie": sessionCookie(token) },
		);
	}

	// ---- 登录 ----
	if (path === "/api/auth/login" && method === "POST") {
		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const email = String(body.email || "").trim().toLowerCase();
		const password = String(body.password || "");
		const row: any = await env.DB.prepare(`SELECT id, password_hash FROM users WHERE email = ?1`)
			.bind(email)
			.first();
		if (!row || !(await verifyPassword(password, row.password_hash))) {
			return json({ error: "邮箱或密码错误" }, 401);
		}
		const token = await createSession(env, row.id);
		return json(
			{ user: { email, isAdmin: isAdminEmail(env, email) } },
			200,
			{ "Set-Cookie": sessionCookie(token) },
		);
	}

	// ---- 退出 ----
	if (path === "/api/auth/logout" && method === "POST") {
		const token = parseCookies(request)[COOKIE];
		if (token) {
			await env.DB.prepare(`DELETE FROM sessions WHERE token = ?1`).bind(token).run();
		}
		return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
	}

	// ---- 当前用户 ----
	if (path === "/api/auth/me" && method === "GET") {
		const user = await getSessionUser(env, request);
		return json({ user });
	}

	// ---- 私人内容解锁（仅管理员） ----
	if (path === "/api/private/unlock" && method === "GET") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) {
			return json({ error: "无权限" }, 403);
		}
		return json({ password: env.PRIVATE_PASSWORD || "" });
	}

	return json({ error: "Not Found" }, 404);
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname.startsWith("/api/")) {
			try {
				return await handleApi(request, env, url);
			} catch (e: any) {
				return json({ error: "服务器错误" }, 500);
			}
		}
		return env.ASSETS.fetch(request);
	},
};
