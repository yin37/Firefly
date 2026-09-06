// 博客账号系统 API：邮箱注册 / 登录 / 会话 / 私人内容解锁
// - 数据存 D1 (firefly-users)
// - 管理员 = 邮箱在 ADMIN_EMAILS 名单中（wrangler.jsonc vars）
// - 非静态路径 /api/* 进入本 Worker，其余全部回落到静态资源

interface Env {
	DB: any;
	ASSETS: { fetch: (req: Request) => Promise<Response> };
	BACKUPS?: any; // KV 存储绑定：数据库每日备份（put/list/delete 子集，兼容 R2 接口）
	ADMIN_EMAILS: string;
	PRIVATE_PASSWORD: string;
	GH_TOKEN?: string;
	GITHUB_REPO?: string;
	GITHUB_BRANCH?: string;
}

const COOKIE = "ff_session";
const SESSION_DAYS = 30;
const ITERATIONS = 100000;
const BACKUP_KEEP_DAYS = 30;

function json(data: any, status = 200, headers: Record<string, string> = {}) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
	});
}

// 北京时间日期（YYYY-MM-DD），每日阅读统计用
function beijingDay(): string {
	return new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Shanghai" }).format(new Date());
}

// n 天前的北京时间日期，备份保留期判断用
function daysAgoDay(n: number): string {
	return new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Shanghai" }).format(new Date(Date.now() - n * 86400000));
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

// ---- 防暴力破解：同一 IP(+邮箱) 在时间窗内超过次数则拒绝 ----
// 记录在 D1 auth_attempts 表；限速系统自身故障时放行（不拦正常用户）
async function tooManyAttempts(env: Env, key: string, max: number, windowSec: number): Promise<boolean> {
	const now = Date.now();
	try {
		const row: any = await env.DB.prepare(`SELECT COUNT(*) AS c FROM auth_attempts WHERE key = ?1 AND ts > ?2`)
			.bind(key, now - windowSec * 1000)
			.first();
		if ((row?.c || 0) >= max) return true;
		await env.DB.prepare(`INSERT INTO auth_attempts (key, ts) VALUES (?1, ?2)`).bind(key, now).run();
		// 顺带清理一天前的旧记录（5% 概率触发，避免每次都多一次写）
		if (Math.random() < 0.05) {
			await env.DB.prepare(`DELETE FROM auth_attempts WHERE ts < ?1`).bind(now - 86400000).run();
		}
		return false;
	} catch {
		return false;
	}
}

function clientIp(request: Request): string {
	return request.headers.get("CF-Connecting-IP") || "unknown";
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

// ---- GitHub 内容 API 辅助（隐藏/恢复/删除文章用） ----
function ghEnv(env: Env) {
	return {
		token: env.GH_TOKEN || "",
		repo: env.GITHUB_REPO || "yin37/Firefly",
		branch: env.GITHUB_BRANCH || "master",
	};
}

function ghHeaders(token: string, raw = false): Record<string, string> {
	return {
		Authorization: `Bearer ${token}`,
		Accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json",
		"User-Agent": "firefly-blog",
		"Content-Type": "application/json",
	};
}

function encPath(p: string): string {
	return p.split("/").map(encodeURIComponent).join("/");
}

// 按常见命名规则定位文章源文件
async function findPostFile(env: Env, slug: string): Promise<{ path: string; sha: string } | null> {
	const { token, repo, branch } = ghEnv(env);
	const candidates = [
		`src/content/posts/${slug}.md`,
		`src/content/posts/${slug}.mdx`,
		`src/content/posts/${slug}/index.md`,
		`src/content/posts/${slug}/index.mdx`,
	];
	for (const p of candidates) {
		const r = await fetch(
			`https://api.github.com/repos/${repo}/contents/${encPath(p)}?ref=${encodeURIComponent(branch)}`,
			{ headers: ghHeaders(token) },
		);
		if (r.ok) {
			const j: any = await r.json();
			if (!Array.isArray(j)) return { path: j.path as string, sha: j.sha as string };
		}
		if (r.status === 401 || r.status === 403) throw new Error("GH_AUTH");
	}
	return null;
}

async function fetchPostRaw(env: Env, path: string): Promise<string | null> {
	const { token, repo, branch } = ghEnv(env);
	const r = await fetch(
		`https://api.github.com/repos/${repo}/contents/${encPath(path)}?ref=${encodeURIComponent(branch)}`,
		{ headers: ghHeaders(token, true) },
	);
	if (!r.ok) return null;
	return r.text();
}

// UTF-8 安全 base64（btoa 不支持非 ASCII，分块转换避免栈溢出）
function utf8ToBase64(text: string): string {
	const bytes = new TextEncoder().encode(text);
	let bin = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)) as any);
	}
	return btoa(bin);
}

// 在 frontmatter 中设置布尔标记（存在则替换，不存在则插入到 --- 之后）
function setFrontmatterFlag(content: string, key: string, value: boolean): string {
	const re = new RegExp(`^${key}:.*$`, "m");
	if (re.test(content)) return content.replace(re, `${key}: ${value}`);
	return content.replace(/^---\n/, `---\n${key}: ${value}\n`);
}

// 从 frontmatter 原文提取单值字段
function parseFrontmatterField(fm: string, key: string): string {
	const m = fm.match(new RegExp(`^${key}:\\s*(.+)$`, "m"));
	if (!m) return "";
	return m[1].trim().replace(/^["']|["']$/g, "");
}

// 解析 markdown 的 frontmatter 区块
function splitFrontmatter(raw: string): { fm: string; body: string } {
	const m = raw.match(/^---\n([\s\S]*?)\n---\n?/);
	if (!m) return { fm: "", body: raw };
	return { fm: m[1], body: raw.slice(m[0].length) };
}

// 权限：管理员，或文章 frontmatter 记录的发布者邮箱与当前登录邮箱一致
function canManagePost(user: { email: string; isAdmin: boolean }, authorEmail: string): boolean {
	if (user.isAdmin) return true;
	const a = (authorEmail || "").trim().toLowerCase();
	return a !== "" && a === user.email.toLowerCase();
}

// ---- 数据库备份：把 D1 全部表导出为 SQL 文本，存进 R2，保留最近 30 天 ----
async function dumpDbToSql(env: Env): Promise<string> {
	const tablesRes: any = await env.DB.prepare(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'`,
	).all();
	const tables = (tablesRes.results || []).map((r: any) => String(r.name));
	const parts: string[] = [`-- firefly-users backup ${new Date().toISOString()}`, "-- restore: wrangler d1 execute firefly-users --remote --file <this-file>"];
	for (const t of tables) {
		const schemaRow: any = await env.DB.prepare(`SELECT sql FROM sqlite_master WHERE name = ?1`).bind(t).first();
		if (schemaRow?.sql) parts.push(`DROP TABLE IF EXISTS ${t};`, `${schemaRow.sql};`);
		const { results } = await env.DB.prepare(`SELECT * FROM ${t}`).all();
		for (const row of results || []) {
			const cols = Object.keys(row as any);
			const vals = cols.map((c) => {
				const v = (row as any)[c];
				if (v === null || v === undefined) return "NULL";
				if (typeof v === "number") return String(v);
				return `'${String(v).replace(/'/g, "''")}'`;
			});
			parts.push(`INSERT INTO ${t} (${cols.join(", ")}) VALUES (${vals.join(", ")});`);
		}
	}
	return parts.join("\n") + "\n";
}

async function doBackup(env: Env): Promise<{ key: string; size: number }> {
	const sql = await dumpDbToSql(env);
	const key = `backup/${beijingDay()}.sql`;
	await env.BACKUPS.put(key, sql);
	// 清理超过保留期的旧备份（备份键名格式 backup/YYYY-MM-DD.sql，按日期字符串比较）
	try {
		const cutoffDay = daysAgoDay(BACKUP_KEEP_DAYS);
		const list = await env.BACKUPS.list({ prefix: "backup/" });
		const keys = (list.keys || list.objects || []).map((k: any) => k.name || k.key);
		for (const key of keys) {
			const day = String(key).replace("backup/", "").replace(".sql", "");
			if (/^\d{4}-\d{2}-\d{2}$/.test(day) && day < cutoffDay) await env.BACKUPS.delete(key);
		}
	} catch {}
	return { key, size: sql.length };
}

async function handleApi(request: Request, env: Env, url: URL): Promise<Response> {
	const path = url.pathname;
	const method = request.method;

	// ---- 注册 ----
	if (path === "/api/auth/register" && method === "POST") {
		// 防滥用：同 IP 每小时最多 5 次注册尝试
		if (await tooManyAttempts(env, `reg:${clientIp(request)}`, 5, 3600)) {
			return json({ error: "注册尝试过于频繁，请 1 小时后再试" }, 429);
		}
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
		if (exists) return json({ error: "该邮箱已注册，请直接登录", code: "ALREADY_EXISTS" }, 409);

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
		// 防暴力破解：同 IP 15 分钟最多 10 次；同一 IP+邮箱 15 分钟最多 5 次
		if (await tooManyAttempts(env, `login:${clientIp(request)}`, 10, 900)) {
			return json({ error: "尝试次数过多，请 15 分钟后再试" }, 429);
		}
		if (await tooManyAttempts(env, `login:${clientIp(request)}:${email}`, 5, 900)) {
			return json({ error: "该账号尝试次数过多，请 15 分钟后再试" }, 429);
		}
		const row: any = await env.DB.prepare(`SELECT id, password_hash FROM users WHERE email = ?1`)
			.bind(email)
			.first();
		if (!row) {
			// 账号不存在：明确提示去注册（前端会自动切到注册页签并带入邮箱）
			return json({ error: `该邮箱（${email}）尚未注册，请先注册账号`, code: "NO_ACCOUNT" }, 401);
		}
		if (!(await verifyPassword(password, row.password_hash))) {
			return json({ error: "密码错误，请重试", code: "WRONG_PASSWORD" }, 401);
		}
		const token = await createSession(env, row.id);
		return json(
			{ user: { email, isAdmin: isAdminEmail(env, email) } },
			200,
			{ "Set-Cookie": sessionCookie(token) },
		);
	}

	// ---- 修改密码（需登录，验证旧密码） ----
	if (path === "/api/auth/change-password" && method === "POST") {
		const user = await getSessionUser(env, request);
		if (!user) return json({ error: "请先登录" }, 401);
		if (await tooManyAttempts(env, `pwd:${clientIp(request)}`, 5, 900)) {
			return json({ error: "尝试次数过多，请 15 分钟后再试" }, 429);
		}
		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const oldPassword = String(body.oldPassword || "");
		const newPassword = String(body.newPassword || "");
		if (newPassword.length < 6) return json({ error: "新密码至少 6 位" }, 400);
		if (newPassword.length > 128) return json({ error: "新密码过长" }, 400);

		const row: any = await env.DB.prepare(`SELECT id, password_hash FROM users WHERE email = ?1`)
			.bind(user.email)
			.first();
		if (!row || !(await verifyPassword(oldPassword, row.password_hash))) {
			return json({ error: "旧密码不正确" }, 401);
		}
		const hash = await hashPassword(newPassword);
		await env.DB.prepare(`UPDATE users SET password_hash = ?1 WHERE id = ?2`).bind(hash, row.id).run();
		// 安全起见：改密后吊销该用户其他设备的会话，保留当前会话
		await env.DB.prepare(
			`DELETE FROM sessions WHERE user_id = ?1 AND token != ?2`,
		)
			.bind(row.id, parseCookies(request)[COOKIE])
			.run();
		return json({ ok: true });
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

	// ---- 后台文章列表（仅管理员）：标题 + 删除/隐藏状态 ----
	if (path === "/api/admin/posts" && method === "GET") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员可以查看" }, 403);
		const { token } = ghEnv(env);
		if (!token) return json({ error: "服务器未配置 GitHub 令牌" }, 500);
		const { repo, branch } = ghEnv(env);

		// 递归列出文章目录（含子目录，如 guide/）
		async function listDir(dir: string): Promise<any[]> {
			const r = await fetch(
				`https://api.github.com/repos/${repo}/contents/${encPath(dir)}?ref=${encodeURIComponent(branch)}`,
				{ headers: ghHeaders(token) },
			);
			if (!r.ok) return [];
			const arr: any[] = await r.json();
			const files: any[] = [];
			for (const item of arr) {
				if (item.type === "file" && /\.(md|mdx)$/i.test(item.name)) files.push(item);
				else if (item.type === "dir") files.push(...(await listDir(item.path)));
			}
			return files;
		}

		const files = await listDir("src/content/posts");
		const posts: any[] = [];
		for (const f of files) {
			const slug = String(f.path)
				.replace(/^src\/content\/posts\//, "")
				.replace(/\.(md|mdx)$/i, "");
			let title = slug;
			let deleted = false;
			let hidden = false;
			let authorEmail = "";
			let published = "";
			let category = "";
			const raw = await fetchPostRaw(env, f.path);
			if (raw) {
				const { fm } = splitFrontmatter(raw);
				title = parseFrontmatterField(fm, "title") || slug;
				deleted = /^deleted:\s*true\b/m.test(fm);
				hidden = /^hidden:\s*true\b/m.test(fm);
				authorEmail = parseFrontmatterField(fm, "authorEmail");
				published = parseFrontmatterField(fm, "published");
				category = parseFrontmatterField(fm, "category");
			}
			posts.push({ slug, title, deleted, hidden, authorEmail, published, category });
		}
		return json({ posts });
	}

	// ---- 隐藏 / 恢复文章（软删除，管理员或发布者本人） ----
	if (path === "/api/admin/set-deleted" && method === "POST") {
		const user = await getSessionUser(env, request);
		if (!user) return json({ error: "请先登录" }, 401);
		const { token } = ghEnv(env);
		if (!token) return json({ error: "服务器未配置 GitHub 令牌，暂时无法删除" }, 500);

		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const slug = String(body.slug || "").trim();
		const deleted = body.deleted === true;
		if (!slug || slug.includes("..") || slug.startsWith("/")) return json({ error: "参数错误" }, 400);

		let file: { path: string; sha: string } | null = null;
		try {
			file = await findPostFile(env, slug);
		} catch (e: any) {
			if (e && e.message === "GH_AUTH") return json({ error: "GitHub 令牌无效或权限不足" }, 500);
			throw e;
		}
		if (!file) return json({ error: "未找到对应的文章文件" }, 404);

		const raw = await fetchPostRaw(env, file.path);
		if (raw === null) return json({ error: "读取文章失败" }, 502);
		const { fm } = splitFrontmatter(raw);
		const authorEmail = parseFrontmatterField(fm, "authorEmail");
		if (!canManagePost(user, authorEmail)) {
			return json({ error: "只有管理员或文章发布者可以删除" }, 403);
		}

		const newContent = setFrontmatterFlag(raw, "deleted", deleted);
		const { repo, branch } = ghEnv(env);
		const put = await fetch(`https://api.github.com/repos/${repo}/contents/${encPath(file.path)}`, {
			method: "PUT",
			headers: ghHeaders(token),
			body: JSON.stringify({
				message: `${deleted ? "删除（隐藏）" : "恢复"}文章：${slug}`,
				content: utf8ToBase64(newContent),
				sha: file.sha,
				branch,
			}),
		});
		if (!put.ok) {
			const detail = await put.text().catch(() => "");
			return json({ error: `操作失败（GitHub ${put.status}）`, detail: detail.slice(0, 200) }, 502);
		}
		return json({ ok: true, deleted });
	}

	// ---- 彻底删除文章（仅管理员，后台二次确认后调用） ----
	if (path === "/api/admin/delete-article" && method === "POST") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员可以彻底删除文章" }, 403);
		const { token } = ghEnv(env);
		if (!token) return json({ error: "服务器未配置 GitHub 令牌，暂时无法删除" }, 500);

		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const slug = String(body.slug || "").trim();
		if (!slug || slug.includes("..") || slug.startsWith("/")) return json({ error: "参数错误" }, 400);

		let file: { path: string; sha: string } | null = null;
		try {
			file = await findPostFile(env, slug);
		} catch (e: any) {
			if (e && e.message === "GH_AUTH") return json({ error: "GitHub 令牌无效或权限不足" }, 500);
			throw e;
		}
		if (!file) return json({ error: "未找到对应的文章文件" }, 404);

		const { repo, branch } = ghEnv(env);
		const del = await fetch(`https://api.github.com/repos/${repo}/contents/${encPath(file.path)}`, {
			method: "DELETE",
			headers: ghHeaders(token),
			body: JSON.stringify({ message: `彻底删除文章：${slug}`, sha: file.sha, branch }),
		});
		if (!del.ok) {
			const detail = await del.text().catch(() => "");
			return json({ error: `删除失败（GitHub ${del.status}）`, detail: detail.slice(0, 200) }, 502);
		}
		return json({ ok: true });
	}

	// ---- 阅读量：浏览一篇文章时 +1 ----
	if (path === "/api/views" && method === "POST") {
		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const slug = String(body.slug || "").trim();
		if (!slug || slug.length > 200) return json({ error: "参数错误" }, 400);
		try {
			await env.DB.prepare(
				`INSERT INTO post_views (slug, count) VALUES (?1, 1) ON CONFLICT(slug) DO UPDATE SET count = count + 1`,
			)
				.bind(slug)
				.run();
			// 每日阅读计数（统计失败不影响主计数）
			try {
				await env.DB.prepare(
					`INSERT INTO daily_views (day, count) VALUES (?1, 1) ON CONFLICT(day) DO UPDATE SET count = count + 1`,
				)
					.bind(beijingDay())
					.run();
			} catch {}
			const row: any = await env.DB.prepare(`SELECT count FROM post_views WHERE slug = ?1`).bind(slug).first();
			return json({ ok: true, count: row?.count ?? 1 });
		} catch {
			return json({ error: "统计失败" }, 500);
		}
	}

	// ---- 阅读量：批量查询（列表页用） ----
	if (path === "/api/views" && method === "GET") {
		const slugsParam = url.searchParams.get("slugs") || "";
		const slugs = slugsParam.split(",").map((s) => s.trim()).filter(Boolean).slice(0, 50);
		if (slugs.length === 0) return json({ counts: {} });
		try {
			const placeholders = slugs.map((_, i) => `?${i + 1}`).join(",");
			const stmt = env.DB.prepare(`SELECT slug, count FROM post_views WHERE slug IN (${placeholders})`).bind(
				...slugs,
			);
			const { results } = await stmt.all();
			const counts: Record<string, number> = {};
			for (const r of results || []) counts[(r as any).slug] = (r as any).count;
			return json({ counts });
		} catch {
			return json({ counts: {} });
		}
	}

	// ---- 阅读量：管理员全量（后台热度榜） ----
	if (path === "/api/admin/views" && method === "GET") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员" }, 403);
		const { results } = await env.DB.prepare(`SELECT slug, count FROM post_views ORDER BY count DESC`).all();
		return json({ views: results || [] });
	}

	// ---- 数据仪表盘（仅管理员）：总阅读 / 今日阅读 / 热度 Top10 ----
	if (path === "/api/admin/stats" && method === "GET") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员" }, 403);
		try {
			const totalRow: any = await env.DB.prepare(`SELECT COALESCE(SUM(count), 0) AS t FROM post_views`).first();
			const today = beijingDay();
			const todayRow: any = await env.DB.prepare(`SELECT count FROM daily_views WHERE day = ?1`).bind(today).first();
			const { results } = await env.DB.prepare(`SELECT slug, count FROM post_views ORDER BY count DESC LIMIT 10`).all();
			return json({
				totalViews: totalRow?.t || 0,
				todayViews: todayRow?.count || 0,
				today,
				top: results || [],
			});
		} catch {
			return json({ error: "统计查询失败" }, 500);
		}
	}

	// ---- 数据库备份：手动触发一次（仅管理员） ----
	if (path === "/api/admin/backup" && method === "POST") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员" }, 403);
		if (!env.BACKUPS) return json({ error: "未配置备份存储桶" }, 500);
		try {
			const r = await doBackup(env);
			return json({ ok: true, key: r.key, size: r.size, at: new Date().toISOString() });
		} catch {
			return json({ error: "备份失败" }, 500);
		}
	}

	// ---- 数据库备份：查看备份列表（仅管理员） ----
	if (path === "/api/admin/backup" && method === "GET") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员" }, 403);
		if (!env.BACKUPS) return json({ error: "未配置备份存储桶" }, 500);
		try {
			const list = await env.BACKUPS.list({ prefix: "backup/" });
			const keys = (list.keys || list.objects || []).map((k: any) => k.name || k.key);
			return json({ keys });
		} catch {
			return json({ error: "读取备份列表失败" }, 500);
		}
	}

	// ---- 公告：读取（公开） ----
	if (path === "/api/announce" && method === "GET") {
		try {
			const row: any = await env.DB.prepare(`SELECT value, updated_at FROM site_config WHERE key = 'announcement'`).first();
			return json({ text: row?.value || "", updatedAt: row?.updated_at || "" });
		} catch {
			return json({ text: "", updatedAt: "" });
		}
	}

	// ---- 公告：发布 / 撤下（仅管理员） ----
	if (path === "/api/admin/announce" && method === "POST") {
		const user = await getSessionUser(env, request);
		if (!user || !user.isAdmin) return json({ error: "仅管理员可以发布公告" }, 403);
		let body: any;
		try {
			body = await request.json();
		} catch {
			return json({ error: "请求格式错误" }, 400);
		}
		const text = String(body.text || "").trim().slice(0, 500);
		try {
			if (!text) {
				await env.DB.prepare(`DELETE FROM site_config WHERE key = 'announcement'`).run();
				return json({ ok: true, cleared: true });
			}
			await env.DB.prepare(
				`INSERT INTO site_config (key, value, updated_at) VALUES ('announcement', ?1, datetime('now'))
				 ON CONFLICT(key) DO UPDATE SET value = ?1, updated_at = datetime('now')`,
			)
				.bind(text)
				.run();
			return json({ ok: true });
		} catch {
			return json({ error: "保存失败" }, 500);
		}
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

	// 定时任务：每天北京时间 05:00 自动备份数据库到 R2
	async scheduled(_event: any, env: Env, _ctx: any): Promise<void> {
		try {
			if (env.BACKUPS) await doBackup(env);
		} catch {}
	},
};
