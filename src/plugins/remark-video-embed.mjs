import { visit } from "unist-util-visit";

/**
 * remark-video-embed
 * 文章里单独一行的 B 站 / YouTube 视频链接，构建时自动转换为站内响应式播放器。
 *
 * 支持的链接形式（整段只有这个链接，裸链接或 Markdown 链接均可）：
 *   https://www.bilibili.com/video/BV1fK4y1s7Qf
 *   https://youtu.be/5gIf0_xpFPI
 *   https://www.youtube.com/watch?v=5gIf0_xpFPI
 *   https://www.youtube.com/shorts/5gIf0_xpFPI
 *
 * b23.tv 短链接暂不支持自动转换（保持原样显示为文字链接）。
 */

// id 只允许字母数字下划线连字符，杜绝通过构造 URL 注入 HTML
const safeId = (id) => (id && /^[0-9A-Za-z_-]+$/.test(id) ? id : null);

function resolveEmbed(rawUrl) {
	let url;
	try {
		url = new URL(rawUrl);
	} catch {
		return null;
	}
	const host = url.hostname.replace(/^www\./, "");
	let src = null;

	if (host === "bilibili.com" || host === "m.bilibili.com") {
		const bv = safeId(url.pathname.match(/\/video\/(BV[0-9A-Za-z]+)/)?.[1]);
		if (bv) src = `https://player.bilibili.com/player.html?bvid=${bv}&autoplay=0&high_quality=1`;
	} else if (host === "youtu.be") {
		const id = safeId(url.pathname.slice(1));
		if (id) src = `https://www.youtube-nocookie.com/embed/${id}`;
	} else if (host === "youtube.com" || host === "m.youtube.com") {
		const id =
			safeId(url.searchParams.get("v")) ??
			safeId(url.pathname.match(/\/shorts\/([0-9A-Za-z_-]+)/)?.[1]);
		if (id) src = `https://www.youtube-nocookie.com/embed/${id}`;
	}

	if (!src) return null;
	return (
		`<div style="position:relative;width:100%;aspect-ratio:16/9;margin:1.25rem 0;border-radius:0.5rem;overflow:hidden;background:#000;">` +
		`<iframe src="${src}" style="position:absolute;inset:0;width:100%;height:100%;border:0;" ` +
		`loading="lazy" allowfullscreen ` +
		`allow="accelerometer; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share; fullscreen">` +
		`</iframe></div>`
	);
}

export function remarkVideoEmbed() {
	return (tree) => {
		visit(tree, "paragraph", (node, index, parent) => {
			if (!parent || node.children.length !== 1) return;
			const child = node.children[0];
			let url = null;
			if (child.type === "link") {
				url = child.url;
			} else if (child.type === "text" && /^https?:\/\/\S+$/.test(child.value.trim())) {
				url = child.value.trim();
			}
			if (!url) return;
			const embed = resolveEmbed(url);
			if (!embed) return;
			parent.children.splice(index, 1, { type: "html", value: embed });
			return [visit.SKIP, index];
		});
	};
}
