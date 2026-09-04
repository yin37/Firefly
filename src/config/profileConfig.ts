import type { ProfileConfig } from "../types/profileConfig";
import profileData from "./profile.json";

/**
 * 个人信息配置：实际数据存放在同目录的 profile.json 中，
 * 可通过博客后台（/admin → 站点设置 → 个人信息）直接修改，无需改代码。
 * 此文件只负责读取 json 并提供默认值兜底。
 */
const data = profileData as Partial<ProfileConfig>;

export const profileConfig: ProfileConfig = {
	avatar: data.avatar || "assets/images/avatar.avif",
	name: data.name || "yin37",
	bio: data.bio || "",
	links: (data.links || []).filter((l) => l && l.icon && l.url),
};
