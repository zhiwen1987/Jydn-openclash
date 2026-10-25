"""Shared strategy and node-group catalog for template generation and validation."""


BUSINESS_STRATEGY_GROUPS = (
    "🏠 本地网络",
    "🌐 联网检测",
    "🧠 人工智能",
    "📞 即时通讯",
    "💬 社交平台",
    "🌐 Meta 平台",
    "🎞️ 海外影音",
    "💻 开发服务",
    "☁️ 云端办公",
    "🕹️ 游戏服务",
    "💳 海外支付",
    "🪙 数字货币",
    "📚 海外学术",
    "🛒 海外电商",
    "🏦 国内银行",
    "🏛️ 政务服务",
    "📈 国内证券",
    "☁️ 国内网盘",
    "🎵 国内音乐",
    "⬇️ 游戏下载",
    "🚫 广告拦截",
    "📦 笔记协作（Notion）",
    "🤖 对话助手（ChatGPT）",
    "🟠 对话助手（Claude）",
    "🔵 对话助手（Gemini）",
    "⚫ 对话助手（Grok）",
    "🔎 智能搜索（Perplexity）",
    "🪟 办公助手（Microsoft Copilot）",
    "🧑‍💻 编程助手（GitHub Copilot）",
    "📨 电报通讯（Telegram）",
    "💬 聊天社区（Discord）",
    "🟢 通讯工具（WhatsApp）",
    "🔐 安全通信（Signal）",
    "🟩 通讯工具（LINE）",
    "📸 图片社交（Instagram）",
    "🐦 社交平台（X）",
    "👥 社交平台（Facebook）",
    "🗨️ 社区论坛（Reddit）",
    "🎬 视频平台（YouTube）",
    "🎥 流媒体（Netflix）",
    "🎵 短视频（TikTok）",
    "🏰 流媒体（Disney+）",
    "📺 流媒体（HBO）",
    "📦 流媒体（Prime Video）",
    "🎥 直播平台（Twitch）",
    "🎧 音乐服务（Spotify）",
    "🛠️ 代码托管（GitHub）",
    "🦊 代码托管（GitLab）",
    "🐳 容器服务（Docker）",
    "📦 软件包服务（NPM）",
    "🎮 游戏平台（Steam）",
    "🟣 游戏平台（Epic）",
    "🟩 游戏平台（Xbox）",
    "🔷 游戏平台（PlayStation）",
    "🔴 游戏平台（Nintendo）",
    "🚝 测速工具",
    "💳 支付服务（PayPal）",
    "💸 跨境汇款（Wise）",
    "🟦 欧易（OKX）",
    "🟨 币安（Binance）",
    "🟪 交易平台（Bybit）",
    "🟥 创意软件（Adobe）",
    "🍎 苹果服务（Apple）",
    "🔎 谷歌服务（Google）",
    "☁️ 网络服务（Cloudflare）",
    "🪟 微软服务（Microsoft）",
    "☁️ 微软云盘（OneDrive）",
    "📦 云存储（Dropbox）",
    "🌍 境外网站",
)

# The production subscriptions currently expose nodes in these eight regions.
# Less common/future regions are still reachable through the global pools and
# the catch-all "other regions" pool, so they do not need an empty dashboard
# card and a permanently running health checker of their own.
REGION_NODE_GROUPS = ()

COUNTRY_NODE_GROUPS = (
    "🇭🇰 香港",
    "🇹🇼 台湾",
    "🇯🇵 日本",
    "🇸🇬 新加坡",
    "🇰🇷 韩国",
    "🇬🇧 英国",
    "🇩🇪 德国",
    "🇺🇸 美国",
)

FUNCTIONAL_NODE_GROUPS = (
    "⚡ 专线节点",
    "🏠 原生住宅",
    "🎬 流媒体节点",
    "💰 低倍率节点",
    "🌍 其他地区",
)

# Business-aware automatic pools probe the real service instead of inferring
# availability from a generic latency endpoint.  They are intentionally kept
# separate from the business selectors so a user can still override one
# service without changing the shared AI or streaming parent policy.
CAPABILITY_NODE_GROUPS = (
    "🤖 ChatGPT 专用节点池",
    "🟠 Claude 专用节点池",
    "🔵 Gemini 专用节点池",
    "🎥 Netflix 专用节点池",
)

# Business selectors are ordered for this mainland-China one-arm-router setup:
# stable/common exits first, nearby locations next, then regional navigation
# and long-distance country choices. "Other regions" remains the final proxy
# choice because it is the least specific fallback.
NODE_SELECTION_GROUPS = (
    "🛟 稳定自动",
    "🧭 手动选择",
    "♻️ 自动选择",
)

# This is a policy gateway that deliberately funnels traffic into a node group;
# it is selectable from business strategies but is not itself a node pool.
POLICY_GATEWAY_GROUPS = (
    "🔒 隐私代理",
)

NEARBY_COUNTRY_NODE_GROUPS = (
    "🇭🇰 香港",
    "🇹🇼 台湾",
    "🇯🇵 日本",
    "🇸🇬 新加坡",
    "🇰🇷 韩国",
)

OTHER_COUNTRY_NODE_GROUPS = tuple(
    name for name in COUNTRY_NODE_GROUPS if name not in NEARBY_COUNTRY_NODE_GROUPS
)

BUSINESS_PROXY_GROUP_CHOICES = (
    NODE_SELECTION_GROUPS[0],
    *POLICY_GATEWAY_GROUPS,
    *NODE_SELECTION_GROUPS[1:],
    *FUNCTIONAL_NODE_GROUPS[:-1],
    *NEARBY_COUNTRY_NODE_GROUPS,
    *OTHER_COUNTRY_NODE_GROUPS,
    FUNCTIONAL_NODE_GROUPS[-1],
)

# Built-in actions are valid choices, but are no longer injected into every
# business selector. Each group declares only the actions that make sense for
# that service so the dashboard stays safe and quick to operate.
BUSINESS_BUILTIN_CHOICES = (
    "DIRECT",
    "REJECT",
)

# Every business selector exposes the same direct, automatic, manual, country,
# streaming, and blocking controls. The group's existing first choice remains
# first so service defaults and parent inheritance never change.
STANDARD_BUSINESS_MENU_CHOICES = (
    "DIRECT",
    "🔒 隐私代理",
    NODE_SELECTION_GROUPS[0],
    "♻️ 自动选择",
    "🧭 手动选择",
    "🇭🇰 香港",
    "🇹🇼 台湾",
    "🇯🇵 日本",
    "🇸🇬 新加坡",
    "🇰🇷 韩国",
    "🇺🇸 美国",
    "🇬🇧 英国",
    "🇩🇪 德国",
    "🎬 流媒体节点",
    "REJECT",
)

# Preserve the broader functional parent as an explicit manual escape hatch
# when a business-specific pool becomes the new default.  These entries appear
# directly after the default and before the common controls.
BUSINESS_ADDITIONAL_MENU_CHOICES = {
    "🤖 对话助手（ChatGPT）": ("🧠 人工智能",),
    "🟠 对话助手（Claude）": ("🧠 人工智能",),
    "🔵 对话助手（Gemini）": ("🧠 人工智能",),
}

# Infrastructure controls are not ordinary service menus. Keep them compact so
# a country override cannot accidentally send LAN addresses through a remote
# node or make operating-system connectivity checks report a false outage.
CONTROL_GROUP_MENUS = {
    "🏠 本地网络": ("DIRECT", "REJECT"),
    "🌐 联网检测": ("DIRECT", "🔒 隐私代理"),
    "🚫 广告拦截": ("REJECT", "DIRECT", "🔒 隐私代理"),
}

BUSINESS_STRATEGY_CHOICES = (
    *BUSINESS_PROXY_GROUP_CHOICES,
    *BUSINESS_BUILTIN_CHOICES,
)


# Zashboard orders outer proxy-group cards through the order exposed by the
# Mihomo GLOBAL group. The runtime patch therefore keeps one explicit order for
# every generated group: common controls, local/business policies, node pools,
# then diagnostic/advanced groups.
LOCAL_BUSINESS_GROUPS = (
    "🏠 本地网络",
    "🌐 联网检测",
    "🏦 国内银行",
    "🏛️ 政务服务",
    "📈 国内证券",
    "☁️ 国内网盘",
    "🎵 国内音乐",
    "⬇️ 游戏下载",
    "🚝 测速工具",
    "🚫 广告拦截",
)

OTHER_BUSINESS_GROUPS = tuple(
    name for name in BUSINESS_STRATEGY_GROUPS if name not in LOCAL_BUSINESS_GROUPS
)

DASHBOARD_COMMON_GROUPS = (
    "🛟 稳定自动",
    "🔒 隐私代理",
    "🧭 手动选择",
    "♻️ 自动选择",
    "🚀 手动选择",
    "🌐 默认策略",
    "🐟 漏网之鱼",
)

DASHBOARD_NODE_GROUPS = (
    *FUNCTIONAL_NODE_GROUPS[:-1],
    *NEARBY_COUNTRY_NODE_GROUPS,
    *OTHER_COUNTRY_NODE_GROUPS,
    FUNCTIONAL_NODE_GROUPS[-1],
)

DASHBOARD_CAPABILITY_GROUPS = CAPABILITY_NODE_GROUPS

DASHBOARD_ADVANCED_GROUPS = (
    "🔬 节点归属校验",
    "🇸🇬 指定新加坡",
    "🇺🇸 指定美国",
    "🛡️ 实时通信（WebRTC）",
    "🔀 非标端口",
    "🐟 遵循规则",
)

DASHBOARD_PROXY_GROUP_ORDER = (
    *DASHBOARD_COMMON_GROUPS,
    *LOCAL_BUSINESS_GROUPS,
    *OTHER_BUSINESS_GROUPS,
    *DASHBOARD_CAPABILITY_GROUPS,
    *DASHBOARD_NODE_GROUPS,
    *DASHBOARD_ADVANCED_GROUPS,
)

# One shared selector is appended; existing cards keep their order.
from strict_catalog import choices as strict_choices, policy as strict_policy
DASHBOARD_PROXY_GROUP_ORDER += tuple(dict.fromkeys(
    choice for name in BUSINESS_STRATEGY_GROUPS
    if name in strict_policy()["business_groups"]
    for choice in strict_choices(name)
))
