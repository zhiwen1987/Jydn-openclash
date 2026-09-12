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

REGION_NODE_GROUPS = (
    "🌏 亚洲国家",
    "🇪🇺 欧洲国家",
    "🌎 美洲国家",
    "🌍 中东非洲",
    "🌊 大洋洲",
)

COUNTRY_NODE_GROUPS = (
    "🇭🇰 香港",
    "🇹🇼 台湾",
    "🇯🇵 日本",
    "🇸🇬 新加坡",
    "🇰🇷 韩国",
    "🇮🇳 印度",
    "🇻🇳 越南",
    "🇹🇭 泰国",
    "🇲🇾 马来西亚",
    "🇵🇭 菲律宾",
    "🇮🇩 印度尼西亚",
    "🇲🇲 缅甸",
    "🇵🇰 巴基斯坦",
    "🇬🇧 英国",
    "🇩🇪 德国",
    "🇫🇷 法国",
    "🇳🇱 荷兰",
    "🇪🇸 西班牙",
    "🇨🇭 瑞士",
    "🇸🇪 瑞典",
    "🇷🇺 俄罗斯",
    "🇹🇷 土耳其",
    "🇬🇷 希腊",
    "🇳🇴 挪威",
    "🇺🇸 美国",
    "🇨🇦 加拿大",
    "🇲🇽 墨西哥",
    "🇧🇷 巴西",
    "🇨🇱 智利",
    "🇨🇴 哥伦比亚",
    "🇦🇪 阿联酋",
    "🇸🇦 沙特阿拉伯",
    "🇮🇱 以色列",
    "🇿🇦 南非",
    "🇳🇬 尼日利亚",
    "🇦🇺 澳大利亚",
)

FUNCTIONAL_NODE_GROUPS = (
    "⚡ 专线节点",
    "🏠 原生住宅",
    "🎬 流媒体节点",
    "💰 低倍率节点",
    "🌍 其他地区",
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
    *REGION_NODE_GROUPS,
    *OTHER_COUNTRY_NODE_GROUPS,
    FUNCTIONAL_NODE_GROUPS[-1],
)

# The current group default stays first. These built-in actions are then kept at
# the front of every selector before all other proxy-group choices.
BUSINESS_BUILTIN_CHOICES = (
    "DIRECT",
    "REJECT",
)

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
    *REGION_NODE_GROUPS,
    *OTHER_COUNTRY_NODE_GROUPS,
    FUNCTIONAL_NODE_GROUPS[-1],
)

DASHBOARD_ADVANCED_GROUPS = (
    "🔬 节点归属校验",
    "🇸🇬 指定新加坡",
    "🛡️ 实时通信（WebRTC）",
    "🔀 非标端口",
    "🐟 遵循规则",
)

DASHBOARD_PROXY_GROUP_ORDER = (
    *DASHBOARD_COMMON_GROUPS,
    *LOCAL_BUSINESS_GROUPS,
    *OTHER_BUSINESS_GROUPS,
    *DASHBOARD_NODE_GROUPS,
    *DASHBOARD_ADVANCED_GROUPS,
)
