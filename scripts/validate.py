#!/usr/bin/env python3
import re
import json
import sys
from pathlib import Path

from group_catalog import (
    BUSINESS_BUILTIN_CHOICES,
    BUSINESS_PROXY_GROUP_CHOICES,
    BUSINESS_STRATEGY_CHOICES,
    BUSINESS_STRATEGY_GROUPS,
    COUNTRY_NODE_GROUPS,
    DASHBOARD_PROXY_GROUP_ORDER,
    FUNCTIONAL_NODE_GROUPS as FUNCTIONAL_NODE_GROUP_NAMES,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "metafenliu.ini"
BASE = ROOT / "upstream" / "metafenliu.ini"
OVERWRITE = ROOT / "modules" / "openclash-dns-privacy-override.yaml"
ADVANCED_ROUTING_EXAMPLE = ROOT / "modules" / "openclash-source-inbound-subrule.example.yaml"
RUNTIME_CATALOG = ROOT / "modules" / "openclash-business-group-catalog.json"
RUNTIME_PATCH = ROOT / "scripts" / "patch_runtime_groups.rb"
RUNTIME_HOOK = ROOT / "scripts" / "jydn_group_filter_hook.sh"
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
COUNTRY_GROUPS = set(COUNTRY_NODE_GROUPS)
LEGACY_COUNTRY_CODES = {
    "HK", "TW", "JP", "SG", "KR", "IN", "VN", "TH", "MY", "PH", "ID",
    "MM", "PK", "UK", "GB", "DE", "FR", "NL", "ES", "CH", "SE", "RU",
    "TR", "GR", "NO", "US", "CA", "MX", "BR", "CL", "CO", "AE", "SA",
    "IL", "ZA", "NG", "AU",
}
FUNCTIONAL_NODE_GROUPS = set(FUNCTIONAL_NODE_GROUP_NAMES)
REGION_GROUPS = {
    "🌏 亚洲国家": {"🇭🇰 香港", "🇹🇼 台湾", "🇯🇵 日本", "🇸🇬 新加坡", "🇰🇷 韩国", "🇮🇳 印度", "🇻🇳 越南", "🇹🇭 泰国", "🇲🇾 马来西亚", "🇵🇭 菲律宾", "🇮🇩 印度尼西亚", "🇲🇲 缅甸", "🇵🇰 巴基斯坦"},
    "🇪🇺 欧洲国家": {"🇬🇧 英国", "🇩🇪 德国", "🇫🇷 法国", "🇳🇱 荷兰", "🇪🇸 西班牙", "🇨🇭 瑞士", "🇸🇪 瑞典", "🇷🇺 俄罗斯", "🇹🇷 土耳其", "🇬🇷 希腊", "🇳🇴 挪威"},
    "🌎 美洲国家": {"🇺🇸 美国", "🇨🇦 加拿大", "🇲🇽 墨西哥", "🇧🇷 巴西", "🇨🇱 智利", "🇨🇴 哥伦比亚"},
    "🌍 中东非洲": {"🇦🇪 阿联酋", "🇸🇦 沙特阿拉伯", "🇮🇱 以色列", "🇿🇦 南非", "🇳🇬 尼日利亚"},
    "🌊 大洋洲": {"🇦🇺 澳大利亚"},
}
REQUIRED_URL_TEST_GROUPS = {"♻️ 自动选择", "🛟 稳定自动"} | COUNTRY_GROUPS | FUNCTIONAL_NODE_GROUPS
STATUS_FILTER_FRAGMENT = "(剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|刷新订阅|刷新失败|更新失败|取消订阅时限)"
GEO_CHECK_GROUP = "🔬 节点归属校验"
COUNTRY_NODE_FIXTURES = {
    "🇭🇰 香港": "🇭🇰香港 01", "🇹🇼 台湾": "🇨🇳台湾 01",
    "🇯🇵 日本": "Tokyo-01", "🇸🇬 新加坡": "SG 01", "🇰🇷 韩国": "🇰🇷韩国 01",
    "🇮🇳 印度": "🇮🇳印度 01", "🇻🇳 越南": "🇻🇳越南 01", "🇹🇭 泰国": "🇹🇭泰国 01",
    "🇲🇾 马来西亚": "🇲🇾马来西亚 01", "🇵🇭 菲律宾": "🇵🇭菲律宾 01",
    "🇮🇩 印度尼西亚": "🇮🇩印度尼西亚 01", "🇲🇲 缅甸": "🇲🇲缅甸 01",
    "🇵🇰 巴基斯坦": "🇵🇰巴基斯坦 01", "🇬🇧 英国": "London-01",
    "🇩🇪 德国": "🇩🇪德国 01", "🇫🇷 法国": "🇫🇷法国 01", "🇳🇱 荷兰": "🇳🇱荷兰 01",
    "🇪🇸 西班牙": "🇪🇸西班牙 01", "🇨🇭 瑞士": "🇨🇭瑞士 01",
    "🇸🇪 瑞典": "🇸🇪瑞典 01", "🇷🇺 俄罗斯": "Moscow-01",
    "🇹🇷 土耳其": "🇹🇷土耳其 01", "🇬🇷 希腊": "🇬🇷希腊 01",
    "🇳🇴 挪威": "🇳🇴挪威 01", "🇺🇸 美国": "New York 01",
    "🇨🇦 加拿大": "🇨🇦加拿大 01", "🇲🇽 墨西哥": "🇲🇽墨西哥 01",
    "🇧🇷 巴西": "São Paulo 01", "🇨🇱 智利": "🇨🇱智利 01",
    "🇨🇴 哥伦比亚": "Bogotá-01", "🇦🇪 阿联酋": "UAE-01",
    "🇸🇦 沙特阿拉伯": "🇸🇦沙特 01", "🇮🇱 以色列": "🇮🇱以色列 01",
    "🇿🇦 南非": "🇿🇦南非 01", "🇳🇬 尼日利亚": "🇳🇬尼日利亚 01",
    "🇦🇺 澳大利亚": "Sydney-01",
}
FUNCTIONAL_NODE_FIXTURES = {
    "⚡ 专线节点": "🇭🇰香港 IEPL 01",
    "🏠 原生住宅": "🇭🇰香港住宅IP 01",
    "🎬 流媒体节点": "🇸🇬新加坡 Netflix 01",
    "💰 低倍率节点": "🇯🇵日本 0.5x 01",
}
STATUS_PSEUDO_NODES = (
    "剩余流量：883.58 GB",
    "距离下次重置剩余：18 天",
    "套餐到期：2028-12-31",
)
REQUIRED_DIRECT_GEOSITES = {"baidu", "geolocation-cn"}
REQUIRED_ROUTED_GEOSITES = {
    ("🟥 创意软件（Adobe）", "adobe"),
    ("🚫 广告拦截", "category-ads-all"),
    ("⬇️ 游戏下载", "category-game-platforms-download"),
    ("🚝 测速工具", "category-speedtest"),
    ("🏦 国内银行", "category-bank-cn"),
    ("☁️ 国内网盘", "aliyun-drive"),
    ("☁️ 国内网盘", "115"),
    ("📦 笔记协作（Notion）", "notion"),
    ("🤖 对话助手（ChatGPT）", "openai"),
    ("🧠 人工智能", "category-ai-!cn"),
    ("📨 电报通讯（Telegram）", "telegram"),
    ("💬 聊天社区（Discord）", "discord"),
    ("🟢 通讯工具（WhatsApp）", "whatsapp"),
    ("🔐 安全通信（Signal）", "signal"),
    ("🟩 通讯工具（LINE）", "line"),
    ("📞 即时通讯", "category-communication"),
    ("📸 图片社交（Instagram）", "instagram"),
    ("🐦 社交平台（X）", "twitter"),
    ("👥 社交平台（Facebook）", "facebook"),
    ("🗨️ 社区论坛（Reddit）", "reddit"),
    ("💬 社交平台", "category-social-media-!cn"),
    ("🎬 视频平台（YouTube）", "youtube"),
    ("🎥 流媒体（Netflix）", "netflix"),
    ("🎵 短视频（TikTok）", "tiktok"),
    ("🏰 流媒体（Disney+）", "disney"),
    ("📺 流媒体（HBO）", "hbo"),
    ("📦 流媒体（Prime Video）", "primevideo"),
    ("🎥 直播平台（Twitch）", "twitch"),
    ("🎧 音乐服务（Spotify）", "spotify"),
    ("🎞️ 海外影音", "category-entertainment"),
    ("🛠️ 代码托管（GitHub）", "github"),
    ("🦊 代码托管（GitLab）", "gitlab"),
    ("🐳 容器服务（Docker）", "docker"),
    ("📦 软件包服务（NPM）", "npmjs"),
    ("💻 开发服务", "category-dev"),
    ("🎮 游戏平台（Steam）", "steam"),
    ("🟣 游戏平台（Epic）", "epicgames"),
    ("🟩 游戏平台（Xbox）", "xbox"),
    ("🔷 游戏平台（PlayStation）", "playstation"),
    ("🔴 游戏平台（Nintendo）", "nintendo"),
    ("🕹️ 游戏服务", "category-games"),
    ("💳 支付服务（PayPal）", "paypal"),
    ("💸 跨境汇款（Wise）", "wise"),
    ("🟦 欧易（OKX）", "okx"),
    ("🟨 币安（Binance）", "binance"),
    ("🟪 交易平台（Bybit）", "bybit"),
    ("🪙 数字货币", "category-cryptocurrency"),
    ("💳 海外支付", "category-finance"),
    ("🍎 苹果服务（Apple）", "apple"),
    ("🔎 谷歌服务（Google）", "google"),
    ("☁️ 网络服务（Cloudflare）", "cloudflare"),
    ("🪟 微软服务（Microsoft）", "microsoft"),
    ("☁️ 微软云盘（OneDrive）", "onedrive"),
    ("📦 云存储（Dropbox）", "dropbox"),
    ("📚 海外学术", "category-scholar-!cn"),
    ("🛒 海外电商", "category-ecommerce"),
}
REQUIRED_DIRECT_EXCEPTIONS = {
    "'+.pbccrc.org.cn'",
    "'+.bankofbeijing.com.cn'",
    "'+.alipan.com'",
    "'+.aliyundrive.net'",
    "'+.baidupcs.com'",
    "'+.115cloud.com'",
    "'+.12315.cn'",
    "'+.12321.cn'",
    "'+.12306.cn'",
    "'+.chsi.com.cn'",
}
REQUIRED_RULE_FILES = {
    "bank-cn.yaml",
    "government-cn.yaml",
    "securities-cn.yaml",
    "cloud-drive-cn.yaml",
    "connectivity-check.yaml",
    "apple-ip-asn.yaml",
    "google-ip-asn.yaml",
    "meta-ip-asn.yaml",
    "music-cn.yaml",
    "netflix-ip-asn.yaml",
    "development.yaml",
    "node-geo-check.yaml",
    "telegram-ip-asn.yaml",
    "webrtc-client.yaml",
}
REQUIRED_RULE_FILE_ENTRIES = {
    "bank-cn.yaml": {"'+.pbccrc.org.cn'", "'+.bankofbeijing.com.cn'"},
    "government-cn.yaml": {"'+.gov.cn'", "'+.12315.cn'", "'+.12306.cn'"},
    "securities-cn.yaml": {"'+.csrc.gov.cn'", "'+.sse.com.cn'", "'+.chinaclear.cn'"},
    "cloud-drive-cn.yaml": {"'+.alipan.com'", "'+.baidupcs.com'", "'+.115cloud.com'"},
    "connectivity-check.yaml": {
        "'DOMAIN,connectivitycheck.gstatic.com'",
        "'DOMAIN-SUFFIX,msftconnecttest.com'",
        "'DOMAIN-SUFFIX,msftncsi.com'",
        "'DOMAIN-KEYWORD,connectivitycheck'",
        "'DOMAIN-WILDCARD,time*.apple.com'",
        "'DOMAIN-REGEX,^time[0-9]*\\.(apple|windows)\\.com$'",
        "'AND,((NETWORK,udp),(SRC-PORT,123),(DST-PORT,123))'",
    },
    "apple-ip-asn.yaml": {"'IP-ASN,714,no-resolve'"},
    "google-ip-asn.yaml": {"'IP-ASN,15169,no-resolve'"},
    "meta-ip-asn.yaml": {"'IP-ASN,32934,no-resolve'"},
    "music-cn.yaml": {"'+.kugou.com'", "'music.163.com'", "'y.qq.com'"},
    "netflix-ip-asn.yaml": {"'IP-ASN,2906,no-resolve'"},
    "telegram-ip-asn.yaml": {
        "'IP-ASN,62041,no-resolve'",
        "'IP-ASN,62014,no-resolve'",
        "'IP-ASN,59930,no-resolve'",
        "'IP-ASN,44907,no-resolve'",
        "'IP-ASN,211157,no-resolve'",
    },
    "webrtc-client.yaml": {
        "'AND,((SRC-IP-CIDR,10.88.0.0/24),(NOT,((SRC-IP-CIDR,10.88.0.254/32))),(NETWORK,udp),(OR,((DST-PORT,3478-3481),(DST-PORT,5349))))'",
        "'AND,((SRC-IP-CIDR,10.88.0.0/24),(NOT,((SRC-IP-CIDR,10.88.0.254/32))),(NETWORK,tcp),(DST-PORT,5349))'",
    },
}
EXPECTED_DEFAULT_TARGETS = {
    "🏠 本地网络": "DIRECT",
    "🌐 联网检测": "DIRECT",
    "🧠 人工智能": "🔒 隐私代理",
    "📞 即时通讯": "🔒 隐私代理",
    "💬 社交平台": "🔒 隐私代理",
    "🌐 Meta 平台": "💬 社交平台",
    "🎞️ 海外影音": "🔒 隐私代理",
    "💻 开发服务": "🔒 隐私代理",
    "☁️ 云端办公": "🔒 隐私代理",
    "🕹️ 游戏服务": "🔒 隐私代理",
    "💳 海外支付": "🧭 手动选择",
    "🪙 数字货币": "🧭 手动选择",
    "📚 海外学术": "🔒 隐私代理",
    "🛒 海外电商": "🔒 隐私代理",
    "🏦 国内银行": "DIRECT",
    "🏛️ 政务服务": "DIRECT",
    "📈 国内证券": "DIRECT",
    "☁️ 国内网盘": "DIRECT",
    "🎵 国内音乐": "DIRECT",
    "⬇️ 游戏下载": "DIRECT",
    "🚫 广告拦截": "REJECT",
    "📦 笔记协作（Notion）": "☁️ 云端办公",
    "🤖 对话助手（ChatGPT）": "🧠 人工智能",
    "📨 电报通讯（Telegram）": "📞 即时通讯",
    "💬 聊天社区（Discord）": "📞 即时通讯",
    "🟢 通讯工具（WhatsApp）": "📞 即时通讯",
    "🔐 安全通信（Signal）": "📞 即时通讯",
    "🟩 通讯工具（LINE）": "📞 即时通讯",
    "📸 图片社交（Instagram）": "💬 社交平台",
    "🐦 社交平台（X）": "💬 社交平台",
    "👥 社交平台（Facebook）": "💬 社交平台",
    "🗨️ 社区论坛（Reddit）": "💬 社交平台",
    "🎬 视频平台（YouTube）": "🎞️ 海外影音",
    "🎥 流媒体（Netflix）": "🎞️ 海外影音",
    "🎵 短视频（TikTok）": "🎞️ 海外影音",
    "🏰 流媒体（Disney+）": "🎞️ 海外影音",
    "📺 流媒体（HBO）": "🎞️ 海外影音",
    "📦 流媒体（Prime Video）": "🎞️ 海外影音",
    "🎥 直播平台（Twitch）": "🎞️ 海外影音",
    "🎧 音乐服务（Spotify）": "🎞️ 海外影音",
    "🛠️ 代码托管（GitHub）": "💻 开发服务",
    "🦊 代码托管（GitLab）": "💻 开发服务",
    "🐳 容器服务（Docker）": "💻 开发服务",
    "📦 软件包服务（NPM）": "💻 开发服务",
    "🎮 游戏平台（Steam）": "🕹️ 游戏服务",
    "🟣 游戏平台（Epic）": "🕹️ 游戏服务",
    "🟩 游戏平台（Xbox）": "🕹️ 游戏服务",
    "🔷 游戏平台（PlayStation）": "🕹️ 游戏服务",
    "🔴 游戏平台（Nintendo）": "🕹️ 游戏服务",
    "🚝 测速工具": "DIRECT",
    "💳 支付服务（PayPal）": "💳 海外支付",
    "💸 跨境汇款（Wise）": "💳 海外支付",
    "🟦 欧易（OKX）": "🪙 数字货币",
    "🟨 币安（Binance）": "🪙 数字货币",
    "🟪 交易平台（Bybit）": "🪙 数字货币",
    "🟥 创意软件（Adobe）": "REJECT",
    "🍎 苹果服务（Apple）": "DIRECT",
    "🔎 谷歌服务（Google）": "🔒 隐私代理",
    "☁️ 网络服务（Cloudflare）": "🔒 隐私代理",
    "🪟 微软服务（Microsoft）": "DIRECT",
    "☁️ 微软云盘（OneDrive）": "☁️ 云端办公",
    "📦 云存储（Dropbox）": "☁️ 云端办公",
    "🌍 境外网站": "🔒 隐私代理",
}
FIRST_MATCH_ORDER = (
    ("ruleset=🤖 对话助手（ChatGPT）,[]GEOSITE,openai", "ruleset=🧠 人工智能,[]GEOSITE,category-ai-!cn"),
    ("ruleset=📨 电报通讯（Telegram）,[]GEOSITE,telegram", "ruleset=📞 即时通讯,[]GEOSITE,category-communication"),
    ("ruleset=📸 图片社交（Instagram）,[]GEOSITE,instagram", "ruleset=💬 社交平台,[]GEOSITE,category-social-media-!cn"),
    ("ruleset=🎥 流媒体（Netflix）,[]GEOSITE,netflix", "ruleset=🎞️ 海外影音,[]GEOSITE,category-entertainment"),
    ("ruleset=🛠️ 代码托管（GitHub）,[]GEOSITE,github", "ruleset=💻 开发服务,[]GEOSITE,category-dev"),
    ("ruleset=🎮 游戏平台（Steam）,[]GEOSITE,steam", "ruleset=🕹️ 游戏服务,[]GEOSITE,category-games"),
    ("ruleset=🟦 欧易（OKX）,[]GEOSITE,okx", "ruleset=🪙 数字货币,[]GEOSITE,category-cryptocurrency"),
    ("ruleset=🪙 数字货币,[]GEOSITE,category-cryptocurrency", "ruleset=💳 海外支付,[]GEOSITE,category-finance"),
    ("ruleset=☁️ 微软云盘（OneDrive）,[]GEOSITE,onedrive", "ruleset=🪟 微软服务（Microsoft）,[]GEOSITE,microsoft"),
    ("ruleset=⬇️ 游戏下载,[]GEOSITE,category-game-platforms-download", "ruleset=DIRECT,[]GEOSITE,category-games@cn"),
    ("ruleset=🏦 国内银行,clash-domain:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/bank-cn.yaml,86400", "ruleset=DIRECT,[]GEOSITE,geolocation-cn"),
    ("ruleset=🏛️ 政务服务,clash-domain:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/government-cn.yaml,86400", "ruleset=DIRECT,[]GEOSITE,geolocation-cn"),
    ("ruleset=📈 国内证券,clash-domain:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/securities-cn.yaml,86400", "ruleset=DIRECT,[]GEOSITE,geolocation-cn"),
    ("ruleset=☁️ 国内网盘,clash-domain:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/cloud-drive-cn.yaml,86400", "ruleset=DIRECT,[]GEOSITE,geolocation-cn"),
    ("ruleset=🎵 国内音乐,clash-domain:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/music-cn.yaml,86400", "ruleset=DIRECT,[]GEOSITE,geolocation-cn"),
)

REQUIRED_PRECISION_RULES = {
    "ruleset=🏠 本地网络,[]DOMAIN,localhost",
    "ruleset=🏠 本地网络,[]DOMAIN-SUFFIX,home.arpa",
    "ruleset=🏠 本地网络,[]IP-CIDR,10.0.0.0/8,no-resolve",
    "ruleset=🏠 本地网络,[]IP-CIDR6,fc00::/7,no-resolve",
    "ruleset=🏠 本地网络,[]GEOSITE,private",
    "ruleset=🏠 本地网络,[]GEOIP,private,no-resolve",
    "ruleset=📨 电报通讯（Telegram）,clash-classic:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/telegram-ip-asn.yaml,86400",
    "ruleset=🌐 Meta 平台,clash-classic:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/meta-ip-asn.yaml,86400",
    "ruleset=🎥 流媒体（Netflix）,clash-classic:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/netflix-ip-asn.yaml,86400",
    "ruleset=🍎 苹果服务（Apple）,clash-classic:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/apple-ip-asn.yaml,86400",
    "ruleset=🔎 谷歌服务（Google）,clash-classic:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/google-ip-asn.yaml,86400",
}

WEBRTC_LOGIC_RULES = {
    "ruleset=🛡️ 实时通信（WebRTC）,clash-classic:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/webrtc-client.yaml,86400",
}


def active_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]


def node_filter(line: str) -> str | None:
    """Return the first node-name regex from one subconverter group line."""
    for field in line.split("`")[2:]:
        if not field or field.startswith("[]") or field.startswith("http"):
            continue
        return field
    return None


def validate_config(errors: list[str]) -> None:
    text = CONFIG.read_text(encoding="utf-8")
    lines = active_lines(text)
    group_lines = [line for line in lines if line.startswith("custom_proxy_group=")]
    rule_lines = [line for line in lines if line.startswith("ruleset=")]

    groups: dict[str, str] = {}
    group_definitions: dict[str, str] = {}
    for line in group_lines:
        definition = line.split("=", 1)[1]
        fields = definition.split("`")
        if len(fields) < 2:
            errors.append(f"策略组格式错误：{line}")
            continue
        name, group_type = fields[0].strip(), fields[1].strip()
        if name in groups:
            errors.append(f"策略组重复定义：{name}")
        groups[name] = group_type
        group_definitions[name] = line

    for line in rule_lines:
        target = line.split("=", 1)[1].split(",", 1)[0].strip()
        if target not in BUILTIN_POLICIES and target not in groups:
            errors.append(f"规则引用了不存在的策略组：{target}")

    group_reference = re.compile(r"`\[\]([^`]+)")
    group_edges: dict[str, list[str]] = {}
    for line in group_lines:
        owner = line.split("=", 1)[1].split("`", 1)[0].strip()
        group_edges[owner] = []
        for target in group_reference.findall(line):
            target = target.strip()
            if target not in BUILTIN_POLICIES and target not in groups:
                errors.append(f"策略组 {owner} 引用了不存在的策略：{target}")
            elif target in groups:
                group_edges[owner].append(target)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit_group(name: str, path: list[str]) -> None:
        if name in visiting:
            start = path.index(name)
            errors.append("策略组存在循环引用：" + " → ".join(path[start:] + [name]))
            return
        if name in visited:
            return
        visiting.add(name)
        path.append(name)
        for target in group_edges.get(name, []):
            visit_group(target, path)
        path.pop()
        visiting.remove(name)
        visited.add(name)

    for name in groups:
        visit_group(name, [])

    for name in sorted(REQUIRED_URL_TEST_GROUPS):
        if name not in groups:
            errors.append(f"缺少自动测速组：{name}")
            continue
        if groups[name] != "url-test":
            errors.append(f"{name} 必须是 url-test，当前为 {groups[name]}")
            continue
        line = next(
            item for item in group_lines if item.startswith(f"custom_proxy_group={name}`")
        )
        fields = line.split("`")
        if len(fields) < 5 or "https://cp.cloudflare.com/generate_204" not in fields:
            errors.append(f"{name} 必须使用 Cloudflare HTTPS 测速地址")
        if not fields[-1].endswith("120,,10"):
            errors.append(f"{name} 必须使用 120 秒间隔和 10 ms 容差")

    for name in sorted(COUNTRY_GROUPS | FUNCTIONAL_NODE_GROUPS):
        line = next(
            (item for item in group_lines if item.startswith(f"custom_proxy_group={name}`")),
            None,
        )
        if line is not None and "`[]REJECT`" not in line:
            errors.append(f"叶子节点组 {name} 必须用 REJECT 防止空组回退 DIRECT")

    for region, members in REGION_GROUPS.items():
        line = next(
            (item for item in group_lines if item.startswith(f"custom_proxy_group={region}`")),
            None,
        )
        if line is None:
            errors.append(f"缺少地区导航组：{region}")
            continue
        if groups.get(region) != "select":
            errors.append(f"地区导航组 {region} 必须是 select")
        for member in sorted(members):
            if f"`[]{member}" not in line:
                errors.append(f"地区导航组 {region} 缺少国家组：{member}")

    for name in ("🧭 手动选择", "♻️ 自动选择", "🌍 其他地区"):
        line = next(
            (item for item in group_lines if item.startswith(f"custom_proxy_group={name}`")),
            None,
        )
        if line is not None and STATUS_FILTER_FRAGMENT not in line:
            errors.append(f"节点池 {name} 缺少订阅提示过滤")

    manual_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🚀 手动选择`")),
        None,
    )
    for target in set(REGION_GROUPS) | FUNCTIONAL_NODE_GROUPS | {"🧭 手动选择"}:
        if manual_line is not None and f"`[]{target}" not in manual_line:
            errors.append(f"手动选择缺少节点分类入口：{target}")

    if "🧊 冷门节点" in groups:
        errors.append("旧的冷门节点组仍然存在，应由全量国家组和其他地区组替代")

    legacy_country_groups = sorted(
        name
        for name in groups
        if len(name.rsplit(" ", 1)) == 2
        and name.rsplit(" ", 1)[1] in LEGACY_COUNTRY_CODES
    )
    if legacy_country_groups:
        errors.append(
            "国家节点组仍使用英文代码名称：" + ", ".join(legacy_country_groups)
        )

    geo_check_line = group_definitions.get(GEO_CHECK_GROUP)
    if geo_check_line is None:
        errors.append(f"缺少在线节点归属校验组：{GEO_CHECK_GROUP}")
    else:
        if groups.get(GEO_CHECK_GROUP) != "select":
            errors.append(f"{GEO_CHECK_GROUP} 必须是 select，避免自动切换干扰逐节点查询")
        if "`[]🔒 隐私代理`" not in geo_check_line:
            errors.append(f"{GEO_CHECK_GROUP} 默认必须继承隐私代理")
        if STATUS_FILTER_FRAGMENT not in geo_check_line:
            errors.append(f"{GEO_CHECK_GROUP} 缺少订阅提示过滤")

    expected_geo_ruleset = (
        "ruleset=🔬 节点归属校验,clash-domain:"
        "https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/"
        "refs/heads/main/rules/node-geo-check.yaml,86400"
    )
    if expected_geo_ruleset not in lines:
        errors.append("缺少在线节点归属校验专用规则集")

    compiled_filters: dict[str, re.Pattern[str]] = {}
    for name in sorted(REQUIRED_URL_TEST_GROUPS | {"🧭 手动选择"}):
        line = group_definitions.get(name)
        pattern = node_filter(line) if line is not None else None
        if pattern is None:
            errors.append(f"节点池 {name} 缺少节点名筛选表达式")
            continue
        try:
            compiled_filters[name] = re.compile(pattern)
        except re.error as exc:
            errors.append(f"节点池 {name} 的正则表达式无效：{exc}")

    country_filters = {
        name: compiled_filters[name]
        for name in COUNTRY_GROUPS
        if name in compiled_filters
    }
    other_filter = compiled_filters.get("🌍 其他地区")
    for expected, node in COUNTRY_NODE_FIXTURES.items():
        matched = {name for name, pattern in country_filters.items() if pattern.search(node)}
        if matched != {expected}:
            errors.append(
                f"代表节点分类错误：{node} 应只属于 {expected}，实际为 {sorted(matched)}"
            )
        if other_filter is not None and other_filter.search(node):
            errors.append(f"已知国家节点误入其他地区：{node}")

    for expected, node in FUNCTIONAL_NODE_FIXTURES.items():
        pattern = compiled_filters.get(expected)
        if pattern is not None and not pattern.search(node):
            errors.append(f"实用节点分类错误：{node} 未进入 {expected}")

    for node in STATUS_PSEUDO_NODES:
        for name in ("🧭 手动选择", "♻️ 自动选择", "🌍 其他地区"):
            pattern = compiled_filters.get(name)
            if pattern is not None and pattern.search(node):
                errors.append(f"订阅提示误入节点池 {name}：{node}")

    if other_filter is not None and not other_filter.search("🇳🇿新西兰 01"):
        errors.append("未预定义国家节点应进入其他地区安全承接组")

    stable_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🛟 稳定自动`")),
        None,
    )
    if stable_line is not None:
        if "`[]♻️ 自动选择`" not in stable_line:
            errors.append("稳定自动组必须包含自动选择组作为非 DIRECT 兜底")
        if "CUCM|专线.*流媒体" not in stable_line:
            errors.append("稳定自动组缺少稳定线路筛选条件")

    privacy_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🔒 隐私代理`")),
        None,
    )
    if privacy_line is None:
        errors.append("缺少隐私代理策略组")
    else:
        expected = "custom_proxy_group=🔒 隐私代理`select`[]🛟 稳定自动"
        if privacy_line != expected:
            errors.append("隐私代理必须永久收口且只能引用稳定自动")

    for name, expected_target in sorted(EXPECTED_DEFAULT_TARGETS.items()):
        line = group_definitions.get(name)
        if line is None:
            errors.append(f"缺少实用精细策略组：{name}")
            continue
        refs = group_reference.findall(line)
        actual_target = refs[0].strip() if refs else None
        if actual_target != expected_target:
            errors.append(
                f"策略组 {name} 默认目标应为 {expected_target}，实际为 {actual_target}"
            )

    if set(BUSINESS_STRATEGY_GROUPS) != set(EXPECTED_DEFAULT_TARGETS):
        errors.append("业务策略组目录与默认行为校验目录不一致")

    dashboard_order = list(DASHBOARD_PROXY_GROUP_ORDER)
    if len(dashboard_order) != len(set(dashboard_order)):
        errors.append("Zashboard 外层代理组排序存在重复项")
    if set(dashboard_order) != set(group_definitions):
        missing_dashboard = sorted(set(group_definitions) - set(dashboard_order))
        unknown_dashboard = sorted(set(dashboard_order) - set(group_definitions))
        if missing_dashboard:
            errors.append(
                "Zashboard 外层排序缺少代理组：" + ", ".join(missing_dashboard)
            )
        if unknown_dashboard:
            errors.append(
                "Zashboard 外层排序包含未知组：" + ", ".join(unknown_dashboard)
            )

    for name in BUSINESS_STRATEGY_GROUPS:
        line = group_definitions.get(name)
        if line is None:
            continue
        ordered_references = [
            target.strip() for target in group_reference.findall(line)
        ]
        references = set(ordered_references)
        missing = [
            target
            for target in BUSINESS_STRATEGY_CHOICES
            if target not in references
        ]
        if missing:
            errors.append(
                f"业务策略组 {name} 未显示全部节点类代理组："
                + ", ".join(missing)
            )

        default_target = EXPECTED_DEFAULT_TARGETS[name]
        expected_front = list(
            dict.fromkeys([default_target, *BUSINESS_BUILTIN_CHOICES])
        )
        if ordered_references[: len(expected_front)] != expected_front:
            errors.append(
                f"策略组 {name} 前置顺序应为："
                + " → ".join(expected_front)
            )

        actual_proxy_order = [
            target
            for target in ordered_references
            if target in BUSINESS_PROXY_GROUP_CHOICES
        ]
        expected_proxy_order = list(
            dict.fromkeys(
                ([default_target] if default_target in BUSINESS_PROXY_GROUP_CHOICES else [])
                + list(BUSINESS_PROXY_GROUP_CHOICES)
            )
        )
        if actual_proxy_order != expected_proxy_order:
            errors.append(f"策略组 {name} 的代理组顺序不统一")

    if BUSINESS_BUILTIN_CHOICES != ("DIRECT", "REJECT"):
        errors.append("业务策略组必须按 DIRECT、REJECT 顺序补齐内置策略")

    missing_precision_rules = sorted(REQUIRED_PRECISION_RULES - set(lines))
    if missing_precision_rules:
        errors.append(
            "缺少多维精准分流规则：" + " | ".join(missing_precision_rules)
        )

    missing_webrtc_rules = sorted(WEBRTC_LOGIC_RULES - set(lines))
    if missing_webrtc_rules:
        errors.append(
            "WebRTC 未完整结合来源网段、网络、端口和逻辑规则："
            + " | ".join(missing_webrtc_rules)
        )

    connectivity_provider = (
        "ruleset=🌐 联网检测,clash-classic:"
        "https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/"
        "refs/heads/main/rules/connectivity-check.yaml,86400"
    )
    if connectivity_provider not in lines:
        errors.append("缺少联网检测 classical RULE-SET")

    unsafe_runtime_types = ("[]IN-NAME,", "[]IN-TYPE,", "[]SUB-RULE,")
    for marker in unsafe_runtime_types:
        if any(marker in line for line in rule_lines):
            errors.append(
                f"生成模板不得在未确认真实入站前启用 {marker[2:-1]}"
            )

    if "ruleset=🌐 默认策略,[]GEOSITE,geolocation-!cn" not in lines:
        errors.append("缺少 GEOSITE,geolocation-!cn 海外域名规则")
    for category in sorted(REQUIRED_DIRECT_GEOSITES):
        if f"ruleset=DIRECT,[]GEOSITE,{category}" not in lines:
            errors.append(f"缺少国内直连 GeoSite 分类：{category}")
    for target, category in sorted(REQUIRED_ROUTED_GEOSITES):
        if f"ruleset={target},[]GEOSITE,{category}" not in lines:
            errors.append(f"缺少精细分流 GeoSite：{category} → {target}")

    for specific, category in FIRST_MATCH_ORDER:
        if specific not in lines or category not in lines:
            continue
        if lines.index(specific) >= lines.index(category):
            errors.append(f"精细规则必须位于通用分类之前：{specific} → {category}")
    if "ruleset=🔒 隐私代理,[]GEOSITE,gfw" not in lines:
        errors.append("GFW 域名必须收口到隐私代理")
    if "ruleset=🚀 手动选择,[]GEOSITE,gfw" in lines:
        errors.append("GFW 域名仍受手动选择历史节点影响")
    if "ruleset=DIRECT,[]GEOSITE,cn" not in lines:
        errors.append("缺少 GEOSITE,cn 国内直连规则")
    if "ruleset=DIRECT,[]GEOIP,cn,no-resolve" not in lines:
        errors.append("缺少 GEOIP,cn 国内直连规则")

    overseas = lines.index("ruleset=🌐 默认策略,[]GEOSITE,geolocation-!cn")
    china = lines.index("ruleset=DIRECT,[]GEOSITE,cn")
    final = lines.index("ruleset=🐟 漏网之鱼,[]FINAL")
    if not overseas < china < final:
        errors.append("规则顺序应为 geolocation-!cn → GEOSITE,cn → FINAL")

    default_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🌐 默认策略`")),
        None,
    )
    if default_line != "custom_proxy_group=🌐 默认策略`select`[]🔒 隐私代理":
        errors.append("默认策略必须永久收口且只能引用隐私代理")

    final_line = next(
        (item for item in group_lines if item.startswith("custom_proxy_group=🐟 漏网之鱼`")),
        None,
    )
    if final_line != "custom_proxy_group=🐟 漏网之鱼`select`[]🌐 默认策略":
        errors.append("漏网之鱼必须永久收口且只能继承默认策略")

    if "zhiwen1987/openclash-rules" in text:
        errors.append("生成配置仍包含旧仓库 openclash-rules 地址")
    if "Bloomberg-zhong/openclash-rules" in text:
        errors.append("生成配置仍包含外部 singapore.yaml 地址")


def validate_base(errors: list[str]) -> None:
    text = BASE.read_text(encoding="utf-8")
    for marker in (
        "; >>> custom rules injection point <<<",
        "; >>> custom groups injection point <<<",
    ):
        count = text.count(marker)
        if count != 1:
            errors.append(f"基础模板标记数量错误（{count}）：{marker}")


def validate_rule_files(errors: list[str]) -> None:
    rule_paths = sorted((ROOT / "rules").glob("*.yaml"))
    missing_files = sorted(REQUIRED_RULE_FILES - {path.name for path in rule_paths})
    if missing_files:
        errors.append("缺少实用精细版规则文件：" + ", ".join(missing_files))

    for path in rule_paths:
        text = path.read_text(encoding="utf-8")
        if not re.search(r"(?m)^payload:\s*$", text):
            errors.append(f"{path.relative_to(ROOT)} 缺少 payload:")
        entries = [
            match.group(1).strip()
            for match in re.finditer(r"(?m)^\s*-\s+(.+?)\s*$", text)
        ]
        duplicates = sorted({entry for entry in entries if entries.count(entry) > 1})
        if duplicates:
            errors.append(
                f"{path.relative_to(ROOT)} 存在重复条目：{', '.join(duplicates)}"
            )
        required_entries = REQUIRED_RULE_FILE_ENTRIES.get(path.name, set())
        missing_entries = sorted(required_entries - set(entries))
        if missing_entries:
            errors.append(
                f"{path.relative_to(ROOT)} 缺少关键分类条目："
                + ", ".join(missing_entries)
            )
        if path.name == "direct.yaml":
            missing = sorted(REQUIRED_DIRECT_EXCEPTIONS - set(entries))
            if missing:
                errors.append(
                    "rules/direct.yaml 缺少银行、政务或网盘补充："
                    + ", ".join(missing)
                )
        if path.name == "node-geo-check.yaml":
            required = {
                "'api.country.is'",
                "'ipwho.is'",
                "'api.ip.sb'",
                "'countries.dev'",
                "'www.cloudflare.com'",
            }
            missing = sorted(required - set(entries))
            if missing:
                errors.append(
                    "rules/node-geo-check.yaml 缺少多源查询域名："
                    + ", ".join(missing)
                )


def validate_overwrite(errors: list[str]) -> None:
    text = OVERWRITE.read_text(encoding="utf-8")
    required = (
        "[YAML]",
        "<proxy-groups>*:",
        "type: smart",
        "interval: 120",
        "tolerance: 100",
        "timeout: 5000",
        "max-failed-times: 2",
        "expected-status: 204",
    )
    for marker in required:
        if marker not in text:
            errors.append(f"覆写模块缺少自动组健康检查设置：{marker}")
    if "[General]" in text:
        errors.append("覆写模块不应包含 [General]；插件参数应由 LuCI/UCI 持久化")


def validate_runtime_group_filter(errors: list[str]) -> None:
    if not RUNTIME_CATALOG.is_file():
        errors.append("缺少运行期业务策略组目录")
    else:
        catalog = json.loads(RUNTIME_CATALOG.read_text(encoding="utf-8"))
        expected = {
            "business_groups": list(BUSINESS_STRATEGY_GROUPS),
            "proxy_choices": list(BUSINESS_PROXY_GROUP_CHOICES),
            "always_choices": list(BUSINESS_BUILTIN_CHOICES),
            "dashboard_group_order": list(DASHBOARD_PROXY_GROUP_ORDER),
        }
        if catalog != expected:
            errors.append("运行期业务策略组目录与生成源不一致")

    required_files = {
        RUNTIME_PATCH: (
            "empty_proxy_choices",
            'group["proxies"] << "REJECT"',
            "choices.replace",
            "reordered_group_count",
            "dashboard_reordered_group_count",
        ),
        RUNTIME_HOOK: (
            "jydn_patch_runtime_groups.rb",
            "jydn_business_group_catalog.json",
        ),
    }
    for path, markers in required_files.items():
        if not path.is_file():
            errors.append(f"缺少运行期空组过滤文件：{path.relative_to(ROOT)}")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                errors.append(f"{path.relative_to(ROOT)} 缺少关键逻辑：{marker}")


def validate_advanced_routing_example(errors: list[str]) -> None:
    if not ADVANCED_ROUTING_EXAMPLE.is_file():
        errors.append("缺少来源设备/入站/SUB-RULE 安全示例模块")
        return
    text = ADVANCED_ROUTING_EXAMPLE.read_text(encoding="utf-8")
    required = (
        "[YAML]",
        "sub-rules:",
        "+rules:",
        "SUB-RULE,",
        "SRC-IP-CIDR,192.0.2.1/32",
        "IN-NAME,replace-with-real-inbound",
        "IN-TYPE,tun",
        "GEOSITE,geolocation-!cn,🔒 隐私代理",
        "GEOSITE,cn,DIRECT",
        "GEOIP,cn,DIRECT,no-resolve",
    )
    for marker in required:
        if marker not in text:
            errors.append(f"高级分流示例缺少安全占位或语法：{marker}")
    if "SRC-IP-CIDR,10.88.0." in text:
        errors.append("高级分流示例不得预置真实 10.88.0.0/24 客户端地址")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    errors: list[str] = []
    validate_base(errors)
    validate_config(errors)
    validate_rule_files(errors)
    validate_overwrite(errors)
    validate_runtime_group_filter(errors)
    validate_advanced_routing_example(errors)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)
    print("Validation passed: groups, multidimensional rules, rule order, URL tests, overwrite, and rule files")


if __name__ == "__main__":
    main()
