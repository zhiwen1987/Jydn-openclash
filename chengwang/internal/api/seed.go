package api

import (
	"time"

	"chengwang/internal/domain"
)

func seedSnapshot(mode, version string, locked, mihomoConfigured bool) domain.Snapshot {
	if version == "" {
		version = "尚未发布"
	}
	draft := domain.PolicyDraft{
		Name: "精准分流草稿",
		Base: version,
		Pools: []domain.NodePool{
			{ID: "chatgpt_pool", Name: "ChatGPT 专用节点池", Members: []string{"美国-01", "日本-01", "新加坡-01"}, Capabilities: []string{"chatgpt"}},
			{ID: "gemini_pool", Name: "Gemini 专用节点池", Members: []string{"新加坡-01", "美国-01"}, Capabilities: []string{"gemini"}},
			{ID: "stable_auto", Name: "稳定自动", Members: []string{"香港-01", "新加坡-01", "日本-01"}},
			{ID: "香港", Name: "香港", Members: []string{"香港-01"}},
			{ID: "台湾", Name: "台湾", Members: nil},
			{ID: "日本", Name: "日本", Members: []string{"日本-01"}},
			{ID: "新加坡", Name: "新加坡", Members: []string{"新加坡-01"}},
			{ID: "韩国", Name: "韩国", Members: nil},
			{ID: "美国", Name: "美国", Members: []string{"美国-01"}},
			{ID: "英国", Name: "英国", Members: nil},
			{ID: "德国", Name: "德国", Members: nil},
		},
		Businesses: []domain.BusinessPolicy{
			{ID: "chatgpt", Name: "对话助手 (ChatGPT)", Domains: []string{"chatgpt.com", "openai.com", "oaistatic.com"}, Strategy: "chatgpt_pool", Candidates: []string{"chatgpt_pool", "美国", "日本", "新加坡", "stable_auto", "DIRECT", "REJECT"}, Fallback: "previous_stable", SkipEmptyPools: true, FailuresToSwitch: 3, ProbeIntervalSec: 30, SessionStickyMin: 30, SwitchCooldownSec: 300, RequireCapabilities: []string{"chatgpt"}},
			{ID: "gemini", Name: "Gemini", Domains: []string{"gemini.google.com", "generativelanguage.googleapis.com"}, Strategy: "gemini_pool", Candidates: []string{"gemini_pool", "新加坡", "美国", "日本", "stable_auto"}, Fallback: "previous_stable", SkipEmptyPools: true, FailuresToSwitch: 3, ProbeIntervalSec: 30, SessionStickyMin: 30, SwitchCooldownSec: 300, RequireCapabilities: []string{"gemini"}},
			{ID: "domestic", Name: "国内网站", Domains: []string{"cn"}, Strategy: "DIRECT", Candidates: []string{"DIRECT"}, Fallback: "DIRECT", SkipEmptyPools: true, FailuresToSwitch: 3, ProbeIntervalSec: 60, SessionStickyMin: 30, SwitchCooldownSec: 300},
			{ID: "payments", Name: "支付与交易", Domains: []string{"paypal.com"}, Strategy: "DIRECT", Candidates: []string{"DIRECT"}, Fallback: "DIRECT", SkipEmptyPools: true, FailuresToSwitch: 5, ProbeIntervalSec: 60, SessionStickyMin: 1440, SwitchCooldownSec: 1800},
		},
		DNS: domain.DNSPolicy{DomesticResolvers: []string{"223.5.5.5", "119.29.29.29"}, OverseasResolvers: []string{"https://1.1.1.1/dns-query", "tls://9.9.9.9"}, HijackPort53: true, LeakProtection: true},
	}
	now := time.Now().UTC()
	status := "演示快照 · 未配置 Mihomo 实时读回"
	if mihomoConfigured {
		status = "演示总览 · Mihomo 实际状态仅在设备读回页展示"
	}
	return domain.Snapshot{
		Product: "澄网 · 网络代理与路由平台", Version: version, Mode: mode, Status: status, DataSource: "demo", PublishLocked: locked,
		Businesses: []domain.BusinessStatus{
			{ID: "chatgpt", Name: "对话助手 (ChatGPT)", Strategy: "ChatGPT 专用节点池", ActiveRoute: "美国专用池", Status: "正常"},
			{ID: "gemini", Name: "Gemini", Strategy: "Gemini 专用节点池", ActiveRoute: "新加坡专用池", Status: "正常"},
			{ID: "domestic", Name: "国内网站", Strategy: "DIRECT", ActiveRoute: "中国大陆", Status: "正常"},
			{ID: "payments", Name: "支付与交易", Strategy: "固定出口", ActiveRoute: "国内固定出口", Status: "已锁定"},
		},
		Pools: []domain.PoolStatus{
			{Name: "美国专用池", Region: "美国", LatencyMS: 128, LossRate: 0.2, Available: 8, Total: 8, Status: "正常"},
			{Name: "新加坡专用池", Region: "新加坡", LatencyMS: 86, LossRate: 0.1, Available: 6, Total: 6, Status: "正常"},
			{Name: "日本专用池", Region: "日本", LatencyMS: 112, LossRate: 0.3, Available: 5, Total: 6, Status: "正常"},
		},
		Interfaces: seedProxyInterfaces(),
		Events: []domain.Event{
			{At: now.Add(-22 * time.Minute), Type: "节点切换", Reason: "连续三次业务探测失败", Result: "已回退至稳定节点"},
			{At: now.Add(-51 * time.Minute), Type: "DNS 恢复", Reason: "上游解析超时达到阈值", Result: "切换备用解析器"},
			{At: now.Add(-2 * time.Hour), Type: "规则校验", Reason: "订阅内容发生变化", Result: "验证通过，未自动发布"},
		},
		Draft: draft,
	}
}

func seedProxyInterfaces() []domain.ProxyInterface {
	return []domain.ProxyInterface{
		{ID: "local_mixed", Name: "本机 Mixed", Type: "mixed", Core: "Mihomo", Listen: "127.0.0.1", Port: 7890, UDP: true, AuthMode: "none", AccessScope: "local", MaxConnections: 512, IdleTimeoutSec: 300, AuditEnabled: true, Enabled: true, Status: "影子配置", RoutingProfile: "家庭主网", Description: "为本机应用同时提供 HTTP 与 SOCKS5 代理。"},
		{ID: "lan_socks5", Name: "局域网 SOCKS5", Type: "socks5", Core: "Mihomo", Listen: "0.0.0.0", Port: 7891, UDP: true, LANAccess: true, AuthMode: "password", AuthReference: "lan-proxy-users", AccessScope: "lan", AllowedCIDRs: []string{"10.88.0.0/24"}, MaxConnections: 256, IdleTimeoutSec: 300, RateLimitMbps: 200, AuditEnabled: true, Enabled: false, Status: "待部署", RoutingProfile: "家庭主网", Description: "供可信局域网设备按账号访问。凭据只保存引用，不进入配置快照。"},
		{ID: "lan_http", Name: "局域网 HTTP", Type: "http", Core: "Mihomo", Listen: "0.0.0.0", Port: 7892, LANAccess: true, AuthMode: "password", AuthReference: "lan-proxy-users", AccessScope: "lan", AllowedCIDRs: []string{"10.88.0.0/24"}, MaxConnections: 256, IdleTimeoutSec: 300, RateLimitMbps: 200, AuditEnabled: true, Enabled: false, Status: "待部署", RoutingProfile: "家庭主网", Description: "适配只支持 HTTP 代理的客户端。"},
		{ID: "primary_tun", Name: "主 TUN", Type: "tun", Core: "Mihomo", Listen: "chengwang0", UDP: true, AuthMode: "none", AccessScope: "local", MaxConnections: 4096, IdleTimeoutSec: 600, AuditEnabled: true, Enabled: false, Status: "待适配", RoutingProfile: "家庭主网", Description: "透明接管本机或网关流量，需设备适配器与路由权限。"},
		{ID: "gateway_tproxy", Name: "网关 TProxy", Type: "tproxy", Core: "sing-box", Listen: "0.0.0.0", Port: 7895, UDP: true, LANAccess: true, AuthMode: "none", AccessScope: "lan", AllowedCIDRs: []string{"10.88.0.0/24"}, MaxConnections: 8192, IdleTimeoutSec: 600, AuditEnabled: true, Enabled: false, Status: "待适配", RoutingProfile: "家庭主网", Description: "承接旁路由透明代理流量，不向普通客户端公开应用代理。"},
		{ID: "control_api", Name: "本机控制 API", Type: "api", Core: "Mihomo", Listen: "127.0.0.1", Port: 9090, AuthMode: "token", AuthReference: "local-control-token", AccessScope: "local", MaxConnections: 64, IdleTimeoutSec: 60, AuditEnabled: true, Enabled: false, Status: "待部署", RoutingProfile: "家庭主网", Description: "仅限本机控制面使用，默认不暴露到局域网。"},
	}
}
