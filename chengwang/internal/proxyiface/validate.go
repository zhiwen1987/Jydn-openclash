package proxyiface

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"chengwang/internal/domain"
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,47}$`)

var supportedTypes = map[string]bool{
	"http": true, "socks5": true, "mixed": true, "tun": true,
	"tproxy": true, "redirect": true, "api": true,
}

var supportedAuth = map[string]bool{
	"none": true, "password": true, "token": true, "mtls": true,
}

var supportedScopes = map[string]bool{
	"local": true, "lan": true, "vpn": true, "custom": true,
}

var coreCapabilities = map[string]map[string]bool{
	"Mihomo":   {"http": true, "socks5": true, "mixed": true, "tun": true, "tproxy": true, "redirect": true, "api": true},
	"sing-box": {"http": true, "socks5": true, "mixed": true, "tun": true, "tproxy": true, "redirect": true, "api": true},
	"Xray":     {"http": true, "socks5": true, "tproxy": true, "redirect": true, "api": true},
}

func Validate(items []domain.ProxyInterface) domain.ValidationResult {
	issues := make([]domain.ValidationIssue, 0)
	ids := make(map[string]int, len(items))
	bindings := make(map[string]int, len(items))

	for index, item := range items {
		path := fmt.Sprintf("interfaces[%d]", index)
		kind := strings.ToLower(strings.TrimSpace(item.Type))
		if !idPattern.MatchString(item.ID) {
			issues = append(issues, issue("invalid_id", "error", path+".id", "接口 ID 必须以小写字母开头，且只包含小写字母、数字、下划线或连字符"))
		}
		if previous, exists := ids[item.ID]; exists {
			issues = append(issues, issue("duplicate_id", "error", path+".id", fmt.Sprintf("接口 ID 与 interfaces[%d] 重复", previous)))
		} else {
			ids[item.ID] = index
		}
		if strings.TrimSpace(item.Name) == "" {
			issues = append(issues, issue("name_required", "error", path+".name", "接口名称不能为空"))
		}
		if !supportedTypes[kind] {
			issues = append(issues, issue("unsupported_type", "error", path+".type", "不支持的代理接口类型"))
		}
		capabilities, coreKnown := coreCapabilities[item.Core]
		if !coreKnown {
			issues = append(issues, issue("unknown_core", "error", path+".core", "未识别的内核"))
		} else if !capabilities[kind] {
			issues = append(issues, issue("core_incompatible", "error", path+".type", item.Core+" 不支持该接口类型"))
		}
		if strings.TrimSpace(item.Listen) == "" {
			issues = append(issues, issue("listen_required", "error", path+".listen", "监听地址或设备名不能为空"))
		}
		if kind == "tun" {
			if item.Port != 0 {
				issues = append(issues, issue("tun_port_forbidden", "error", path+".port", "TUN 接口使用设备名，不应配置端口"))
			}
		} else if item.Port < 1 || item.Port > 65535 {
			issues = append(issues, issue("invalid_port", "error", path+".port", "端口必须在 1 到 65535 之间"))
		}
		if !supportedAuth[item.AuthMode] {
			issues = append(issues, issue("invalid_auth_mode", "error", path+".authMode", "认证模式必须为 none、password、token 或 mtls"))
		}
		if item.AuthMode != "none" && strings.TrimSpace(item.AuthReference) == "" {
			issues = append(issues, issue("auth_reference_required", "error", path+".authReference", "已启用认证，但未提供凭据引用"))
		}
		if !supportedScopes[item.AccessScope] {
			issues = append(issues, issue("invalid_access_scope", "error", path+".accessScope", "访问范围必须为 local、lan、vpn 或 custom"))
		}
		if item.AccessScope == "custom" && len(item.AllowedCIDRs) == 0 {
			issues = append(issues, issue("allowed_cidrs_required", "error", path+".allowedCidrs", "自定义访问范围必须至少配置一个 CIDR"))
		}
		for cidrIndex, cidr := range item.AllowedCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				issues = append(issues, issue("invalid_cidr", "error", fmt.Sprintf("%s.allowedCidrs[%d]", path, cidrIndex), "访问网段不是有效 CIDR"))
			}
		}
		if item.LANAccess && item.AuthMode == "none" && kind != "tun" && kind != "tproxy" && kind != "redirect" {
			issues = append(issues, issue("lan_auth_required", "error", path+".authMode", "局域网可访问的应用代理或控制接口必须启用认证"))
		}
		if item.TLS && strings.TrimSpace(item.TLSReference) == "" {
			issues = append(issues, issue("tls_reference_required", "error", path+".tlsReference", "已启用 TLS，但未配置证书引用"))
		}
		if item.MaxConnections < 0 || item.MaxConnections > 1000000 {
			issues = append(issues, issue("invalid_connection_limit", "error", path+".maxConnections", "连接上限必须在 0 到 1000000 之间，0 表示使用系统默认值"))
		}
		if item.IdleTimeoutSec < 0 || item.IdleTimeoutSec > 86400 {
			issues = append(issues, issue("invalid_idle_timeout", "error", path+".idleTimeoutSec", "空闲超时必须在 0 到 86400 秒之间"))
		}
		if item.RateLimitMbps < 0 || item.RateLimitMbps > 100000 {
			issues = append(issues, issue("invalid_rate_limit", "error", path+".rateLimitMbps", "限速必须在 0 到 100000 Mbps 之间，0 表示不限速"))
		}
		if kind == "api" && item.LANAccess && (!item.TLS || (item.AuthMode != "token" && item.AuthMode != "mtls")) {
			issues = append(issues, issue("insecure_remote_api", "error", path, "局域网控制 API 必须同时启用 TLS 以及 token 或 mTLS 认证"))
		}
		if strings.TrimSpace(item.RoutingProfile) == "" {
			issues = append(issues, issue("routing_profile_required", "error", path+".routingProfile", "必须绑定路由方案"))
		}
		if item.Enabled && kind != "tun" && item.Port > 0 {
			binding := normalizedBinding(item.Listen, item.Port)
			if previous, exists := bindings[binding]; exists {
				issues = append(issues, issue("binding_conflict", "error", path+".port", fmt.Sprintf("监听地址和端口与 interfaces[%d] 冲突", previous)))
			} else {
				bindings[binding] = index
			}
		}
	}

	valid := true
	for _, current := range issues {
		if current.Severity == "error" {
			valid = false
			break
		}
	}
	return domain.ValidationResult{Valid: valid, Issues: issues}
}

func normalizedBinding(listen string, port int) string {
	host := strings.TrimSpace(strings.ToLower(listen))
	if host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "*"
	} else if parsed := net.ParseIP(host); parsed != nil {
		host = parsed.String()
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func issue(code, severity, path, message string) domain.ValidationIssue {
	return domain.ValidationIssue{Code: code, Severity: severity, Path: path, Message: message}
}
