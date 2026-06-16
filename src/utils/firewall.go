package utils

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"fnproxy/config"
	"fnproxy/models"
)

// FirewallMiddleware 防火墙中间件（最高优先级）
func FirewallMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config.GetManager()
		firewallCfg := cfg.GetFirewallConfig()

		// 防火墙未启用，直接放行
		if !firewallCfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端IP
		clientIP := firewallGetClientIP(r)

		// localhost 永远允许访问
		if ip := net.ParseIP(clientIP); ip != nil && ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端国家
		country := firewallGetCountryByIP(clientIP)

		// 匹配规则
		action := firewallMatchRules(clientIP, country, firewallCfg)

		switch action {
		case models.FirewallActionDeny:
			firewallDropConnection(w)
			return
		case models.FirewallActionAllow:
			next.ServeHTTP(w, r)
		default:
			if firewallCfg.DefaultDeny {
				firewallDropConnection(w)
			} else {
				next.ServeHTTP(w, r)
			}
		}
	})
}

// firewallDropConnection 直接关闭连接，不返回任何数据（DROP 行为）
func firewallDropConnection(w http.ResponseWriter) {
	// 优先通过 Hijack 接管并关闭底层 TCP 连接，客户端收到 RST
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, err := hijacker.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	// HTTP/2 或不支持 Hijack 时：发送空响应体，并通知对端关闭连接
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusNoContent)
}

func firewallGetClientIP(r *http.Request) string {
	// 优先从 Header 中获取
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := firewallSplitIPs(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	
	// 处理 RemoteAddr
	// Unix Socket 连接的 RemoteAddr 可能是 "@"、空字符串或其他特殊格式
	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" || remoteAddr == "@" {
		// Unix Socket 连接,视为本地连接
		return "127.0.0.1"
	}
	
	// 检查是否包含协议前缀 (unix:, fd:等)
	if strings.HasPrefix(remoteAddr, "unix:") || 
	   strings.HasPrefix(remoteAddr, "fd:") {
		return "127.0.0.1"
	}
	
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// 记录日志以便调试
		fmt.Printf("[WARN] 无法解析 RemoteAddr: %s, error: %v\n", remoteAddr, err)
		// 如果无法解析,检查是否是有效的 IP
		if net.ParseIP(remoteAddr) != nil {
			return remoteAddr
		}
		// 否则视为本地连接(Unix Socket)
		return "127.0.0.1"
	}
	return ip
}

func firewallSplitIPs(xff string) []string {
	var ips []string
	for _, ip := range strings.Split(xff, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" && ip != "unknown" {
			ips = append(ips, ip)
		}
	}
	return ips
}

func firewallGetCountryByIP(ip string) string {
	code, _ := LookupCountry(ip)
	return code
}

func firewallMatchRules(clientIP, country string, cfg *models.FirewallConfig) models.FirewallAction {
	rules := cfg.Rules
	if len(rules) == 0 {
		return ""
	}

	sortedRules := make([]models.FirewallRule, len(rules))
	copy(sortedRules, rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})

	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}
		switch rule.Type {
		case models.FirewallRuleTypeIP:
			if firewallMatchIPRule(clientIP, rule.IPs) {
				return rule.Action
			}
		case models.FirewallRuleTypeCountry:
			if firewallMatchCountryRule(country, rule.Countries) {
				return rule.Action
			}
		case models.FirewallRuleTypeAll:
			// 匹配所有 IP
			return rule.Action
		case models.FirewallRuleTypeChina:
			// 中国大陆境内：country 为 CN，或私有/内网 IP（无法定位到国家）
			if country == "CN" || (country == "" && firewallIsPrivateIP(clientIP)) {
				return rule.Action
			}
		case models.FirewallRuleTypeOutsideChina:
			// 中国大陆境外：非 CN 的公网 IP；私有/内网 IP 不属于"境外"，不匹配
			if country != "CN" && !firewallIsPrivateIP(clientIP) {
				return rule.Action
			}
		}
	}
	return ""
}

// firewallIsPrivateIP 检查是否为私有/内网地址（RFC1918 + 链路本地）
func firewallIsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	// 10.0.0.0/8
	if v4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if v4[0] == 192 && v4[1] == 168 {
		return true
	}
	return false
}

func firewallMatchIPRule(clientIP string, ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	client := net.ParseIP(clientIP)
	if client == nil {
		return false
	}
	for _, ipRange := range ips {
		ipRange = strings.TrimSpace(ipRange)
		if ipRange == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			if ipRange == clientIP {
				return true
			}
			continue
		}
		if ipNet.Contains(client) {
			return true
		}
	}
	return false
}

func firewallMatchCountryRule(country string, countries []string) bool {
	if country == "" || len(countries) == 0 {
		return false
	}
	for _, c := range countries {
		if c == country {
			return true
		}
	}
	return false
}
