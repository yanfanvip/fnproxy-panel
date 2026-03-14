package middleware

import (
	"net"
	"net/http"
	"sort"
	"strings"

	"fnproxy/config"
	"fnproxy/models"
)

// FirewallMiddleware 防火墙中间件
func FirewallMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取防火墙配置
		cfg := config.GetManager()
		firewallCfg := cfg.GetFirewallConfig()

		// 如果防火墙未启用，直接放行
		if !firewallCfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端IP
		clientIP := getClientIP(r)

		// localhost 永远允许访问
		if isLoopbackIP(clientIP) {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端国家（暂时返回空，需要集成GeoIP库）
		country := getCountryByIP(clientIP)

		// 匹配规则
		action := matchRules(clientIP, country, firewallCfg)

		switch action {
		case models.FirewallActionDeny:
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		case models.FirewallActionAllow:
			next.ServeHTTP(w, r)
		default:
			// 默认动作
			if firewallCfg.DefaultDeny {
				http.Error(w, "Access Denied", http.StatusForbidden)
			} else {
				next.ServeHTTP(w, r)
			}
		}
	})
}

// getClientIP 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 优先从 X-Forwarded-For 获取
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For 可能包含多个IP，第一个是原始客户端IP
		ips := splitIPs(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}

	// 其次从 X-Real-IP 获取
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// 最后使用 RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// splitIPs 分割IP地址列表
func splitIPs(xff string) []string {
	var ips []string
	for _, ip := range strings.Split(xff, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" && ip != "unknown" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// getCountryByIP 根据IP获取国家代码
// 注意：此函数需要集成GeoIP库才能正常工作，目前返回空字符串
func getCountryByIP(ip string) string {
	// 跳过本地IP
	if isPrivateIP(ip) {
		return ""
	}

	// TODO: 集成 ip2location-go 库进行GeoIP查询
	// 示例代码:
	// record, err := ip2location.Open("path/to/ip2location.mmdb")
	// if err != nil { return "" }
	// country := record.GetCountryShort(ip)
	// return country

	return ""
}

// isLoopbackIP 检查是否为本地回环地址
func isLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// isPrivateIP 检查是否为私有IP
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}

	// 172.16.0.0/12
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}

	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}

	// 127.0.0.0/8
	if ip[0] == 127 {
		return true
	}

	return false
}

// matchRules 匹配规则
func matchRules(clientIP, country string, cfg *models.FirewallConfig) models.FirewallAction {
	rules := cfg.Rules
	if len(rules) == 0 {
		return ""
	}

	// 按优先级排序
	sortedRules := make([]models.FirewallRule, len(rules))
	copy(sortedRules, rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})

	// 遍历规则
	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}

		// IP规则匹配
		if rule.Type == models.FirewallRuleTypeIP {
			if matchIPRule(clientIP, rule.IPs) {
				return rule.Action
			}
		}

		// 国家规则匹配
		if rule.Type == models.FirewallRuleTypeCountry {
			if matchCountryRule(country, rule.Countries) {
				return rule.Action
			}
		}
	}

	return ""
}

// matchIPRule 检查IP是否匹配规则
func matchIPRule(clientIP string, ips []string) bool {
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

		// 检查是否为CIDR格式
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			// 不是CIDR，尝试作为单个IP匹配
			if ipRange == clientIP {
				return true
			}
			continue
		}

		// 检查IP是否在CIDR范围内
		if ipNet.Contains(client) {
			return true
		}
	}

	return false
}

// matchCountryRule 检查国家是否匹配规则
func matchCountryRule(country string, countries []string) bool {
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
