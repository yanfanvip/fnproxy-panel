package routes

// API 路由常量
const (
	// 认证相关
	RouteAdminOAuth   = "/admin-oauth"
	RouteAuthLogin    = "/api/auth/login"
	RouteAuthLogout   = "/api/auth/logout"
	RouteAuthPublicKey = "/api/auth/public-key"
	
	// 用户管理
	RouteUsers       = "/api/users"
	RouteUserByID    = "/api/users/:id"
	
	// 配置管理
	RouteConfig      = "/api/config"
	RouteFirewall    = "/api/firewall"
	
	// 服务管理
	RouteServices    = "/api/services"
	RouteListeners   = "/api/listeners"
	
	// 证书管理
	RouteCertificates = "/api/certificates"
	
	// 监控与日志
	RouteMetrics     = "/api/metrics"
	RouteSecurityLogs = "/api/security-logs"
	
	// WebSocket
	RouteWSTerminal  = "/ws/terminal"
	
	// 公开接口
	RouteGeoIP       = "/api/geoip"
	RouteStatus      = "/api/status"
)

// 静态文件路由
const (
	RouteStatic      = "/static/"
	RouteRoot        = "/"
)

// API 路由前缀（用于 mux.Handle 挂载）
const (
	RouteAPIPrefix   = "/api/"
	RouteWSPrefix    = "/ws/"
)

// BuildRoute 构建带WebRoot前缀的完整路由
func BuildRoute(webRoot, route string) string {
	if webRoot == "" || webRoot == "/" {
		return route
	}
	// 确保webRoot不以/结尾，route以/开头
	if len(webRoot) > 0 && webRoot[len(webRoot)-1] == '/' {
		webRoot = webRoot[:len(webRoot)-1]
	}
	if len(route) > 0 && route[0] != '/' {
		route = "/" + route
	}
	return webRoot + route
}
