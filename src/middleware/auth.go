package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fnproxy/config"
	"fnproxy/handlers"
	"fnproxy/utils"
)

// AuthMiddleware 认证中间件
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径不需要认证
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 优先支持 Auth header 的用户令牌登录
		if claims, err := utils.GetAuthClaimsFromRequest(r); err == nil && claims != nil {
			ctx := context.WithValue(r.Context(), "claims", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 获取Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// 判断是否为API请求
			if isAPIRequest(r) {
				// API请求返回JSON错误
				handlers.WriteError(w, http.StatusUnauthorized, "Authorization header required")
			} else {
				// 页面请求重定向到登录页
				webRoot := config.GetRuntimeWebRoot()
				loginPath := "/admin-oauth"
				if webRoot != "" && webRoot != "/" {
					loginPath = webRoot + loginPath
				}
				redirectURL := loginPath + "?redirect=" + r.URL.RequestURI()
				http.Redirect(w, r, redirectURL, http.StatusFound)
			}
			return
		}

		// 提取Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			handlers.WriteError(w, http.StatusUnauthorized, "Invalid authorization header format")
			return
		}

		tokenString := parts[1]
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			handlers.WriteError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// 将claims添加到context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isPublicPath 检查是否为公开路径
func isPublicPath(path string) bool {
	// 如果使用飞牛NAS网关认证,所有路径都需要通过网关认证
	if config.IsRuntimeOAuthFnnas() {
		// 仅保留真正公开的接口
		publicPaths := []string{
			"/api/geoip",
			"/api/status",  // 状态接口公开,用于健康检查
		}
		for _, p := range publicPaths {
			if path == p {
				return true
			}
		}
		return false
	}

	// 传统模式：登录相关接口始终公开
	publicPaths := []string{
		"/admin-oauth",      // OAuth登录页面
		"/api/login",
		"/api/auth/public-key",
		"/api/logout",
		"/api/geoip",
	}
	for _, p := range publicPaths {
		if path == p {
			return true
		}
	}
	// 其他路径根据全局认证设置决定是否公开
	// 当 DefaultAuth=true 时，非公开路径需要认证
	return false
}

// isAPIRequest 判断是否为API请求
func isAPIRequest(r *http.Request) bool {
	path := r.URL.Path
	// API请求：以 /api/ 或 /ws/ 开头
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws/") {
		return true
	}
	// WebSocket升级请求
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		return true
	}
	// JSON请求（通过Accept或Content-Type判断）
	accept := r.Header.Get("Accept")
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(accept, "application/json") || strings.Contains(contentType, "application/json") {
		return true
	}
	return false
}

// AdminMiddleware 管理员权限中间件
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("claims").(*utils.Claims)
		if !ok {
			handlers.WriteError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		if claims.Role != "admin" {
			handlers.WriteError(w, http.StatusForbidden, "Admin access required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware CORS中间件
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// 白名单验证 - 允许同源请求和特定域名
			if isAllowedOrigin(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			// 如果不在白名单中，不设置 CORS header，浏览器会阻止跨域请求
		}
		
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Auth")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAllowedOrigin 检查来源是否在白名单中
func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	
	// 允许 localhost 和 127.0.0.1
	allowedOrigins := []string{
		"http://localhost",
		"http://127.0.0.1",
		"https://localhost",
		"https://127.0.0.1",
	}
	
	for _, allowed := range allowedOrigins {
		if origin == allowed || strings.HasPrefix(origin, allowed+":") {
			return true
		}
	}
	
	// 允许同域名（从配置或环境变量获取）
	// TODO: 可以从配置文件读取允许的域名列表
	return false
}

// LoggingMiddleware 日志中间件
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		// 简单日志输出
		fmt.Printf("[%s] %s %s %v\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.URL.Path, duration)
	})
}
