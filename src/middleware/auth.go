package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

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
			handlers.WriteError(w, http.StatusUnauthorized, "Authorization header required")
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
	// 登录相关接口始终公开
	publicPaths := []string{
		"/api/login",
		"/api/auth/public-key",
		"/api/logout",
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
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Auth")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
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
