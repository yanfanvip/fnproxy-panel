package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"fnproxy/handlers"
	"fnproxy/security"
	"fnproxy/utils"
)

// FnnasGatewayAuthMiddleware 飞牛NAS网关认证中间件
// 当使用 -oauth=fnnas 参数时，通过网关透传的 Header 进行认证
// 注意：管理端仅允许管理员用户访问
func FnnasGatewayAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径不需要认证
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端IP用于日志
		remoteAddr := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			remoteAddr = xff
		}

		// 从网关透传的 Header 中获取用户信息
		userID := r.Header.Get("X-Trim-Userid")
		isAdmin := r.Header.Get("X-Trim-Isadmin")
		username := r.Header.Get("X-Trim-Username")

		// 详细检查缺失的Header
		missingHeaders := []string{}
		if userID == "" {
			missingHeaders = append(missingHeaders, "X-Trim-Userid")
		}
		if username == "" {
			missingHeaders = append(missingHeaders, "X-Trim-Username")
		}
		if isAdmin == "" {
			missingHeaders = append(missingHeaders, "X-Trim-Isadmin")
		}

		// 如果没有网关透传的用户信息，拒绝访问
		if len(missingHeaders) > 0 {
			errorMsg := fmt.Sprintf("缺少必要的认证Header: %v", missingHeaders)
			fmt.Printf("[飞牛NAS认证失败] IP=%s 路径=%s 原因=%s\n", remoteAddr, r.URL.Path, errorMsg)
			security.GetAuditLogger().LogOAuthLogin("", remoteAddr, false, errorMsg)
			handlers.WriteErrorWithDetail(w, http.StatusUnauthorized, "未认证", map[string]interface{}{
				"reason":        "missing_headers",
				"message":       "需要飞牛NAS网关认证",
				"detail":        errorMsg,
				"missing_headers": missingHeaders,
				"hint":          "请确认请求经过飞牛NAS统一网关，网关会自动添加认证Header",
			})
			return
		}

		// 管理端仅允许管理员访问
		if isAdmin != "true" {
			errorMsg := fmt.Sprintf("用户 %s (UID:%s) 不是管理员，Isadmin=%s", username, userID, isAdmin)
			fmt.Printf("[飞牛NAS权限拒绝] IP=%s 用户=%s 原因=%s\n", remoteAddr, username, errorMsg)
			security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, errorMsg)
			handlers.WriteErrorWithDetail(w, http.StatusForbidden, "未认证", map[string]interface{}{
				"reason":   "not_admin",
				"message":  "管理端仅允许管理员访问",
				"detail":   errorMsg,
				"username": username,
				"uid":      userID,
				"is_admin": isAdmin,
				"hint":     "请联系飞牛NAS系统管理员授予管理员权限",
			})
			return
		}

		// 构建 Claims（模拟 JWT claims）
		claims := &utils.Claims{
			Username: username,
			Role:     "admin", // 仅管理员可访问，所以固定为 admin
		}

		// 将 claims 添加到 context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FnnasAdminMiddleware 飞牛NAS管理员权限中间件
// 检查 X-Trim-Isadmin header 是否为 true
func FnnasAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value("claims").(*utils.Claims)
		if !ok {
			handlers.WriteError(w, http.StatusUnauthorized, "未认证")
			return
		}

		// 检查角色是否为 admin
		if claims.Role != "admin" {
			handlers.WriteError(w, http.StatusForbidden, "需要管理员权限")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetFnnasUserInfo 从请求中获取飞牛NAS用户信息
// 返回: uid, isAdmin, username, error
func GetFnnasUserInfo(r *http.Request) (int, bool, string, error) {
	userIDStr := r.Header.Get("X-Trim-Userid")
	isAdminStr := r.Header.Get("X-Trim-Isadmin")
	username := r.Header.Get("X-Trim-Username")

	if userIDStr == "" || username == "" {
		return 0, false, "", nil
	}

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		return 0, false, "", err
	}

	isAdmin := isAdminStr == "true"
	return userID, isAdmin, username, nil
}
