package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fnproxy/config"
	"fnproxy/fnproxy"
	"fnproxy/pkg/oauth"
	"fnproxy/security"
	"fnproxy/utils"
)

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

// LoginHandler 登录处理器
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user := config.GetManager().GetUserByUsername(req.Username)
	if user == nil {
		WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if !user.Enabled {
		WriteError(w, http.StatusForbidden, "User is disabled")
		return
	}

	// 验证密码
	if !security.ComparePassword(user.Password, req.Password) {
		WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	tokenString, err := utils.GenerateToken(user.Username, user.Role, 24*time.Hour)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	utils.SetAuthCookie(w, tokenString, r.TLS != nil, 24*time.Hour)

	resp := LoginResponse{
		Token: tokenString,
	}
	resp.User.Username = user.Username
	resp.User.Role = user.Role

	WriteSuccess(w, resp)
}

func AuthPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, map[string]string{
		"public_key": fnproxy.GetServer().GetOAuthPublicKeyPEM(),
	})
}

// LogoutHandler 登出处理器
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// JWT是无状态的，客户端只需删除token
	WriteSuccess(w, map[string]string{"message": "Logged out successfully"})
}

// GetCurrentUserHandler 获取当前用户信息
func GetCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*utils.Claims)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user := config.GetManager().GetUserByUsername(claims.Username)
	if user == nil {
		WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	WriteSuccess(w, map[string]interface{}{
		"username": user.Username,
		"email":    user.Email,
		"enabled":  user.Enabled,
		"role":     user.Role,
	})
}

// ValidateToken 验证JWT token
func ValidateToken(tokenString string) (*utils.Claims, error) {
	return utils.ValidateToken(tokenString)
}

// adminOAuthLoginPayload OAuth登录请求负载
type adminOAuthLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

// AdminOAuthHandler 管理后台OAuth登录处理
func AdminOAuthHandler(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remoteAddr = strings.Split(xff, ",")[0]
	}

	// 检查是否已登录
	if claims, _ := utils.GetAuthClaimsFromRequest(r); claims != nil {
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/"
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		renderAdminOAuthLoginPage(w, r, "")
		return
	}

	// POST 处理登录
	if err := r.ParseForm(); err != nil {
		security.GetAuditLogger().LogOAuthLogin("", remoteAddr, false, "表单解析失败")
		renderAdminOAuthLoginPage(w, r, "表单解析失败")
		return
	}

	payload, err := parseAdminOAuthLoginPayload(r)
	if err != nil {
		security.GetAuditLogger().LogOAuthLogin("", remoteAddr, false, err.Error())
		renderAdminOAuthLoginPage(w, r, err.Error())
		return
	}

	username := strings.TrimSpace(payload.Username)
	password := payload.Password
	redirectTarget := r.FormValue("redirect")
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	user := config.GetManager().GetUserByUsername(username)
	if user == nil {
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "用户不存在")
		renderAdminOAuthLoginPage(w, r, "用户名或密码错误")
		return
	}
	if !user.Enabled {
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "用户已被禁用")
		renderAdminOAuthLoginPage(w, r, "用户已被禁用")
		return
	}
	if !security.ComparePassword(user.Password, password) {
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "密码错误")
		renderAdminOAuthLoginPage(w, r, "用户名或密码错误")
		return
	}

	tokenTTL := 24 * time.Hour
	if payload.Remember {
		tokenTTL = 30 * 24 * time.Hour
	}
	token, err := utils.GenerateToken(user.Username, user.Role, tokenTTL)
	if err != nil {
		security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, false, "生成令牌失败")
		renderAdminOAuthLoginPage(w, r, "生成登录令牌失败")
		return
	}

	security.GetAuditLogger().LogOAuthLogin(username, remoteAddr, true, "管理后台登录成功")
	utils.SetAuthCookie(w, token, r.TLS != nil, tokenTTL)
	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

func parseAdminOAuthLoginPayload(r *http.Request) (*adminOAuthLoginPayload, error) {
	encryptedPayload := strings.TrimSpace(r.FormValue("payload"))
	if encryptedPayload != "" {
		return decryptAdminOAuthPayload(encryptedPayload)
	}
	return &adminOAuthLoginPayload{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		Remember: r.FormValue("remember") == "on" || r.FormValue("remember") == "true",
	}, nil
}

func decryptAdminOAuthPayload(encryptedPayload string) (*adminOAuthLoginPayload, error) {
	privateKey := fnproxy.GetServer().GetOAuthPrivateKey()
	if privateKey == nil {
		return nil, fmt.Errorf("服务端未配置加密密钥")
	}

	encryptedPayload = strings.ReplaceAll(encryptedPayload, "-", "+")
	encryptedPayload = strings.ReplaceAll(encryptedPayload, "_", "/")
	switch len(encryptedPayload) % 4 {
	case 2:
		encryptedPayload += "=="
	case 3:
		encryptedPayload += "="
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("解码失败: %w", err)
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	var payload adminOAuthLoginPayload
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		return nil, fmt.Errorf("解析失败: %w", err)
	}
	return &payload, nil
}

func renderAdminOAuthLoginPage(w http.ResponseWriter, r *http.Request, errMsg string) {
	redirectTarget := r.URL.Query().Get("redirect")
	if redirectTarget == "" {
		redirectTarget = r.FormValue("redirect")
	}
	publicKeyPEM := fnproxy.GetServer().GetOAuthPublicKeyPEM()
	oauth.RenderLoginPage(w, redirectTarget, errMsg, publicKeyPEM)
}

// AdminPageAuthMiddleware 管理后台页面认证中间件
func AdminPageAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否已登录
		if claims, _ := utils.GetAuthClaimsFromRequest(r); claims != nil {
			next.ServeHTTP(w, r)
			return
		}
		// 未登录，重定向到登录页面
		redirectURL := fmt.Sprintf("/admin-oauth?redirect=%s", url.QueryEscape(r.URL.RequestURI()))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}
