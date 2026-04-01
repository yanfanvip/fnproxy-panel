package utils

import (
	"net/http"
	"strings"
)

// RequestIsHTTPS 判断客户端是否通过 HTTPS 访问（含 TLS 直连或可信反向代理的 X-Forwarded-Proto）。
// 用于在「HTTPS 对外、HTTP 回源」部署下正确设置 Secure Cookie、X-Forwarded-Proto 等。
func RequestIsHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}
