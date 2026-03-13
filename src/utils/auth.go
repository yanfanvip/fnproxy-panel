package utils

import (
	"net/http"
	"strings"
	"time"

	"fnproxy/config"

	"github.com/golang-jwt/jwt/v5"
)

const AuthCookieName = "fnproxy_auth"

var jwtSecret = []byte("your-secret-key-change-in-production")

// Claims JWT claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken 生成JWT token
func GenerateToken(username, role string, ttl time.Duration) (string, error) {
	claims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateToken 验证JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}

// SetAuthCookie 写入认证Cookie
func SetAuthCookie(w http.ResponseWriter, token string, secure bool, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

// ClearAuthCookie 清理认证Cookie
func ClearAuthCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

// GetAuthClaimsFromRequest 从请求中读取Cookie认证信息
func GetAuthClaimsFromRequest(r *http.Request) (*Claims, error) {
	if claims, _ := getAuthClaimsFromHeaderValue(r.Header.Get("Auth"), false); claims != nil {
		return claims, nil
	}
	if claims, _ := getAuthClaimsFromHeaderValue(r.Header.Get("Authorization"), true); claims != nil {
		return claims, nil
	}
	cookie, err := r.Cookie(AuthCookieName)
	if err != nil {
		return nil, err
	}
	return ValidateToken(cookie.Value)
}

func getAuthClaimsFromHeaderValue(headerValue string, allowJWT bool) (*Claims, error) {
	headerToken := normalizeAuthHeaderToken(headerValue)
	if headerToken == "" {
		return nil, nil
	}
	user := config.GetManager().GetUserByToken(headerToken)
	if user != nil {
		if !user.Enabled {
			return nil, nil
		}
		return &Claims{
			Username: user.Username,
			Role:     user.Role,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
		}, nil
	}
	if allowJWT {
		return ValidateToken(headerToken)
	}
	return nil, nil
}

func normalizeAuthHeaderToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) == 2 {
		scheme := strings.ToLower(strings.TrimSpace(parts[0]))
		if scheme == "bearer" || scheme == "token" || scheme == "auth" {
			return strings.TrimSpace(parts[1])
		}
	}
	return value
}
