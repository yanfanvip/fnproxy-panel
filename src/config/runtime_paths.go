package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	configFileName         = "fnproxy.json"
	pidFileName            = "fnproxy.pid"
	socketFileName         = "fnproxy.sock"
	monitorCacheRelative  = "cache/monitor-cache.db"
	securityCacheRelative = "cache/security-logs.db"
	managedCertsRelative  = "certs/managed"
	accountCertsRelative  = "certs/accounts"
)

var (
	runtimeBaseDir     string
	runtimeBaseDirMu   sync.RWMutex
	runtimeAdminPort   int
	runtimeUseSocket   bool
	runtimeSocketPath  string
	runtimeOAuthMode   string
	runtimeWebRoot     string
	runtimeAdminMu     sync.RWMutex
)

func SetRuntimeBaseDir(path string) error {
	baseDir := strings.TrimSpace(path)
	if baseDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		baseDir = cwd
	} else if !filepath.IsAbs(baseDir) {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		baseDir = filepath.Join(cwd, baseDir)
	}

	absDir, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absDir, 0755); err != nil {
		return err
	}

	runtimeBaseDirMu.Lock()
	runtimeBaseDir = absDir
	runtimeBaseDirMu.Unlock()
	return nil
}

func GetRuntimeBaseDir() string {
	runtimeBaseDirMu.RLock()
	baseDir := runtimeBaseDir
	runtimeBaseDirMu.RUnlock()
	if baseDir != "" {
		return baseDir
	}
	_ = SetRuntimeBaseDir("")
	runtimeBaseDirMu.RLock()
	defer runtimeBaseDirMu.RUnlock()
	return runtimeBaseDir
}

func ResolveRuntimePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return GetRuntimeBaseDir()
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(GetRuntimeBaseDir(), filepath.FromSlash(path))
}

func ConfigFilePath() string {
	return ResolveRuntimePath(configFileName)
}

func RuntimePIDFilePath() string {
	return ResolveRuntimePath(pidFileName)
}

func RuntimeSocketFilePath() string {
	runtimeAdminMu.RLock()
	defer runtimeAdminMu.RUnlock()
	
	// 如果设置了自定义 socket 路径，优先使用
	if runtimeSocketPath != "" {
		return runtimeSocketPath
	}
	
	// 否则使用默认路径
	return ResolveRuntimePath(socketFileName)
}

func RuntimeMonitorCachePath() string {
	return ResolveRuntimePath(monitorCacheRelative)
}

func RuntimeSecurityLogCachePath() string {
	return ResolveRuntimePath(securityCacheRelative)
}

func RuntimeManagedCertDir() string {
	return ResolveRuntimePath(managedCertsRelative)
}

func RuntimeAccountCertDir() string {
	return ResolveRuntimePath(accountCertsRelative)
}

func SetRuntimeAdminTarget(portArg string, defaultPort int) error {
	value := strings.TrimSpace(portArg)

	runtimeAdminMu.Lock()
	defer runtimeAdminMu.Unlock()

	if value == "" {
		runtimeUseSocket = false
		runtimeAdminPort = defaultPort
		return nil
	}
	if strings.EqualFold(value, "sock") {
		runtimeUseSocket = true
		runtimeAdminPort = 0
		return nil
	}

	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("port 参数仅支持数字端口或 sock")
	}
	runtimeUseSocket = false
	runtimeAdminPort = port
	return nil
}

// SetRuntimeSocketPath 设置自定义 socket 文件路径
func SetRuntimeSocketPath(path string) {
	runtimeAdminMu.Lock()
	defer runtimeAdminMu.Unlock()
	path = strings.TrimSpace(path)
	if path != "" {
		// 如果提供了绝对路径，直接使用；否则相对于运行目录
		if filepath.IsAbs(path) {
			runtimeSocketPath = path
		} else {
			runtimeSocketPath = filepath.Join(GetRuntimeBaseDir(), filepath.FromSlash(path))
		}
	} else {
		runtimeSocketPath = ""
	}
}

// SetRuntimeOAuthMode 设置 OAuth 认证模式
func SetRuntimeOAuthMode(mode string) {
	runtimeAdminMu.Lock()
	defer runtimeAdminMu.Unlock()
	runtimeOAuthMode = strings.ToLower(strings.TrimSpace(mode))
}

// GetRuntimeOAuthMode 获取 OAuth 认证模式
func GetRuntimeOAuthMode() string {
	runtimeAdminMu.RLock()
	defer runtimeAdminMu.RUnlock()
	return runtimeOAuthMode
}

// IsRuntimeOAuthFnnas 检查是否使用飞牛NAS网关认证
func IsRuntimeOAuthFnnas() bool {
	return GetRuntimeOAuthMode() == "fnnas"
}

// SetRuntimeWebRoot 设置 Web 根路径前缀
func SetRuntimeWebRoot(webRoot string) {
	runtimeAdminMu.Lock()
	defer runtimeAdminMu.Unlock()
	webRoot = strings.TrimSpace(webRoot)
	// 确保以 / 开头，不以 / 结尾
	if webRoot != "" {
		if !strings.HasPrefix(webRoot, "/") {
			webRoot = "/" + webRoot
		}
		webRoot = strings.TrimSuffix(webRoot, "/")
	}
	runtimeWebRoot = webRoot
}

// GetRuntimeWebRoot 获取 Web 根路径前缀
func GetRuntimeWebRoot() string {
	runtimeAdminMu.RLock()
	defer runtimeAdminMu.RUnlock()
	return runtimeWebRoot
}

func IsRuntimeAdminSocket() bool {
	runtimeAdminMu.RLock()
	defer runtimeAdminMu.RUnlock()
	return runtimeUseSocket
}

func GetRuntimeAdminPort(defaultPort int) int {
	runtimeAdminMu.RLock()
	defer runtimeAdminMu.RUnlock()
	if runtimeUseSocket {
		return 0
	}
	if runtimeAdminPort > 0 {
		return runtimeAdminPort
	}
	return defaultPort
}
