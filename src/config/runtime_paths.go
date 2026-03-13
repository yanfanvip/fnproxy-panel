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
	runtimeBaseDir   string
	runtimeBaseDirMu sync.RWMutex
	runtimeAdminPort int
	runtimeUseSocket bool
	runtimeAdminMu   sync.RWMutex
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
