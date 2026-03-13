package security

import (
	"sync"
	"time"

	"fnproxy/models"

	"github.com/google/uuid"
)

// MaxEntriesFunc 获取最大日志条数的回调函数
type MaxEntriesFunc func() int

// AuditLogger 安全审计日志管理器
type AuditLogger struct {
	mu             sync.RWMutex
	store          *auditStore
	maxEntriesFunc MaxEntriesFunc
}

var auditLoggerInstance *AuditLogger
var auditLoggerOnce sync.Once

// GetAuditLogger 获取安全日志管理器单例
func GetAuditLogger() *AuditLogger {
	auditLoggerOnce.Do(func() {
		auditLoggerInstance = &AuditLogger{}
	})
	return auditLoggerInstance
}

// InitStore 初始化存储
func (l *AuditLogger) InitStore(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	store, err := newAuditStore(path)
	if err != nil {
		return err
	}
	l.store = store
	return nil
}

// SetMaxEntriesFunc 设置获取最大日志条数的回调函数
func (l *AuditLogger) SetMaxEntriesFunc(fn MaxEntriesFunc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxEntriesFunc = fn
}

func (l *AuditLogger) getMaxEntries() int {
	if l.maxEntriesFunc != nil {
		if max := l.maxEntriesFunc(); max > 0 {
			return max
		}
	}
	return 5000 // 默认值
}

// Log 记录安全日志
func (l *AuditLogger) Log(entry models.SecurityLogEntry) {
	// 设置ID和时间戳
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	l.mu.RLock()
	store := l.store
	maxEntries := l.getMaxEntries()
	l.mu.RUnlock()

	if store != nil {
		_ = store.appendLog(entry, maxEntries)
	}
}

// LogOAuthLogin 记录 OAuth 登录日志
func (l *AuditLogger) LogOAuthLogin(username, remoteAddr string, success bool, message string) {
	level := models.SecurityLogLevelInfo
	action := "登录成功"
	if !success {
		level = models.SecurityLogLevelWarning
		action = "登录失败"
	}
	l.Log(models.SecurityLogEntry{
		Type:       models.SecurityLogTypeOAuthLogin,
		Level:      level,
		Username:   username,
		RemoteAddr: remoteAddr,
		Action:     action,
		Message:    message,
		Success:    success,
	})
}

// LogProxyError 记录代理错误日志
func (l *AuditLogger) LogProxyError(serviceName, remoteAddr, message string, extra map[string]any) {
	l.Log(models.SecurityLogEntry{
		Type:       models.SecurityLogTypeProxyError,
		Level:      models.SecurityLogLevelError,
		RemoteAddr: remoteAddr,
		Target:     serviceName,
		Action:     "代理错误",
		Message:    message,
		Success:    false,
		Extra:      extra,
	})
}

// LogSSHConnect 记录 SSH 连接日志
func (l *AuditLogger) LogSSHConnect(username, remoteAddr, connectionName string, success bool, message string) {
	level := models.SecurityLogLevelInfo
	action := "连接成功"
	if !success {
		level = models.SecurityLogLevelWarning
		action = "连接失败"
	}
	l.Log(models.SecurityLogEntry{
		Type:       models.SecurityLogTypeSSHConnect,
		Level:      level,
		Username:   username,
		RemoteAddr: remoteAddr,
		Target:     connectionName,
		Action:     action,
		Message:    message,
		Success:    success,
	})
}

// LogSSHDisconnect 记录 SSH 断开日志
func (l *AuditLogger) LogSSHDisconnect(username, remoteAddr, connectionName, message string) {
	l.Log(models.SecurityLogEntry{
		Type:       models.SecurityLogTypeSSHConnect,
		Level:      models.SecurityLogLevelInfo,
		Username:   username,
		RemoteAddr: remoteAddr,
		Target:     connectionName,
		Action:     "断开连接",
		Message:    message,
		Success:    true,
	})
}

// LogSystemOperate 记录系统操作日志
func (l *AuditLogger) LogSystemOperate(username, remoteAddr, action, target, message string, success bool, extra map[string]any) {
	level := models.SecurityLogLevelInfo
	if !success {
		level = models.SecurityLogLevelWarning
	}
	l.Log(models.SecurityLogEntry{
		Type:       models.SecurityLogTypeSystemOperate,
		Level:      level,
		Username:   username,
		RemoteAddr: remoteAddr,
		Target:     target,
		Action:     action,
		Message:    message,
		Success:    success,
		Extra:      extra,
	})
}

// QueryLogs 查询日志（支持分页和过滤）
func (l *AuditLogger) QueryLogs(logType string, level string, keyword string, page, pageSize int) ([]models.SecurityLogEntry, int) {
	l.mu.RLock()
	store := l.store
	l.mu.RUnlock()

	if store == nil {
		return []models.SecurityLogEntry{}, 0
	}

	logs, total, err := store.queryLogs(logType, level, keyword, page, pageSize)
	if err != nil {
		return []models.SecurityLogEntry{}, 0
	}
	return logs, total
}

// ClearLogs 清空日志
func (l *AuditLogger) ClearLogs() {
	l.mu.RLock()
	store := l.store
	l.mu.RUnlock()

	if store != nil {
		_ = store.clearLogs()
	}
}

// GetStats 获取日志统计信息
func (l *AuditLogger) GetStats() map[string]int {
	l.mu.RLock()
	store := l.store
	l.mu.RUnlock()

	if store == nil {
		return map[string]int{
			"total":          0,
			"oauth_login":    0,
			"proxy_error":    0,
			"ssh_connect":    0,
			"system_operate": 0,
		}
	}

	stats, err := store.getStats()
	if err != nil || stats == nil {
		return map[string]int{
			"total":          0,
			"oauth_login":    0,
			"proxy_error":    0,
			"ssh_connect":    0,
			"system_operate": 0,
		}
	}
	return stats
}
