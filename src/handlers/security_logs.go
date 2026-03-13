package handlers

import (
	"net/http"
	"strconv"

	"fnproxy/security"
)

// HandleGetSecurityLogs 获取安全日志列表
func HandleGetSecurityLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// 获取查询参数
	logType := query.Get("type")
	level := query.Get("level")
	keyword := query.Get("keyword")
	pageStr := query.Get("page")
	pageSizeStr := query.Get("page_size")

	page := 1
	pageSize := 50
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 200 {
		pageSize = ps
	}

	// 查询日志
	logs, total := security.GetAuditLogger().QueryLogs(logType, level, keyword, page, pageSize)

	// 返回响应
	WriteSuccess(w, map[string]interface{}{
		"logs":      logs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// HandleGetSecurityLogStats 获取安全日志统计
func HandleGetSecurityLogStats(w http.ResponseWriter, r *http.Request) {
	stats := security.GetAuditLogger().GetStats()
	WriteSuccess(w, map[string]interface{}{
		"total":          stats["total"],
		"by_type": map[string]int{
			"oauth_login":    stats["oauth_login"],
			"proxy_error":    stats["proxy_error"],
			"ssh_connect":    stats["ssh_connect"],
			"system_operate": stats["system_operate"],
		},
	})
}

// HandleClearSecurityLogs 清空安全日志
func HandleClearSecurityLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	security.GetAuditLogger().ClearLogs()
	WriteSuccess(w, nil)
}
