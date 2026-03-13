package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"fnproxy/utils"
)

// NetworkHistoryHandler 24小时网络历史
func NetworkHistoryHandler(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, utils.GetMonitor().GetNetworkHistory24h())
}

// ListenerStatsHandler 监听统计
func ListenerStatsHandler(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, utils.GetMonitor().GetListenerStats())
}

// ServiceStatsHandler 服务统计
func ServiceStatsHandler(w http.ResponseWriter, r *http.Request) {
	portID := r.URL.Query().Get("port_id")
	if portID == "" {
		WriteError(w, http.StatusBadRequest, "port_id is required")
		return
	}
	WriteSuccess(w, utils.GetMonitor().GetServiceStatsByPort(portID))
}

// ListenerLogsHandler 监听访问日志
func ListenerLogsHandler(w http.ResponseWriter, r *http.Request) {
	listenerID := strings.TrimPrefix(r.URL.Path, "/api/logs/listeners/")
	WriteSuccess(w, utils.GetMonitor().GetListenerLogs(listenerID, parseLimit(r)))
}

// ServiceLogsHandler 服务访问日志
func ServiceLogsHandler(w http.ResponseWriter, r *http.Request) {
	serviceID := strings.TrimPrefix(r.URL.Path, "/api/logs/services/")
	WriteSuccess(w, utils.GetMonitor().GetServiceLogs(serviceID, parseLimit(r)))
}

func parseLimit(r *http.Request) int {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}
