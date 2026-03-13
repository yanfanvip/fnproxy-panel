package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"fnproxy/config"
	"fnproxy/fnproxy"
	"fnproxy/models"
	"fnproxy/security"
	"fnproxy/utils"

	"github.com/google/uuid"
)

// Response 通用响应结构
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

type reorderServicesRequest struct {
	PortID     string   `json:"port_id"`
	OrderedIDs []string `json:"ordered_ids"`
}

const encryptedPasswordPrefix = "enc::"

func normalizeUserToken(token string) string {
	return strings.TrimSpace(token)
}

func ensureUniqueUserToken(token, excludeID string) error {
	token = normalizeUserToken(token)
	if token == "" {
		return nil
	}
	for _, user := range config.GetManager().GetUsers() {
		if user.ID != excludeID && normalizeUserToken(user.Token) == token {
			return fmt.Errorf("token 已被用户 %s 使用，请重新生成", user.Username)
		}
	}
	return nil
}

func decryptIncomingPassword(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, encryptedPasswordPrefix) {
		return value, nil
	}
	plainBytes, err := fnproxy.GetServer().DecryptSecurePayload(strings.TrimPrefix(value, encryptedPasswordPrefix))
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

func validateListenerBeforeSave(listener models.PortListener, excludeID string) (bool, error) {
	if listener.Port <= 0 || listener.Port > 65535 {
		return false, fmt.Errorf("端口号必须在 1-65535 之间")
	}
	if listener.Protocol != "http" && listener.Protocol != "https" {
		return false, fmt.Errorf("监听协议仅支持 http 或 https")
	}
	adminPort := config.GetRuntimeAdminPort(config.GetManager().GetConfig().Global.AdminPort)
	if adminPort > 0 && listener.Port == adminPort {
		return false, fmt.Errorf("端口 %d 为管理后台端口，禁止占用", listener.Port)
	}

	for _, existing := range config.GetManager().GetListeners() {
		if existing.ID != excludeID && existing.Port == listener.Port {
			return false, fmt.Errorf("端口 %d 已存在，请勿重复添加", listener.Port)
		}
	}

	current := config.GetManager().GetListener(excludeID)
	if current != nil && current.Enabled && current.Port == listener.Port {
		return false, nil
	}

	testListener, err := net.Listen("tcp", fmt.Sprintf(":%d", listener.Port))
	if err != nil {
		return true, nil
	}
	testListener.Close()
	return false, nil
}

// WriteJSON 写入JSON响应
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// WriteError 写入错误响应
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, Response{Success: false, Error: message})
}

// WriteSuccess 写入成功响应
func WriteSuccess(w http.ResponseWriter, data interface{}) {
	WriteJSON(w, http.StatusOK, Response{Success: true, Data: data})
}

func WriteSuccessWithMessage(w http.ResponseWriter, data interface{}, message string) {
	WriteJSON(w, http.StatusOK, Response{Success: true, Data: data, Message: message})
}

// getRequestContext 获取请求上下文（用户名和IP）
func getRequestContext(r *http.Request) (username, remoteAddr string) {
	if claims, _ := utils.GetAuthClaimsFromRequest(r); claims != nil {
		username = claims.Username
	}
	remoteAddr = r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		remoteAddr = strings.TrimSpace(parts[0])
	}
	return
}

// StatusHandler 服务器状态处理器
func StatusHandler(w http.ResponseWriter, r *http.Request) {
	status, err := utils.GetServerStatus()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteSuccess(w, status)
}

// ListenerHandlers 端口监听处理器
func ListListenersHandler(w http.ResponseWriter, r *http.Request) {
	listeners := config.GetManager().GetListeners()
	type listenerListItem struct {
		models.PortListener
		Running bool `json:"running"`
	}
	items := make([]listenerListItem, 0, len(listeners))
	for _, listener := range listeners {
		items = append(items, listenerListItem{
			PortListener: listener,
			Running:      fnproxy.GetServer().IsListenerRunning(listener.ID),
		})
	}
	WriteSuccess(w, items)
}

func CreateListenerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		models.PortListener
		DefaultService *models.ServiceConfig `json:"default_service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	listener := req.PortListener
	listener.ID = uuid.New().String()
	listener.CreatedAt = time.Now()
	listener.UpdatedAt = time.Now()
	message := ""

	portOccupied, err := validateListenerBeforeSave(listener, "")
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if portOccupied && listener.Enabled {
		listener.Enabled = false
		message = fmt.Sprintf("端口 %d 已被其他程序占用，监听已保存为未启动状态", listener.Port)
	}

	if err := config.GetManager().AddListener(listener); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 如果有默认服务，创建它
	if req.DefaultService != nil {
		defaultService := *req.DefaultService
		defaultService.ID = uuid.New().String()
		defaultService.PortID = listener.ID
		defaultService.CreatedAt = time.Now()
		defaultService.UpdatedAt = time.Now()

		if err := config.GetManager().AddService(defaultService); err != nil {
			WriteError(w, http.StatusInternalServerError, "Failed to create default service: "+err.Error())
			return
		}
	}

	// 如果启用，启动监听器
	if listener.Enabled {
		if err := fnproxy.GetServer().StartListener(listener); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "新增端口监听", fmt.Sprintf("%d", listener.Port), fmt.Sprintf("新增端口监听: %d (%s)", listener.Port, listener.Protocol), true, nil)

	if message != "" {
		WriteSuccessWithMessage(w, listener, message)
		return
	}
	WriteSuccess(w, listener)
}

func UpdateListenerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/listeners/"):]

	var listener models.PortListener
	if err := json.NewDecoder(r.Body).Decode(&listener); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	listener.ID = id
	listener.UpdatedAt = time.Now()

	oldListener := config.GetManager().GetListener(id)
	if oldListener == nil {
		WriteError(w, http.StatusNotFound, "Listener not found")
		return
	}
	message := ""

	portOccupied, err := validateListenerBeforeSave(listener, id)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if portOccupied && listener.Enabled {
		listener.Enabled = false
		message = fmt.Sprintf("端口 %d 已被其他程序占用，监听已保存为未启动状态", listener.Port)
	}

	if err := config.GetManager().UpdateListener(listener); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 启用状态和配置热更新
	if listener.Enabled {
		if err := fnproxy.GetServer().StartListener(listener); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if oldListener.Enabled {
		if err := fnproxy.GetServer().StopListener(id); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "修改端口监听", fmt.Sprintf("%d", listener.Port), fmt.Sprintf("修改端口监听: %d", listener.Port), true, nil)

	if message != "" {
		WriteSuccessWithMessage(w, listener, message)
		return
	}
	WriteSuccess(w, listener)
}

func DeleteListenerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/listeners/"):]

	listener := config.GetManager().GetListener(id)
	if listener == nil {
		WriteError(w, http.StatusNotFound, "Listener not found")
		return
	}

	// 停止监听器
	if listener.Enabled {
		fnproxy.GetServer().StopListener(id)
	}

	if err := config.GetManager().DeleteListener(id); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "删除端口监听", fmt.Sprintf("%d", listener.Port), fmt.Sprintf("删除端口监听: %d", listener.Port), true, nil)

	WriteSuccess(w, nil)
}

func ToggleListenerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/listeners/") : len(r.URL.Path)-len("/toggle")]

	listener := config.GetManager().GetListener(id)
	if listener == nil {
		WriteError(w, http.StatusNotFound, "Listener not found")
		return
	}
	running := fnproxy.GetServer().IsListenerRunning(id)
	updated := *listener
	updated.UpdatedAt = time.Now()

	if running {
		if err := fnproxy.GetServer().StopListener(id); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		updated.Enabled = false
		if err := config.GetManager().UpdateListener(updated); err != nil {
			if restartErr := fnproxy.GetServer().StartListener(*listener); restartErr != nil {
				WriteError(w, http.StatusInternalServerError, fmt.Sprintf("停止监听后保存状态失败，且回滚失败: %v", restartErr))
				return
			}
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// 记录安全日志
		opUser, opAddr := getRequestContext(r)
		security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "停止端口监听", fmt.Sprintf("%d", listener.Port), fmt.Sprintf("停止端口监听: %d", listener.Port), true, nil)
		WriteSuccess(w, updated)
		return
	}

	updated.Enabled = true
	if err := config.GetManager().UpdateListener(updated); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := fnproxy.GetServer().StartListener(updated); err != nil {
		WriteSuccessWithMessage(w, updated, fmt.Sprintf("监听已设为启用，但启动失败: %v", err))
		return
	}
	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "启动端口监听", fmt.Sprintf("%d", listener.Port), fmt.Sprintf("启动端口监听: %d", listener.Port), true, nil)
	WriteSuccess(w, updated)
}

func ReloadListenerHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/listeners/") : len(r.URL.Path)-len("/reload")]
	listener := config.GetManager().GetListener(id)
	if listener == nil {
		WriteError(w, http.StatusNotFound, "Listener not found")
		return
	}
	if !listener.Enabled {
		WriteError(w, http.StatusBadRequest, "当前端口未启用，无需重载")
		return
	}
	if err := fnproxy.GetServer().ReloadListener(id); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteSuccess(w, listener)
}

// ServiceHandlers 服务配置处理器
func ListServicesHandler(w http.ResponseWriter, r *http.Request) {
	portID := r.URL.Query().Get("port_id")
	var services []models.ServiceConfig
	if portID != "" {
		services = config.GetManager().GetServicesByPort(portID)
	} else {
		services = config.GetManager().GetServices()
	}
	WriteSuccess(w, services)
}

func CreateServiceHandler(w http.ResponseWriter, r *http.Request) {
	var service models.ServiceConfig
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	service.ID = uuid.New().String()
	service.CreatedAt = time.Now()
	service.UpdatedAt = time.Now()

	if err := config.GetManager().AddService(service); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 重新加载对应端口的服务
	if service.Enabled {
		if err := fnproxy.GetServer().ReloadService(service); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	WriteSuccess(w, service)
}

func UpdateServiceHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/services/"):]

	var service models.ServiceConfig
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	service.ID = id
	service.UpdatedAt = time.Now()

	// 获取当前监听器状态，如果监听器是disabled状态，则不启动它
	listener := config.GetManager().GetListener(service.PortID)
	wasListenerDisabled := listener != nil && !listener.Enabled

	if err := config.GetManager().UpdateService(service); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 只有监听器是启用状态时才重新加载服务
	if !wasListenerDisabled {
		if err := fnproxy.GetServer().ReloadService(service); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	WriteSuccess(w, service)
}

func DeleteServiceHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/services/"):]

	service := config.GetManager().GetService(id)
	if service == nil {
		WriteError(w, http.StatusNotFound, "Service not found")
		return
	}

	if err := config.GetManager().DeleteService(id); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 重新加载对应端口的服务
	if err := fnproxy.GetServer().ReloadService(*service); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	WriteSuccess(w, nil)
}

func ReorderServicesHandler(w http.ResponseWriter, r *http.Request) {
	var req reorderServicesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.PortID == "" {
		WriteError(w, http.StatusBadRequest, "port_id is required")
		return
	}
	if err := config.GetManager().ReorderServices(req.PortID, req.OrderedIDs); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	listener := config.GetManager().GetListener(req.PortID)
	if listener != nil && listener.Enabled {
		if err := fnproxy.GetServer().StartListener(*listener); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	WriteSuccess(w, config.GetManager().GetServicesByPort(req.PortID))
}

func ToggleServiceHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/services/") : len(r.URL.Path)-len("/toggle")]

	service := config.GetManager().GetService(id)
	if service == nil {
		WriteError(w, http.StatusNotFound, "Service not found")
		return
	}

	service.Enabled = !service.Enabled
	service.UpdatedAt = time.Now()

	if err := config.GetManager().UpdateService(*service); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := fnproxy.GetServer().ReloadService(*service); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteSuccess(w, service)
}

func GetServiceHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/services/"):]
	service := config.GetManager().GetService(id)
	if service == nil {
		WriteError(w, http.StatusNotFound, "Service not found")
		return
	}
	WriteSuccess(w, service)
}

// UserHandlers 用户管理处理器
func ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	users := config.GetManager().GetUsers()
	// 隐藏密码
	for i := range users {
		users[i].Password = ""
	}
	WriteSuccess(w, users)
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user.ID = uuid.New().String()
	if user.Role == "" {
		user.Role = "user"
	}
	if user.Password != "" {
		plainPassword, err := decryptIncomingPassword(user.Password)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "密码解密失败")
			return
		}
		user.Password = plainPassword
	}
	user.Token = normalizeUserToken(user.Token)
	if err := ensureUniqueUserToken(user.Token, ""); err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	user.Password = security.HashPassword(user.Password)

	if err := config.GetManager().AddUser(user); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "新增用户", user.Username, fmt.Sprintf("新增用户: %s", user.Username), true, nil)

	user.Password = ""
	WriteSuccess(w, user)
}

func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/users/"):]

	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user.ID = id
	existing := config.GetManager().GetUsers()
	var current *models.User
	for i := range existing {
		if existing[i].ID == id {
			current = &existing[i]
			break
		}
	}
	if current == nil {
		WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	// 如果提供了新密码，加密它
	if user.Password != "" {
		plainPassword, err := decryptIncomingPassword(user.Password)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "密码解密失败")
			return
		}
		user.Password = plainPassword
		user.Password = security.HashPassword(user.Password)
	} else {
		user.Password = current.Password
	}
	user.Token = normalizeUserToken(user.Token)
	if user.Token == "" {
		user.Token = current.Token
	}
	if user.Role == "" {
		user.Role = current.Role
	}
	if user.Email == "" {
		user.Email = current.Email
	}
	if err := ensureUniqueUserToken(user.Token, id); err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := config.GetManager().UpdateUser(user); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "修改用户", user.Username, fmt.Sprintf("修改用户: %s", user.Username), true, nil)

	user.Password = ""
	WriteSuccess(w, user)
}

func ToggleUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/users/") : len(r.URL.Path)-len("/toggle")]

	users := config.GetManager().GetUsers()
	var user *models.User
	for i := range users {
		if users[i].ID == id {
			user = &users[i]
			break
		}
	}
	if user == nil {
		WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	// 如果要禁用用户，检查是否还有其他启用用户
	if user.Enabled {
		enabledCount := 0
		for _, u := range users {
			if u.Enabled {
				enabledCount++
			}
		}
		if enabledCount <= 1 {
			WriteError(w, http.StatusBadRequest, "必须保留至少一个启用状态的用户")
			return
		}
	}

	user.Enabled = !user.Enabled
	user.UpdatedAt = time.Now()
	if err := config.GetManager().UpdateUser(*user); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	action := "启用用户"
	if !user.Enabled {
		action = "禁用用户"
	}
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, action, user.Username, fmt.Sprintf("%s: %s", action, user.Username), true, nil)

	user.Password = ""
	WriteSuccess(w, user)
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/users/"):]

	// 检查删除后是否还有启用用户
	users := config.GetManager().GetUsers()
	var targetUser *models.User
	enabledCount := 0
	for i := range users {
		if users[i].ID == id {
			targetUser = &users[i]
		}
		if users[i].Enabled {
			enabledCount++
		}
	}

	if targetUser == nil {
		WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	// 如果要删除的是启用用户，检查是否是最后一个
	if targetUser.Enabled && enabledCount <= 1 {
		WriteError(w, http.StatusBadRequest, "必须保留至少一个启用状态的用户，无法删除")
		return
	}

	if err := config.GetManager().DeleteUser(id); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "删除用户", targetUser.Username, fmt.Sprintf("删除用户: %s", targetUser.Username), true, nil)

	WriteSuccess(w, nil)
}

// ConfigHandlers 配置处理器
func GetConfigHandler(w http.ResponseWriter, r *http.Request) {
	cfg := config.GetManager().GetConfig()
	// 隐藏密码
	for i := range cfg.Users {
		cfg.Users[i].Password = ""
	}
	WriteSuccess(w, map[string]interface{}{
		"admin_port":                        cfg.Global.AdminPort,
		"default_auth":                      cfg.Global.DefaultAuth,
		"log_level":                         cfg.Global.LogLevel,
		"log_file":                          cfg.Global.LogFile,
		"log_retention_days":                cfg.Global.LogRetentionDays,
		"max_access_log_entries":            cfg.Global.MaxAccessLogEntries,
		"certificate_config_path":           cfg.Global.CertificateConfigPath,
		"certificate_sync_interval_seconds": cfg.Global.CertificateSyncIntervalSeconds,
		"effective_paths": map[string]string{
			"pid_path":           config.RuntimePIDFilePath(),
			"socket_path":        config.RuntimeSocketFilePath(),
			"cache_path":         config.RuntimeMonitorCachePath(),
			"security_logs_path": config.RuntimeSecurityLogCachePath(),
			"managed_certs_dir":  config.RuntimeManagedCertDir(),
			"account_certs_dir":  config.RuntimeAccountCertDir(),
			"runtime_base_dir":  config.GetRuntimeBaseDir(),
			"config_file_path":  config.ConfigFilePath(),
		},
	})
}

func UpdateConfigHandler(w http.ResponseWriter, r *http.Request) {
	var global models.GlobalConfig
	if err := json.NewDecoder(r.Body).Decode(&global); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := config.GetManager().UpdateGlobal(global); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	utils.GetCertificateManager().RunMaintenanceNow()

	WriteSuccess(w, global)
}

// RestartServerHandler 重启代理服务器
func RestartServerHandler(w http.ResponseWriter, r *http.Request) {
	if err := fnproxy.GetServer().Restart(); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteSuccess(w, map[string]string{"message": "Server restarted successfully"})
}
