package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fnproxy/models"
	"fnproxy/security"
)

const defaultCertificateConfigPath = "/usr/trim/etc/network_gateway_cert.conf"

type Manager struct {
	mu     sync.RWMutex
	config models.AppConfig
}

func cloneAppConfig(cfg models.AppConfig) models.AppConfig {
	cfg.Listeners = append([]models.PortListener(nil), cfg.Listeners...)
	cfg.Services = append([]models.ServiceConfig(nil), cfg.Services...)
	cfg.Certs = append([]models.CertificateConfig(nil), cfg.Certs...)
	cfg.Users = append([]models.User(nil), cfg.Users...)
	cfg.SSH = append([]models.SSHConnection(nil), cfg.SSH...)
	if cfg.Firewall != nil {
		fw := *cfg.Firewall
		fw.Rules = append([]models.FirewallRule(nil), cfg.Firewall.Rules...)
		cfg.Firewall = &fw
	}
	return cfg
}

var instance *Manager
var once sync.Once

// GetManager 获取配置管理器单例
func GetManager() *Manager {
	once.Do(func() {
		instance = &Manager{
			config: models.AppConfig{
				Global: models.GlobalConfig{
					AdminPort:                      8080,
					DefaultAuth:                    false,
					LogLevel:                       "info",
					LogFile:                        "fnproxy.log",
					LogRetentionDays:               7,
					MaxAccessLogEntries:            10000,
					MaxSecurityLogEntries:          5000,
					CertificateConfigPath:          defaultCertificateConfigPath,
					CertificateSyncIntervalSeconds: 3600,
				},
				Listeners: []models.PortListener{},
				Services:  []models.ServiceConfig{},
				Certs:     []models.CertificateConfig{},
				SSH:       []models.SSHConnection{},
				Users: []models.User{
					{
						ID:        "admin",
						Username:  "admin",
						Password:  security.HashPassword("admin"), // 默认密码 admin
											Email:     "admin@admin.com",
						Enabled:   true,
						Role:      "admin",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
			},
		}
		instance.Load()
	})
	return instance
}

// Load 从文件加载配置
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return m.Save()
		}
		return err
	}

	if err := json.Unmarshal(data, &m.config); err != nil {
		return err
	}
	m.normalizeGlobalLocked()
	m.normalizeAllServiceOrdersLocked()
	return nil
}

// Save 保存配置到文件
func (m *Manager) Save() error {
	m.normalizeGlobalLocked()
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}
	configPath := ConfigFilePath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

func (m *Manager) normalizeGlobalLocked() {
	if m.config.Global.AdminPort <= 0 {
		m.config.Global.AdminPort = 8080
	}
	if m.config.Global.LogLevel == "" {
		m.config.Global.LogLevel = "info"
	}
	if m.config.Global.LogFile == "" {
		m.config.Global.LogFile = "fnproxy.log"
	}
	if m.config.Global.LogRetentionDays <= 0 {
		m.config.Global.LogRetentionDays = 7
	}
	if m.config.Global.MaxAccessLogEntries <= 0 {
		m.config.Global.MaxAccessLogEntries = 10000
	}
	if m.config.Global.MaxSecurityLogEntries <= 0 {
		m.config.Global.MaxSecurityLogEntries = 5000
	}
	if strings.TrimSpace(m.config.Global.CertificateConfigPath) == "" {
		m.config.Global.CertificateConfigPath = defaultCertificateConfigPath
	}
	if m.config.Global.CertificateSyncIntervalSeconds <= 0 {
		m.config.Global.CertificateSyncIntervalSeconds = 3600
	}
	for i := range m.config.Certs {
		m.normalizeCertificateLocked(&m.config.Certs[i])
	}
}

func serviceDomainValue(service models.ServiceConfig) string {
	domain := strings.TrimSpace(service.Domain)
	if domain == "" {
		return "*"
	}
	return domain
}

func isDefaultServiceRule(service models.ServiceConfig) bool {
	return serviceDomainValue(service) == "*"
}

func serviceSortKey(order int, fallback int) int {
	if order > 0 {
		return order
	}
	return 1000000 + fallback
}

func (m *Manager) normalizeAllServiceOrdersLocked() {
	portSeen := make(map[string]struct{})
	for _, service := range m.config.Services {
		if _, exists := portSeen[service.PortID]; exists {
			continue
		}
		portSeen[service.PortID] = struct{}{}
		m.normalizeServiceOrderLocked(service.PortID)
	}
}

func (m *Manager) normalizeServiceOrderLocked(portID string) {
	type serviceEntry struct {
		index    int
		fallback int
		service  models.ServiceConfig
	}

	entries := make([]serviceEntry, 0)
	for index, service := range m.config.Services {
		if service.PortID != portID {
			continue
		}
		entries = append(entries, serviceEntry{
			index:    index,
			fallback: len(entries),
			service:  service,
		})
	}
	if len(entries) == 0 {
		return
	}

	sort.SliceStable(entries, func(i, j int) bool {
		leftDefault := isDefaultServiceRule(entries[i].service)
		rightDefault := isDefaultServiceRule(entries[j].service)
		if leftDefault != rightDefault {
			return !leftDefault
		}
		leftOrder := serviceSortKey(entries[i].service.SortOrder, entries[i].fallback)
		rightOrder := serviceSortKey(entries[j].service.SortOrder, entries[j].fallback)
		if leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		return entries[i].fallback < entries[j].fallback
	})

	nextOrder := 1
	for _, entry := range entries {
		m.config.Services[entry.index].SortOrder = nextOrder
		nextOrder++
	}
}

func (m *Manager) normalizeCertificateLocked(cert *models.CertificateConfig) {
	if cert == nil {
		return
	}
	if cert.Status == "" {
		cert.Status = models.CertificateStatusPending
	}
	if cert.AutoRenew && cert.RenewBeforeDays <= 0 {
		cert.RenewBeforeDays = 30
	}
	if cert.Source == "" {
		cert.Source = models.CertificateSourceImported
	}
}

// GetConfig 获取配置
func (m *Manager) GetConfig() models.AppConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneAppConfig(m.config)
}

// UpdateGlobal 更新全局配置
func (m *Manager) UpdateGlobal(global models.GlobalConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.Global = global
	m.normalizeGlobalLocked()
	return m.Save()
}

// GetListeners 获取所有监听器
func (m *Manager) GetListeners() []models.PortListener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]models.PortListener(nil), m.config.Listeners...)
}

// GetListener 获取指定监听器
func (m *Manager) GetListener(id string) *models.PortListener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.config.Listeners {
		if m.config.Listeners[i].ID == id {
			return &m.config.Listeners[i]
		}
	}
	return nil
}

// AddListener 添加监听器
func (m *Manager) AddListener(listener models.PortListener) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	listener.CreatedAt = time.Now()
	listener.UpdatedAt = time.Now()
	m.config.Listeners = append(m.config.Listeners, listener)
	return m.Save()
}

// UpdateListener 更新监听器
func (m *Manager) UpdateListener(listener models.PortListener) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.config.Listeners {
		if m.config.Listeners[i].ID == listener.ID {
			listener.UpdatedAt = time.Now()
			m.config.Listeners[i] = listener
			return m.Save()
		}
	}
	return nil
}

// DeleteListener 删除监听器
func (m *Manager) DeleteListener(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, l := range m.config.Listeners {
		if l.ID == id {
			m.config.Listeners = append(m.config.Listeners[:i], m.config.Listeners[i+1:]...)
			filteredServices := make([]models.ServiceConfig, 0, len(m.config.Services))
			for _, service := range m.config.Services {
				if service.PortID != id {
					filteredServices = append(filteredServices, service)
				}
			}
			m.config.Services = filteredServices
			return m.Save()
		}
	}
	return nil
}

// GetServices 获取所有服务
func (m *Manager) GetServices() []models.ServiceConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]models.ServiceConfig(nil), m.config.Services...)
}

// GetServicesByPort 获取指定端口的服务
func (m *Manager) GetServicesByPort(portID string) []models.ServiceConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var services []models.ServiceConfig
	for _, s := range m.config.Services {
		if s.PortID == portID {
			services = append(services, s)
		}
	}
	sort.SliceStable(services, func(i, j int) bool {
		leftDefault := isDefaultServiceRule(services[i])
		rightDefault := isDefaultServiceRule(services[j])
		if leftDefault != rightDefault {
			return !leftDefault
		}
		if services[i].SortOrder != services[j].SortOrder {
			if services[i].SortOrder == 0 {
				return false
			}
			if services[j].SortOrder == 0 {
				return true
			}
			return services[i].SortOrder < services[j].SortOrder
		}
		return services[i].CreatedAt.Before(services[j].CreatedAt)
	})
	return services
}

// GetService 获取指定服务
func (m *Manager) GetService(id string) *models.ServiceConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.config.Services {
		if m.config.Services[i].ID == id {
			return &m.config.Services[i]
		}
	}
	return nil
}

// AddService 添加服务
func (m *Manager) AddService(service models.ServiceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	service.CreatedAt = time.Now()
	service.UpdatedAt = time.Now()
	maxOrder := 0
	for _, existing := range m.config.Services {
		if existing.PortID == service.PortID && !isDefaultServiceRule(existing) && existing.SortOrder > maxOrder {
			maxOrder = existing.SortOrder
		}
	}
	if service.SortOrder <= 0 {
		service.SortOrder = maxOrder + 1
	}
	m.config.Services = append(m.config.Services, service)
	m.normalizeServiceOrderLocked(service.PortID)
	return m.Save()
}

// UpdateService 更新服务
func (m *Manager) UpdateService(service models.ServiceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.config.Services {
		if m.config.Services[i].ID == service.ID {
			existing := m.config.Services[i]
			service.CreatedAt = existing.CreatedAt
			if service.SortOrder <= 0 {
				service.SortOrder = existing.SortOrder
			}
			service.UpdatedAt = time.Now()
			m.config.Services[i] = service
			m.normalizeServiceOrderLocked(service.PortID)
			return m.Save()
		}
	}
	return nil
}

// DeleteService 删除服务
func (m *Manager) DeleteService(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.config.Services {
		if s.ID == id {
			m.config.Services = append(m.config.Services[:i], m.config.Services[i+1:]...)
			m.normalizeServiceOrderLocked(s.PortID)
			return m.Save()
		}
	}
	return nil
}

func (m *Manager) ReorderServices(portID string, orderedIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	orderLookup := make(map[string]int, len(orderedIDs))
	nextOrder := 1
	for _, id := range orderedIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := orderLookup[id]; exists {
			continue
		}
		orderLookup[id] = nextOrder
		nextOrder++
	}

	for i := range m.config.Services {
		service := &m.config.Services[i]
		if service.PortID != portID || isDefaultServiceRule(*service) {
			continue
		}
		if order, exists := orderLookup[service.ID]; exists {
			service.SortOrder = order
		}
	}

	for i := range m.config.Services {
		service := &m.config.Services[i]
		if service.PortID != portID || isDefaultServiceRule(*service) {
			continue
		}
		if _, exists := orderLookup[service.ID]; exists {
			continue
		}
		service.SortOrder = nextOrder
		nextOrder++
	}

	m.normalizeServiceOrderLocked(portID)
	return m.Save()
}

// GetCertificates 获取所有证书
func (m *Manager) GetCertificates() []models.CertificateConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]models.CertificateConfig(nil), m.config.Certs...)
}

// GetCertificate 获取指定证书
func (m *Manager) GetCertificate(id string) *models.CertificateConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.config.Certs {
		if m.config.Certs[i].ID == id {
			return &m.config.Certs[i]
		}
	}
	return nil
}

// AddCertificate 添加证书
func (m *Manager) AddCertificate(cert models.CertificateConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert.CreatedAt = time.Now()
	cert.UpdatedAt = time.Now()
	m.normalizeCertificateLocked(&cert)
	m.config.Certs = append(m.config.Certs, cert)
	return m.Save()
}

// UpdateCertificate 更新证书
func (m *Manager) UpdateCertificate(cert models.CertificateConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.config.Certs {
		if m.config.Certs[i].ID == cert.ID {
			cert.UpdatedAt = time.Now()
			m.normalizeCertificateLocked(&cert)
			m.config.Certs[i] = cert
			return m.Save()
		}
	}
	return nil
}

// DeleteCertificate 删除证书
func (m *Manager) DeleteCertificate(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, cert := range m.config.Certs {
		if cert.ID == id {
			m.config.Certs = append(m.config.Certs[:i], m.config.Certs[i+1:]...)
			return m.Save()
		}
	}
	return nil
}

// GetUsers 获取所有用户
func (m *Manager) GetUsers() []models.User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]models.User(nil), m.config.Users...)
}

// GetUserByUsername 通过用户名获取用户
func (m *Manager) GetUserByUsername(username string) *models.User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.config.Users {
		if m.config.Users[i].Username == username {
			return &m.config.Users[i]
		}
	}
	return nil
}

// GetUserByToken 通过访问令牌获取用户
func (m *Manager) GetUserByToken(token string) *models.User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	for i := range m.config.Users {
		if strings.TrimSpace(m.config.Users[i].Token) == token {
			return &m.config.Users[i]
		}
	}
	return nil
}

// AddUser 添加用户
func (m *Manager) AddUser(user models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.config.Users = append(m.config.Users, user)
	return m.Save()
}

// UpdateUser 更新用户
func (m *Manager) UpdateUser(user models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.config.Users {
		if m.config.Users[i].ID == user.ID {
			user.UpdatedAt = time.Now()
			m.config.Users[i] = user
			return m.Save()
		}
	}
	return nil
}

// DeleteUser 删除用户
func (m *Manager) DeleteUser(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, u := range m.config.Users {
		if u.ID == id {
			m.config.Users = append(m.config.Users[:i], m.config.Users[i+1:]...)
			return m.Save()
		}
	}
	return nil
}

// GetSSHConnections 获取所有SSH连接
func (m *Manager) GetSSHConnections() []models.SSHConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]models.SSHConnection(nil), m.config.SSH...)
}

// GetSSHConnection 获取指定SSH连接
func (m *Manager) GetSSHConnection(id string) *models.SSHConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.config.SSH {
		if m.config.SSH[i].ID == id {
			return &m.config.SSH[i]
		}
	}
	return nil
}

// AddSSHConnection 添加SSH连接
func (m *Manager) AddSSHConnection(conn models.SSHConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	conn.CreatedAt = time.Now()
	conn.UpdatedAt = time.Now()
	m.config.SSH = append(m.config.SSH, conn)
	return m.Save()
}

// UpdateSSHConnection 更新SSH连接
func (m *Manager) UpdateSSHConnection(conn models.SSHConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.config.SSH {
		if m.config.SSH[i].ID == conn.ID {
			conn.UpdatedAt = time.Now()
			m.config.SSH[i] = conn
			return m.Save()
		}
	}
	return nil
}

// DeleteSSHConnection 删除SSH连接
func (m *Manager) DeleteSSHConnection(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, conn := range m.config.SSH {
		if conn.ID == id {
			m.config.SSH = append(m.config.SSH[:i], m.config.SSH[i+1:]...)
			return m.Save()
		}
	}
	return nil
}

// GetFirewallConfig 获取防火墙配置
func (m *Manager) GetFirewallConfig() *models.FirewallConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config.Firewall == nil {
		return &models.FirewallConfig{
			Enabled:     false,
			DefaultDeny: false,
			Rules:       []models.FirewallRule{},
		}
	}
	fw := *m.config.Firewall
	fw.Rules = append([]models.FirewallRule(nil), m.config.Firewall.Rules...)
	return &fw
}

// LoadFirewallConfig 获取防火墙配置（从主配置中读取）
func (m *Manager) LoadFirewallConfig() (*models.FirewallConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.Firewall == nil {
		m.config.Firewall = &models.FirewallConfig{
			Enabled:     false,
			DefaultDeny: false,
			Rules:       []models.FirewallRule{},
		}
	}
	fw := *m.config.Firewall
	fw.Rules = append([]models.FirewallRule(nil), m.config.Firewall.Rules...)
	return &fw, nil
}

// SaveFirewallConfig 保存防火墙配置到主配置文件
func (m *Manager) SaveFirewallConfig(config *models.FirewallConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.Firewall = config
	return m.Save()
}

// UpdateFirewallConfig 更新防火墙配置
func (m *Manager) UpdateFirewallConfig(config models.FirewallConfig) error {
	return m.SaveFirewallConfig(&config)
}

// AddFirewallRule 添加防火墙规则
func (m *Manager) AddFirewallRule(rule models.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.Firewall == nil {
		m.config.Firewall = &models.FirewallConfig{
			Enabled:     false,
			DefaultDeny: false,
			Rules:       []models.FirewallRule{},
		}
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	m.config.Firewall.Rules = append(m.config.Firewall.Rules, rule)
	return m.Save()
}

// UpdateFirewallRule 更新防火墙规则
func (m *Manager) UpdateFirewallRule(rule models.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.Firewall == nil {
		return nil
	}
	for i := range m.config.Firewall.Rules {
		if m.config.Firewall.Rules[i].ID == rule.ID {
			rule.CreatedAt = m.config.Firewall.Rules[i].CreatedAt
			rule.UpdatedAt = time.Now()
			m.config.Firewall.Rules[i] = rule
			return m.Save()
		}
	}
	return nil
}

// DeleteFirewallRule 删除防火墙规则
func (m *Manager) DeleteFirewallRule(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.Firewall == nil {
		return nil
	}
	for i, rule := range m.config.Firewall.Rules {
		if rule.ID == id {
			m.config.Firewall.Rules = append(m.config.Firewall.Rules[:i], m.config.Firewall.Rules[i+1:]...)
			return m.Save()
		}
	}
	return nil
}
