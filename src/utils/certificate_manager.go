package utils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fnproxy/config"
	"fnproxy/models"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
)

const (
	certificateManagedDir = "certs/managed"
	certificateAccountDir = "certs/accounts"
)

type acmeUser struct {
	email        string
	registration *registration.Resource
	privateKey   crypto.PrivateKey
}

type fileSyncCertificateEntry struct {
	Host string `json:"host"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func managedCertificateDir() string {
	return config.RuntimeManagedCertDir()
}

func accountCertificateDir() string {
	return config.RuntimeAccountCertDir()
}

func resolveCertificatePath(path string) string {
	return config.ResolveRuntimePath(path)
}

func writeFileEnsuringDir(path string, data []byte, perm os.FileMode) error {
	resolvedPath := resolveCertificatePath(path)
	if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(resolvedPath, data, perm)
}

func (u *acmeUser) GetEmail() string {
	return u.email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.privateKey
}

type loadedCertificate struct {
	config  models.CertificateConfig
	tlsCert *tls.Certificate
	leaf    *x509.Certificate
}

type memoryHTTP01Provider struct {
	mu      sync.RWMutex
	records map[string]string
}

func newMemoryHTTP01Provider() *memoryHTTP01Provider {
	return &memoryHTTP01Provider{
		records: make(map[string]string),
	}
}

func (p *memoryHTTP01Provider) Present(_ string, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records[token] = keyAuth
	return nil
}

func (p *memoryHTTP01Provider) CleanUp(_ string, token, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.records, token)
	return nil
}

func (p *memoryHTTP01Provider) Get(token string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	value, ok := p.records[token]
	return value, ok
}

// CertificateManager 管理证书申请、导入、续签和运行时加载。
type CertificateManager struct {
	mu              sync.RWMutex
	loaded          map[string]*loadedCertificate
	fallback        *tls.Certificate
	httpChallenge   *memoryHTTP01Provider
	startOnce       sync.Once
	issueProgress   map[string]*models.CertificateIssueProgress // 证书申请进度跟踪
	manualDNSStore  map[string]*manualDNSChallenge               // 手动DNS验证存储
}

// manualDNSChallenge 手动DNS验证信息
type manualDNSChallenge struct {
	domain   string
	token    string
	keyAuth  string
	createdAt time.Time
}

var (
	certificateManagerInstance *CertificateManager
	certificateManagerOnce     sync.Once
)

// GetCertificateManager 获取证书管理器单例。
func GetCertificateManager() *CertificateManager {
	certificateManagerOnce.Do(func() {
		certificateManagerInstance = &CertificateManager{
			loaded:        make(map[string]*loadedCertificate),
			httpChallenge: newMemoryHTTP01Provider(),
			issueProgress: make(map[string]*models.CertificateIssueProgress),
			manualDNSStore: make(map[string]*manualDNSChallenge),
		}
		certificateManagerInstance.ensureFallbackCertificate()
		certificateManagerInstance.Reload()
		// 启动清理过期手动DNS验证的定时任务
		go certificateManagerInstance.cleanupExpiredManualDNS()
	})
	return certificateManagerInstance
}

// cleanupExpiredManualDNS 清理过期的手动DNS验证记录
func (m *CertificateManager) cleanupExpiredManualDNS() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for id, challenge := range m.manualDNSStore {
			if now.Sub(challenge.createdAt) > 30*time.Minute {
				delete(m.manualDNSStore, id)
			}
		}
		m.mu.Unlock()
	}
}

// GetIssueProgress 获取证书申请进度
func (m *CertificateManager) GetIssueProgress(certID string) *models.CertificateIssueProgress {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if progress, ok := m.issueProgress[certID]; ok {
		// 返回副本
		copy := *progress
		return &copy
	}
	return nil
}

// updateIssueProgress 更新证书申请进度（内部方法）
func (m *CertificateManager) updateIssueProgress(certID string, step models.CertificateIssueStep, status, message, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	if progress, ok := m.issueProgress[certID]; ok {
		progress.Step = step
		progress.Status = status
		progress.Message = message
		progress.Detail = detail
		progress.UpdatedAt = now
		if status == "success" || status == "error" {
			progress.CompletedAt = &now
		}
	}
}

// StartAutoRenew 启动自动续签任务。
func (m *CertificateManager) StartAutoRenew(ctx context.Context) {
	m.startOnce.Do(func() {
		go func() {
			m.runAutoRenew(ctx)
		}()
	})
}

// RunMaintenanceNow 立即执行一次证书维护任务。
func (m *CertificateManager) RunMaintenanceNow() {
	m.processConfigFileSync()
	m.processAutoRenew()
}

func (m *CertificateManager) runAutoRenew(ctx context.Context) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.processConfigFileSync()
			m.processAutoRenew()
			timer.Reset(m.getMaintenanceInterval())
		}
	}
}

func (m *CertificateManager) getMaintenanceInterval() time.Duration {
	interval := config.GetManager().GetConfig().Global.CertificateSyncIntervalSeconds
	if interval <= 0 {
		interval = 3600
	}
	return time.Duration(interval) * time.Second
}

func (m *CertificateManager) processAutoRenew() {
	certs := config.GetManager().GetCertificates()
	now := time.Now()

	for _, cert := range certs {
		if cert.Source != models.CertificateSourceACME || !cert.AutoRenew {
			continue
		}

		if cert.NextRenewAt == nil && cert.ExpiresAt != nil {
			nextRenewAt := cert.ExpiresAt.AddDate(0, 0, -max(cert.RenewBeforeDays, 30))
			cert.NextRenewAt = &nextRenewAt
			_ = config.GetManager().UpdateCertificate(cert)
		}

		if cert.NextRenewAt != nil && now.Before(*cert.NextRenewAt) {
			continue
		}

		_, err := m.RenewCertificate(cert.ID)
		if err != nil {
			fmt.Printf("自动续签证书失败 [%s]: %v\n", cert.ID, err)
		}
	}
}

// Reload 从配置重新加载所有可用证书。
func (m *CertificateManager) Reload() {
	certs := config.GetManager().GetCertificates()
	loaded := make(map[string]*loadedCertificate)

	for _, cert := range certs {
		if cert.CertPath == "" || cert.KeyPath == "" {
			continue
		}

		loadedCert, metadata, err := loadCertificatePair(cert.CertPath, cert.KeyPath)
		if err != nil {
			continue
		}

		cert.Issuer = metadata.Issuer
		cert.ExpiresAt = metadata.ExpiresAt
		cert.Status = metadata.Status
		if cert.AutoRenew && metadata.ExpiresAt != nil {
			nextRenewAt := metadata.ExpiresAt.AddDate(0, 0, -max(cert.RenewBeforeDays, 30))
			cert.NextRenewAt = &nextRenewAt
		}

		loaded[cert.ID] = &loadedCertificate{
			config:  cert,
			tlsCert: loadedCert,
			leaf:    metadata.Leaf,
		}
	}

	m.mu.Lock()
	m.loaded = loaded
	m.mu.Unlock()
}

// ServeHTTPChallenge 响应 ACME HTTP-01 校验请求。
func (m *CertificateManager) ServeHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}

	token := strings.TrimPrefix(r.URL.Path, prefix)
	keyAuth, ok := m.httpChallenge.Get(token)
	if !ok {
		return false
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(keyAuth))
	return true
}

// GetTLSCertificate 根据 SNI 返回最匹配的证书。
func (m *CertificateManager) GetTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := normalizeDomain(hello.ServerName)
	if serverName == "" {
		return m.fallback, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if matched := m.matchCertificateByDomainLocked(serverName); matched != nil {
		return matched, nil
	}
	return m.fallback, nil
}

// GetTLSCertificateForListener 根据监听器和 SNI 返回证书，优先遵循服务显式绑定。
func (m *CertificateManager) GetTLSCertificateForListener(listenerID string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := normalizeDomain(hello.ServerName)
		if serverName == "" {
			return m.fallback, nil
		}

		m.mu.RLock()
		defer m.mu.RUnlock()

		if cert := m.matchCertificateByServiceBindingLocked(listenerID, serverName); cert != nil {
			return cert, nil
		}
		if cert := m.matchCertificateByDomainLocked(serverName); cert != nil {
			return cert, nil
		}
		return m.fallback, nil
	}
}

// ImportCertificate 导入 PEM 证书。
func (m *CertificateManager) ImportCertificate(cert models.CertificateConfig, certPEM, keyPEM string) (*models.CertificateConfig, error) {
	cert.Source = models.CertificateSourceImported
	cert.ChallengeType = ""
	cert.DNSProvider = ""
	cert.AutoRenew = false
	cert.Status = models.CertificateStatusPending

	if cert.ID == "" {
		cert.ID = randomID()
	}

	if err := ensureCertificateDirs(); err != nil {
		return nil, err
	}

	cert.CertPath = filepath.Join(managedCertificateDir(), cert.ID+".crt")
	cert.KeyPath = filepath.Join(managedCertificateDir(), cert.ID+".key")

	parsedCert, metadata, err := parseCertificatePEM([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	if len(cert.Domains) == 0 {
		cert.Domains = metadata.Domains
	}
	cert.Domains = sanitizeDomains(cert.Domains)
	if len(cert.Domains) == 0 {
		return nil, errors.New("导入证书失败：未解析到可用域名")
	}

	if cert.Name == "" {
		cert.Name = cert.Domains[0]
	}

	if err := writeFileEnsuringDir(cert.CertPath, []byte(certPEM), 0600); err != nil {
		return nil, err
	}
	if err := writeFileEnsuringDir(cert.KeyPath, []byte(keyPEM), 0600); err != nil {
		return nil, err
	}

	now := time.Now()
	cert.Issuer = metadata.Issuer
	cert.ExpiresAt = metadata.ExpiresAt
	cert.LastIssuedAt = &now
	cert.Status = metadata.Status
	cert.NextRenewAt = nil
	cert.CreatedAt = now
	cert.UpdatedAt = now

	if err := config.GetManager().AddCertificate(cert); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.loaded[cert.ID] = &loadedCertificate{
		config:  cert,
		tlsCert: parsedCert,
		leaf:    metadata.Leaf,
	}
	m.mu.Unlock()

	return &cert, nil
}

// UpdateCertificate 更新证书配置。
func (m *CertificateManager) UpdateCertificate(id string, incoming models.CertificateConfig, certPEM, keyPEM string) (*models.CertificateConfig, error) {
	existing := config.GetManager().GetCertificate(id)
	if existing == nil {
		return nil, errors.New("证书不存在")
	}
	if existing.Source == models.CertificateSourceFileSync {
		return nil, errors.New("配置文件同步证书不能单独编辑，请修改外部配置文件")
	}

	updated := *existing
	updated.Name = incoming.Name
	updated.Domains = sanitizeDomains(incoming.Domains)
	if len(updated.Domains) == 0 {
		updated.Domains = existing.Domains
	}
	updated.AutoRenew = incoming.AutoRenew
	updated.RenewBeforeDays = incoming.RenewBeforeDays
	updated.AccountEmail = incoming.AccountEmail
	updated.LastError = ""

	switch existing.Source {
	case models.CertificateSourceImported:
		if certPEM != "" || keyPEM != "" {
			if certPEM == "" || keyPEM == "" {
				return nil, errors.New("更新导入证书时，证书 PEM 和私钥 PEM 需要同时提供")
			}
			updatedCert, err := m.replaceImportedCertificate(updated, certPEM, keyPEM)
			if err != nil {
				return nil, err
			}
			return updatedCert, nil
		}

		if err := config.GetManager().UpdateCertificate(updated); err != nil {
			return nil, err
		}
		m.Reload()
		return config.GetManager().GetCertificate(id), nil

	case models.CertificateSourceACME:
		updated.ChallengeType = incoming.ChallengeType
		updated.DNSProvider = incoming.DNSProvider
		updated.DNSConfig = incoming.DNSConfig

		if !needsACMEReissue(*existing, updated) {
			if updated.ExpiresAt != nil && updated.AutoRenew {
				nextRenewAt := updated.ExpiresAt.AddDate(0, 0, -max(updated.RenewBeforeDays, 30))
				updated.NextRenewAt = &nextRenewAt
			} else if !updated.AutoRenew {
				updated.NextRenewAt = nil
			}
			if err := config.GetManager().UpdateCertificate(updated); err != nil {
				return nil, err
			}
			m.Reload()
			return config.GetManager().GetCertificate(id), nil
		}

		return m.IssueACMECertificate(updated)
	default:
		return nil, errors.New("不支持的证书类型")
	}
}

// IssueACMECertificate 申请新证书。
func (m *CertificateManager) IssueACMECertificate(cert models.CertificateConfig) (*models.CertificateConfig, error) {
	if cert.ID == "" {
		cert.ID = randomID()
	}
	cert.Source = models.CertificateSourceACME
	cert.ChallengeType = models.CertificateChallengeType(strings.ToLower(string(cert.ChallengeType)))
	cert.DNSProvider = models.CertificateDNSProvider(strings.ToLower(string(cert.DNSProvider)))
	cert.Domains = sanitizeDomains(cert.Domains)

	if len(cert.Domains) == 0 {
		return nil, errors.New("请至少配置一个域名")
	}
	if cert.Name == "" {
		cert.Name = cert.Domains[0]
	}
	if cert.RenewBeforeDays <= 0 {
		cert.RenewBeforeDays = 30
	}
	if cert.ChallengeType == models.CertificateChallengeHTTP && !hasEnabledHTTP80Listener() {
		return nil, errors.New("文件校验需要已启用的 HTTP 80 网站管理")
	}

	if err := ensureCertificateDirs(); err != nil {
		return nil, err
	}

	cert.CertPath = filepath.Join(managedCertificateDir(), cert.ID+".crt")
	cert.KeyPath = filepath.Join(managedCertificateDir(), cert.ID+".key")
	cert.AccountKeyPath = filepath.Join(accountCertificateDir(), cert.ID+".account.key")

	// 初始化进度跟踪
	now := time.Now()
	m.mu.Lock()
	m.issueProgress[cert.ID] = &models.CertificateIssueProgress{
		CertID:    cert.ID,
		Step:      models.CertificateStepPrepare,
		Status:    "running",
		Message:   "准备申请证书",
		StartedAt: now,
		UpdatedAt: now,
	}
	m.mu.Unlock()

	// 异步执行证书申请，让前端可以立即获取证书ID并开始轮询进度
	go m.issueACMEAsync(cert)

	// 立即返回证书配置（此时证书还在申请中）
	return &cert, nil
}

// issueACMEAsync 异步执行ACME证书申请
func (m *CertificateManager) issueACMEAsync(cert models.CertificateConfig) {
	resource, reg, err := m.obtainACMEResource(cert)
	if err != nil {
		now := time.Now()
		cert.Status = models.CertificateStatusError
		cert.LastError = err.Error()
		cert.UpdatedAt = now
		if config.GetManager().GetCertificate(cert.ID) != nil {
			_ = config.GetManager().UpdateCertificate(cert)
		}
		// 更新进度为错误状态
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "证书申请失败", err.Error())
		return
	}

	loadedCert, metadata, err := parseCertificatePEM(resource.Certificate, resource.PrivateKey)
	if err != nil {
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "解析证书失败", err.Error())
		return
	}

	if err := writeFileEnsuringDir(cert.CertPath, resource.Certificate, 0600); err != nil {
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "保存证书文件失败", err.Error())
		return
	}
	if err := writeFileEnsuringDir(cert.KeyPath, resource.PrivateKey, 0600); err != nil {
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "保存私钥文件失败", err.Error())
		return
	}

	now := time.Now()
	cert.RegistrationURI = reg.URI
	cert.CertURL = resource.CertURL
	cert.CertStableURL = resource.CertStableURL
	cert.Issuer = metadata.Issuer
	cert.ExpiresAt = metadata.ExpiresAt
	cert.LastIssuedAt = &now
	cert.LastRenewedAt = &now
	if metadata.ExpiresAt != nil {
		nextRenewAt := metadata.ExpiresAt.AddDate(0, 0, -max(cert.RenewBeforeDays, 30))
		cert.NextRenewAt = &nextRenewAt
	}
	cert.Status = models.CertificateStatusValid
	cert.LastError = ""
	cert.UpdatedAt = now
	if cert.CreatedAt.IsZero() {
		cert.CreatedAt = now
	}

	if config.GetManager().GetCertificate(cert.ID) == nil {
		if err := config.GetManager().AddCertificate(cert); err != nil {
			m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "保存证书配置失败", err.Error())
			return
		}
	} else {
		if err := config.GetManager().UpdateCertificate(cert); err != nil {
			m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "更新证书配置失败", err.Error())
			return
		}
	}

	m.mu.Lock()
	m.loaded[cert.ID] = &loadedCertificate{
		config:  cert,
		tlsCert: loadedCert,
		leaf:    metadata.Leaf,
	}
	m.mu.Unlock()

	// 更新进度为完成状态
	m.updateIssueProgress(cert.ID, models.CertificateStepComplete, "success", "证书申请成功", "")
}

// RenewCertificate 手动或自动续签 ACME 证书。
func (m *CertificateManager) RenewCertificate(id string) (*models.CertificateConfig, error) {
	cert := config.GetManager().GetCertificate(id)
	if cert == nil {
		return nil, errors.New("证书不存在")
	}
	if cert.Source != models.CertificateSourceACME {
		return nil, errors.New("当前证书不是 ACME 管理证书，无法自动续签")
	}

	cert.Status = models.CertificateStatusRenew
	cert.LastError = ""
	_ = config.GetManager().UpdateCertificate(*cert)

	updated, err := m.IssueACMECertificate(*cert)
	if err != nil {
		failed := *cert
		failed.Status = models.CertificateStatusError
		failed.LastError = err.Error()
		failed.UpdatedAt = time.Now()
		_ = config.GetManager().UpdateCertificate(failed)
		return nil, err
	}
	return updated, nil
}

// DeleteCertificate 删除证书和对应文件。
func (m *CertificateManager) DeleteCertificate(id string) error {
	cert := config.GetManager().GetCertificate(id)
	if cert == nil {
		return errors.New("证书不存在")
	}
	// 外部配置文件同步的证书，允许直接删除内部数据（不同步到外部配置文件）
	isFileSync := cert.Source == models.CertificateSourceFileSync
	for _, service := range config.GetManager().GetServices() {
		if service.CertificateID == id {
			return fmt.Errorf("证书已绑定到服务 [%s]，请先解除绑定", service.Name)
		}
	}

	// 只有非外部同步证书才删除物理文件
	if !isFileSync {
		_ = os.Remove(resolveCertificatePath(cert.CertPath))
		_ = os.Remove(resolveCertificatePath(cert.KeyPath))
		if cert.AccountKeyPath != "" {
			_ = os.Remove(resolveCertificatePath(cert.AccountKeyPath))
		}
	}

	if err := config.GetManager().DeleteCertificate(id); err != nil {
		return err
	}

	m.mu.Lock()
	delete(m.loaded, id)
	m.mu.Unlock()

	return nil
}

func (m *CertificateManager) processConfigFileSync() {
	configPath := strings.TrimSpace(config.GetManager().GetConfig().Global.CertificateConfigPath)
	if configPath == "" {
		m.cleanupStaleFileSyncCertificates("")
		return
	}

	entries, err := readFileSyncCertificateEntries(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Printf("读取外部证书配置失败 [%s]: %v\n", configPath, err)
		return
	}
	m.cleanupStaleFileSyncCertificates(configPath)

	desired := make(map[string]fileSyncCertificateEntry, len(entries))
	for _, entry := range entries {
		entry.Host = normalizeDomain(entry.Host)
		entry.Cert = strings.TrimSpace(entry.Cert)
		entry.Key = strings.TrimSpace(entry.Key)
		if entry.Host == "" || entry.Cert == "" || entry.Key == "" {
			continue
		}

		id := buildFileSyncCertificateID(configPath, entry)
		desired[id] = entry
		if _, err := m.syncFileSyncCertificate(configPath, id, entry); err != nil {
			fmt.Printf("同步外部证书失败 [%s]: %v\n", entry.Host, err)
		}
	}

	m.cleanupRemovedFileSyncCertificates(configPath, desired)
}

func (m *CertificateManager) cleanupStaleFileSyncCertificates(activeConfigPath string) {
	for _, cert := range config.GetManager().GetCertificates() {
		if cert.Source != models.CertificateSourceFileSync {
			continue
		}
		if activeConfigPath != "" && cert.SourceConfigPath == activeConfigPath {
			continue
		}

		clearServiceCertificateBinding(cert.ID)
		_ = config.GetManager().DeleteCertificate(cert.ID)
		m.mu.Lock()
		delete(m.loaded, cert.ID)
		m.mu.Unlock()
	}
}

func readFileSyncCertificateEntries(path string) ([]fileSyncCertificateEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []fileSyncCertificateEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func buildFileSyncCertificateID(configPath string, entry fileSyncCertificateEntry) string {
	sum := sha1.Sum([]byte(configPath + "|" + normalizeDomain(entry.Host)))
	return "file-sync-" + hex.EncodeToString(sum[:8])
}

func (m *CertificateManager) syncFileSyncCertificate(configPath, id string, entry fileSyncCertificateEntry) (bool, error) {
	existing := config.GetManager().GetCertificate(id)

	certInfo, err := os.Stat(entry.Cert)
	if err != nil {
		return false, m.updateFileSyncError(existing, id, configPath, entry, fmt.Errorf("读取证书文件失败: %w", err))
	}
	keyInfo, err := os.Stat(entry.Key)
	if err != nil {
		return false, m.updateFileSyncError(existing, id, configPath, entry, fmt.Errorf("读取私钥文件失败: %w", err))
	}

	needsReload := existing == nil ||
		existing.Source != models.CertificateSourceFileSync ||
		existing.CertPath != entry.Cert ||
		existing.KeyPath != entry.Key ||
		existing.SourceConfigPath != configPath ||
		!sameStringSlice(existing.Domains, []string{entry.Host}) ||
		!timePtrEquals(existing.CertFileUpdatedAt, certInfo.ModTime()) ||
		!timePtrEquals(existing.KeyFileUpdatedAt, keyInfo.ModTime()) ||
		existing.Status != models.CertificateStatusValid

	if !needsReload {
		return false, nil
	}

	loadedCert, metadata, err := loadCertificatePair(entry.Cert, entry.Key)
	if err != nil {
		return false, m.updateFileSyncError(existing, id, configPath, entry, err)
	}

	now := time.Now()
	cert := models.CertificateConfig{
		ID:                id,
		Name:              entry.Host,
		Domains:           []string{entry.Host},
		Source:            models.CertificateSourceFileSync,
		CertPath:          entry.Cert,
		KeyPath:           entry.Key,
		SourceConfigPath:  configPath,
		AutoRenew:         false,
		RenewBeforeDays:   0,
		Issuer:            metadata.Issuer,
		Status:            metadata.Status,
		LastError:         "",
		LastSyncedAt:      &now,
		CertFileUpdatedAt: timePtr(certInfo.ModTime()),
		KeyFileUpdatedAt:  timePtr(keyInfo.ModTime()),
		ExpiresAt:         metadata.ExpiresAt,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if existing != nil {
		cert.Name = firstNonEmpty(existing.Name, entry.Host)
		cert.CreatedAt = existing.CreatedAt
		if strings.TrimSpace(existing.Name) != "" && normalizeDomain(existing.Name) != entry.Host {
			cert.Name = existing.Name
		}
	}

	if existing == nil {
		if err := config.GetManager().AddCertificate(cert); err != nil {
			return false, err
		}
	} else {
		if err := config.GetManager().UpdateCertificate(cert); err != nil {
			return false, err
		}
	}

	m.mu.Lock()
	m.loaded[id] = &loadedCertificate{
		config:  cert,
		tlsCert: loadedCert,
		leaf:    metadata.Leaf,
	}
	m.mu.Unlock()

	return true, nil
}

func (m *CertificateManager) updateFileSyncError(existing *models.CertificateConfig, id, configPath string, entry fileSyncCertificateEntry, sourceErr error) error {
	if existing == nil {
		now := time.Now()
		failed := models.CertificateConfig{
			ID:               id,
			Name:             entry.Host,
			Domains:          sanitizeDomains([]string{entry.Host}),
			Source:           models.CertificateSourceFileSync,
			CertPath:         entry.Cert,
			KeyPath:          entry.Key,
			SourceConfigPath: configPath,
			Status:           models.CertificateStatusError,
			LastError:        sourceErr.Error(),
			LastSyncedAt:     &now,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		_ = config.GetManager().AddCertificate(failed)
		return sourceErr
	}

	failed := *existing
	now := time.Now()
	failed.Status = models.CertificateStatusError
	failed.LastError = sourceErr.Error()
	failed.LastSyncedAt = &now
	failed.UpdatedAt = now
	_ = config.GetManager().UpdateCertificate(failed)
	return sourceErr
}

func (m *CertificateManager) cleanupRemovedFileSyncCertificates(configPath string, desired map[string]fileSyncCertificateEntry) {
	for _, cert := range config.GetManager().GetCertificates() {
		if cert.Source != models.CertificateSourceFileSync || cert.SourceConfigPath != configPath {
			continue
		}
		if _, ok := desired[cert.ID]; ok {
			continue
		}

		clearServiceCertificateBinding(cert.ID)
		_ = config.GetManager().DeleteCertificate(cert.ID)

		m.mu.Lock()
		delete(m.loaded, cert.ID)
		m.mu.Unlock()
	}
}

func (m *CertificateManager) obtainACMEResource(cert models.CertificateConfig) (*certificate.Resource, *registration.Resource, error) {
	// 更新进度：准备阶段
	m.updateIssueProgress(cert.ID, models.CertificateStepPrepare, "running", "准备ACME账户", "")
	fmt.Printf("[证书申请 %s] 开始准备ACME账户\n", cert.ID)

	accountKey, err := loadOrCreateAccountKey(cert.AccountKeyPath)
	if err != nil {
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "加载ACME账户密钥失败", err.Error())
		return nil, nil, err
	}

	user := &acmeUser{
		email:      strings.TrimSpace(cert.AccountEmail),
		privateKey: accountKey,
	}
	if cert.RegistrationURI != "" {
		user.registration = &registration.Resource{URI: cert.RegistrationURI}
	}

	legoConfig := lego.NewConfig(user)
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "创建ACME客户端失败", err.Error())
		return nil, nil, err
	}

	// 更新进度：配置验证
	m.updateIssueProgress(cert.ID, models.CertificateStepChallenge, "running", "配置验证方式", string(cert.ChallengeType))
	fmt.Printf("[证书申请 %s] 配置验证方式: %s\n", cert.ID, cert.ChallengeType)

	if err := m.configureChallengeProvider(client, cert); err != nil {
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "配置验证方式失败", err.Error())
		return nil, nil, err
	}
	fmt.Printf("[证书申请 %s] 验证方式配置完成\n", cert.ID)

	// 更新进度：等待验证
	m.updateIssueProgress(cert.ID, models.CertificateStepVerify, "running", "等待域名验证", "请确保验证配置已生效")
	fmt.Printf("[证书申请 %s] 开始注册ACME账户\n", cert.ID)

	reg := user.registration
	if reg == nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "注册ACME账户失败", err.Error())
			return nil, nil, err
		}
		user.registration = reg
		fmt.Printf("[证书申请 %s] ACME账户注册完成\n", cert.ID)
	}

	// 更新进度：签发证书
	m.updateIssueProgress(cert.ID, models.CertificateStepIssue, "running", "正在签发证书", fmt.Sprintf("域名: %v", cert.Domains))
	fmt.Printf("[证书申请 %s] 开始签发证书，域名: %v\n", cert.ID, cert.Domains)
	fmt.Printf("[证书申请 %s] 即将调用lego Obtain，这可能需要几分钟...\n", cert.ID)

	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: cert.Domains,
		Bundle:  true,
	})
	if err != nil {
		fmt.Printf("[证书申请 %s] Obtain失败: %v\n", cert.ID, err)
		m.updateIssueProgress(cert.ID, models.CertificateStepError, "error", "签发证书失败", err.Error())
		return nil, nil, err
	}
	fmt.Printf("[证书申请 %s] 证书签发完成\n", cert.ID)

	// 更新进度：完成
	m.updateIssueProgress(cert.ID, models.CertificateStepComplete, "success", "证书申请成功", "")
	return resource, reg, nil
}

// 国内DNS服务器列表，用于替代Google DNS
var chinaNameservers = []string{
	"223.5.5.5:53",       // 阿里DNS
	"223.6.6.6:53",       // 阿里DNS备用
	"119.29.29.29:53",    // 腾讯DNS
	"114.114.114.114:53", // 114DNS
}

func init() {
	// 在程序启动时设置国内DNS服务器和超时，避免Google DNS超时
	// 这会影响所有lego库的DNS查询，包括FindZoneByFqdn
	dns01.ClearFqdnCache()
	// 设置DNS超时为30秒
	if err := dns01.AddDNSTimeout(30 * time.Second)(nil); err != nil {
		fmt.Printf("[DNS配置] 设置DNS超时失败: %v\n", err)
	}
	// 设置国内DNS服务器
	if err := dns01.AddRecursiveNameservers(chinaNameservers)(nil); err != nil {
		fmt.Printf("[DNS配置] 设置DNS服务器失败: %v\n", err)
	} else {
		fmt.Printf("[DNS配置] 已设置国内DNS服务器: %v，超时: 30秒\n", chinaNameservers)
	}
}

func (m *CertificateManager) configureChallengeProvider(client *lego.Client, cert models.CertificateConfig) error {
	switch cert.ChallengeType {
	case models.CertificateChallengeHTTP:
		return client.Challenge.SetHTTP01Provider(m.httpChallenge)
	case models.CertificateChallengeDNS:
		provider, err := newDNSProvider(cert)
		if err != nil {
			return err
		}
		fmt.Printf("[证书申请 %s] DNS provider创建成功: %s\n", cert.ID, cert.DNSProvider)
		// 使用国内DNS服务器，避免Google DNS超时
		// 同时禁用预检查，避免在Present之前进行DNS查询超时
		// 设置传播等待时间为60秒，跳过DNS传播检查（由provider自己处理）
		// 清除FQDN缓存，确保使用新的DNS服务器
		dns01.ClearFqdnCache()
		return client.Challenge.SetDNS01Provider(provider, 
			dns01.AddRecursiveNameservers(chinaNameservers),
			dns01.AddDNSTimeout(30*time.Second),
			dns01.DisableAuthoritativeNssPropagationRequirement(),
			dns01.PropagationWait(60*time.Second, true),
		)
	default:
		return errors.New("不支持的证书校验方式")
	}
}

func newDNSProvider(cert models.CertificateConfig) (challenge.Provider, error) {
	switch cert.DNSProvider {
	case models.CertificateDNSTencentCloud:
		cfg := tencentcloud.NewDefaultConfig()
		cfg.SecretID = strings.TrimSpace(cert.DNSConfig.TencentSecretID)
		cfg.SecretKey = strings.TrimSpace(cert.DNSConfig.TencentSecretKey)
		cfg.SessionToken = strings.TrimSpace(cert.DNSConfig.TencentSessionToken)
		// DNSPod API 不需要 Region，设置为空
		cfg.Region = ""
		// 设置HTTP超时为60秒，避免API调用卡住
		cfg.HTTPTimeout = 60 * time.Second
		// 设置传播超时为120秒
		cfg.PropagationTimeout = 120 * time.Second
		// 添加调试日志
		fmt.Printf("[腾讯云DNS] 配置信息: SecretID=%s, Region=%s, HTTPTimeout=%s, PropagationTimeout=%s\n", 
			maskSecret(cfg.SecretID), cfg.Region, cfg.HTTPTimeout, cfg.PropagationTimeout)
		provider, err := tencentcloud.NewDNSProviderConfig(cfg)
		if err != nil {
			fmt.Printf("[腾讯云DNS] 创建provider失败: %v\n", err)
			return nil, fmt.Errorf("腾讯云DNS配置错误: %w", err)
		}
		fmt.Printf("[腾讯云DNS] Provider创建成功\n")
		return provider, nil
	case models.CertificateDNSAliDNS:
		cfg := alidns.NewDefaultConfig()
		cfg.APIKey = strings.TrimSpace(cert.DNSConfig.AliAccessKey)
		cfg.SecretKey = strings.TrimSpace(cert.DNSConfig.AliSecretKey)
		// 设置HTTP超时为60秒
		cfg.HTTPTimeout = 60 * time.Second
		// 设置传播超时为120秒
		cfg.PropagationTimeout = 120 * time.Second
		fmt.Printf("[阿里云DNS] 配置信息: AccessKey=%s\n", maskSecret(cfg.APIKey))
		return alidns.NewDNSProviderConfig(cfg)
	case models.CertificateDNSCloudflare:
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthEmail = strings.TrimSpace(cert.DNSConfig.CloudflareEmail)
		cfg.AuthKey = strings.TrimSpace(cert.DNSConfig.CloudflareAPIKey)
		cfg.AuthToken = strings.TrimSpace(cert.DNSConfig.CloudflareDNSAPIToken)
		cfg.ZoneToken = strings.TrimSpace(cert.DNSConfig.CloudflareZoneToken)
		return cloudflare.NewDNSProviderConfig(cfg)
	case models.CertificateDNSManual:
		// 手动DNS验证，返回一个特殊的provider，会暂停等待用户手动添加记录
		return &manualDNSProvider{certID: cert.ID}, nil
	default:
		return nil, errors.New("当前 DNS 服务商暂不支持")
	}
}

// manualDNSProvider 手动DNS验证provider
type manualDNSProvider struct {
	certID string
}

func (p *manualDNSProvider) Present(domain, token, keyAuth string) error {
	// 存储挑战信息，等待用户手动添加DNS记录
	manager := GetCertificateManager()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	
	manager.manualDNSStore[p.certID] = &manualDNSChallenge{
		domain:    domain,
		token:     token,
		keyAuth:   keyAuth,
		createdAt: time.Now(),
	}
	
	// 构建TXT记录信息
	fqdn := "_acme-challenge." + domain
	if progress, ok := manager.issueProgress[p.certID]; ok {
		progress.Step = models.CertificateStepVerify
		progress.Status = "running"
		progress.Message = "等待手动添加DNS TXT记录"
		progress.Detail = fmt.Sprintf("请在 %s 域名下添加 TXT 记录", domain)
		progress.TXTRecords = []models.DNSTXTRecord{
			{
				Domain: domain,
				Host:   "_acme-challenge",
				Value:  keyAuth,
			},
		}
		progress.UpdatedAt = time.Now()
	}
	
	fmt.Printf("[手动DNS验证 %s] 需要添加TXT记录: %s = %s\n", p.certID, fqdn, keyAuth)
	
	return nil
}

func (p *manualDNSProvider) CleanUp(domain, token, keyAuth string) error {
	// 清理存储的挑战信息
	manager := GetCertificateManager()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	delete(manager.manualDNSStore, p.certID)
	return nil
}

func loadOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	if path != "" {
		resolvedPath := resolveCertificatePath(path)
		if data, err := os.ReadFile(resolvedPath); err == nil {
			return parsePrivateKeyPEM(data)
		}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	if path != "" {
		resolvedPath := resolveCertificatePath(path)
		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(resolvedPath, encodeECPrivateKey(privateKey), 0600); err != nil {
			return nil, err
		}
	}
	return privateKey, nil
}

func ensureCertificateDirs() error {
	if err := os.MkdirAll(managedCertificateDir(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(accountCertificateDir(), 0755); err != nil {
		return err
	}
	return nil
}

func parsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("私钥文件格式不正确")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("不支持的私钥格式")
}

func encodeECPrivateKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func loadCertificatePair(certPath, keyPath string) (*tls.Certificate, certificateMetadata, error) {
	certPEM, err := os.ReadFile(resolveCertificatePath(certPath))
	if err != nil {
		return nil, certificateMetadata{}, err
	}
	keyPEM, err := os.ReadFile(resolveCertificatePath(keyPath))
	if err != nil {
		return nil, certificateMetadata{}, err
	}
	return parseCertificatePEM(certPEM, keyPEM)
}

type certificateMetadata struct {
	Leaf      *x509.Certificate
	Domains   []string
	Issuer    string
	ExpiresAt *time.Time
	Status    models.CertificateStatus
}

func parseCertificatePEM(certPEM, keyPEM []byte) (*tls.Certificate, certificateMetadata, error) {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, certificateMetadata{}, err
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, certificateMetadata{}, errors.New("证书内容为空")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, certificateMetadata{}, err
	}
	tlsCert.Leaf = leaf

	expiresAt := leaf.NotAfter
	status := models.CertificateStatusValid
	if time.Now().After(expiresAt) {
		status = models.CertificateStatusExpired
	}

	domains := sanitizeDomains(append([]string{leaf.Subject.CommonName}, leaf.DNSNames...))
	return &tlsCert, certificateMetadata{
		Leaf:      leaf,
		Domains:   domains,
		Issuer:    leaf.Issuer.CommonName,
		ExpiresAt: &expiresAt,
		Status:    status,
	}, nil
}

func hasEnabledHTTP80Listener() bool {
	listeners := config.GetManager().GetListeners()
	for _, listener := range listeners {
		if listener.Enabled && listener.Protocol == "http" && listener.Port == 80 {
			return true
		}
	}
	return false
}

func sanitizeDomains(domains []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(domains))

	for _, domain := range domains {
		normalized := normalizeDomain(domain)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}

	return result
}

func (m *CertificateManager) matchCertificateByServiceBindingLocked(listenerID, host string) *tls.Certificate {
	services := config.GetManager().GetServicesByPort(listenerID)
	var wildcardCertificateID string
	var defaultCertificateID string

	for _, service := range services {
		if !service.Enabled || strings.TrimSpace(service.CertificateID) == "" {
			continue
		}
		domain := normalizeDomain(service.Domain)
		switch {
		case domain == host:
			if loaded := m.loaded[service.CertificateID]; loaded != nil {
				return loaded.tlsCert
			}
		case domain == "" || domain == "*":
			if defaultCertificateID == "" {
				defaultCertificateID = service.CertificateID
			}
		case matchCertificateDomain(domain, host) && wildcardCertificateID == "":
			wildcardCertificateID = service.CertificateID
		}
	}

	if wildcardCertificateID != "" {
		if loaded := m.loaded[wildcardCertificateID]; loaded != nil {
			return loaded.tlsCert
		}
	}
	if defaultCertificateID != "" {
		if loaded := m.loaded[defaultCertificateID]; loaded != nil {
			return loaded.tlsCert
		}
	}
	return nil
}

func (m *CertificateManager) matchCertificateByDomainLocked(host string) *tls.Certificate {
	var wildcardMatch *tls.Certificate

	for _, loaded := range m.loaded {
		if loaded.tlsCert == nil {
			continue
		}
		// 首先检查证书配置中的域名
		for _, domain := range loaded.config.Domains {
			domain = normalizeDomain(domain)
			if domain == "" {
				continue
			}
			if domain == host {
				return loaded.tlsCert
			}
			if wildcardMatch == nil && matchCertificateDomain(domain, host) {
				wildcardMatch = loaded.tlsCert
			}
		}
		// 然后检查证书实际包含的域名（用于通配符证书匹配）
		if loaded.leaf != nil {
			certDomains := sanitizeDomains(append([]string{loaded.leaf.Subject.CommonName}, loaded.leaf.DNSNames...))
			for _, domain := range certDomains {
				domain = normalizeDomain(domain)
				if domain == "" {
					continue
				}
				if domain == host {
					return loaded.tlsCert
				}
				if wildcardMatch == nil && matchCertificateDomain(domain, host) {
					wildcardMatch = loaded.tlsCert
				}
			}
		}
	}
	return wildcardMatch
}

func needsACMEReissue(existing, updated models.CertificateConfig) bool {
	if strings.TrimSpace(existing.Name) != strings.TrimSpace(updated.Name) &&
		sameStringSlice(existing.Domains, updated.Domains) &&
		existing.ChallengeType == updated.ChallengeType &&
		existing.DNSProvider == updated.DNSProvider &&
		existing.AccountEmail == updated.AccountEmail &&
		sameDNSConfig(existing.DNSConfig, updated.DNSConfig) {
		return false
	}

	if !sameStringSlice(existing.Domains, updated.Domains) {
		return true
	}
	if existing.ChallengeType != updated.ChallengeType {
		return true
	}
	if existing.DNSProvider != updated.DNSProvider {
		return true
	}
	if existing.AccountEmail != updated.AccountEmail {
		return true
	}
	if !sameDNSConfig(existing.DNSConfig, updated.DNSConfig) {
		return true
	}
	if existing.CertPath == "" || existing.KeyPath == "" {
		return true
	}
	return false
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameDNSConfig(a, b models.CertificateDNSConfig) bool {
	return a == b
}

func timePtrEquals(value *time.Time, target time.Time) bool {
	if value == nil {
		return false
	}
	return value.Equal(target)
}

func timePtr(value time.Time) *time.Time {
	v := value
	return &v
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func clearServiceCertificateBinding(certificateID string) {
	services := config.GetManager().GetServices()
	for _, service := range services {
		if service.CertificateID != certificateID {
			continue
		}
		service.CertificateID = ""
		_ = config.GetManager().UpdateService(service)
	}
}

func (m *CertificateManager) replaceImportedCertificate(cert models.CertificateConfig, certPEM, keyPEM string) (*models.CertificateConfig, error) {
	parsedCert, metadata, err := parseCertificatePEM([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	if err := writeFileEnsuringDir(cert.CertPath, []byte(certPEM), 0600); err != nil {
		return nil, err
	}
	if err := writeFileEnsuringDir(cert.KeyPath, []byte(keyPEM), 0600); err != nil {
		return nil, err
	}

	now := time.Now()
	if len(cert.Domains) == 0 {
		cert.Domains = metadata.Domains
	}
	cert.Domains = sanitizeDomains(cert.Domains)
	cert.Issuer = metadata.Issuer
	cert.ExpiresAt = metadata.ExpiresAt
	cert.LastIssuedAt = &now
	cert.LastRenewedAt = nil
	cert.NextRenewAt = nil
	cert.Status = metadata.Status
	cert.UpdatedAt = now

	if err := config.GetManager().UpdateCertificate(cert); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.loaded[cert.ID] = &loadedCertificate{
		config:  cert,
		tlsCert: parsedCert,
		leaf:    metadata.Leaf,
	}
	m.mu.Unlock()
	return &cert, nil
}

func normalizeDomain(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func matchCertificateDomain(pattern, host string) bool {
	pattern = normalizeDomain(pattern)
	host = normalizeDomain(host)
	if pattern == "" || host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := strings.TrimPrefix(pattern, "*")
	if !strings.HasSuffix(host, suffix) {
		return false
	}

	hostLabels := strings.Count(host, ".")
	suffixLabels := strings.Count(strings.TrimPrefix(suffix, "."), ".")
	return hostLabels == suffixLabels+1
}

func (m *CertificateManager) ensureFallbackCertificate() {
	if fallback, err := tls.X509KeyPair([]byte(embeddedFallbackCertPEM), []byte(embeddedFallbackKeyPEM)); err == nil {
		m.fallback = &fallback
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "fnproxy.local",
			Organization: []string{"fnproxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "fnproxy.local"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	fallback, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return
	}
	m.fallback = &fallback
}

func randomID() string {
	return fmt.Sprintf("cert-%d", time.Now().UnixNano())
}

// maskSecret 脱敏显示密钥
func maskSecret(value string) string {
	if len(value) <= 4 {
		if value == "" {
			return ""
		}
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}
