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
	mu            sync.RWMutex
	loaded        map[string]*loadedCertificate
	fallback      *tls.Certificate
	httpChallenge *memoryHTTP01Provider
	startOnce     sync.Once
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
		}
		certificateManagerInstance.ensureFallbackCertificate()
		certificateManagerInstance.Reload()
	})
	return certificateManagerInstance
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
		return nil, errors.New("文件校验需要已启用的 HTTP 80 端口监听")
	}

	if err := ensureCertificateDirs(); err != nil {
		return nil, err
	}

	cert.CertPath = filepath.Join(managedCertificateDir(), cert.ID+".crt")
	cert.KeyPath = filepath.Join(managedCertificateDir(), cert.ID+".key")
	cert.AccountKeyPath = filepath.Join(accountCertificateDir(), cert.ID+".account.key")

	resource, reg, err := m.obtainACMEResource(cert)
	if err != nil {
		now := time.Now()
		cert.Status = models.CertificateStatusError
		cert.LastError = err.Error()
		cert.UpdatedAt = now
		if config.GetManager().GetCertificate(cert.ID) != nil {
			_ = config.GetManager().UpdateCertificate(cert)
		}
		return nil, err
	}

	loadedCert, metadata, err := parseCertificatePEM(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return nil, err
	}

	if err := writeFileEnsuringDir(cert.CertPath, resource.Certificate, 0600); err != nil {
		return nil, err
	}
	if err := writeFileEnsuringDir(cert.KeyPath, resource.PrivateKey, 0600); err != nil {
		return nil, err
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
			return nil, err
		}
	} else {
		if err := config.GetManager().UpdateCertificate(cert); err != nil {
			return nil, err
		}
	}

	m.mu.Lock()
	m.loaded[cert.ID] = &loadedCertificate{
		config:  cert,
		tlsCert: loadedCert,
		leaf:    metadata.Leaf,
	}
	m.mu.Unlock()

	return &cert, nil
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
	accountKey, err := loadOrCreateAccountKey(cert.AccountKeyPath)
	if err != nil {
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
		return nil, nil, err
	}

	if err := m.configureChallengeProvider(client, cert); err != nil {
		return nil, nil, err
	}

	reg := user.registration
	if reg == nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, err
		}
		user.registration = reg
	}

	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: cert.Domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, nil, err
	}
	return resource, reg, nil
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
		return client.Challenge.SetDNS01Provider(provider)
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
		cfg.Region = strings.TrimSpace(cert.DNSConfig.TencentRegion)
		return tencentcloud.NewDNSProviderConfig(cfg)
	case models.CertificateDNSAliDNS:
		cfg := alidns.NewDefaultConfig()
		cfg.APIKey = strings.TrimSpace(cert.DNSConfig.AliAccessKey)
		cfg.SecretKey = strings.TrimSpace(cert.DNSConfig.AliSecretKey)
		cfg.SecurityToken = strings.TrimSpace(cert.DNSConfig.AliSecurityToken)
		cfg.RegionID = strings.TrimSpace(cert.DNSConfig.AliRegionID)
		cfg.RAMRole = strings.TrimSpace(cert.DNSConfig.AliRAMRole)
		return alidns.NewDNSProviderConfig(cfg)
	case models.CertificateDNSCloudflare:
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthEmail = strings.TrimSpace(cert.DNSConfig.CloudflareEmail)
		cfg.AuthKey = strings.TrimSpace(cert.DNSConfig.CloudflareAPIKey)
		cfg.AuthToken = strings.TrimSpace(cert.DNSConfig.CloudflareDNSAPIToken)
		cfg.ZoneToken = strings.TrimSpace(cert.DNSConfig.CloudflareZoneToken)
		return cloudflare.NewDNSProviderConfig(cfg)
	default:
		return nil, errors.New("当前 DNS 服务商暂不支持")
	}
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
