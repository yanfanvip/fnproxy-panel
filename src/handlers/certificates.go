package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"fnproxy/config"
	"fnproxy/models"
	"fnproxy/security"
	"fnproxy/utils"
)

type certificateUpsertRequest struct {
	Name            string                          `json:"name"`
	Domains         []string                        `json:"domains"`
	Source          models.CertificateSource        `json:"source"`
	ChallengeType   models.CertificateChallengeType `json:"challenge_type"`
	DNSProvider     models.CertificateDNSProvider   `json:"dns_provider"`
	DNSConfig       models.CertificateDNSConfig     `json:"dns_config"`
	AccountEmail    string                          `json:"account_email"`
	AutoRenew       bool                            `json:"auto_renew"`
	RenewBeforeDays int                             `json:"renew_before_days"`
	CA              models.CertificateCA            `json:"ca"`
	CertPEM         string                          `json:"cert_pem"`
	KeyPEM          string                          `json:"key_pem"`
}

func ListCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	certs := config.GetManager().GetCertificates()
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].UpdatedAt.After(certs[j].UpdatedAt)
	})

	response := make([]models.CertificateConfig, 0, len(certs)+1)
	for _, cert := range certs {
		certWithDomains := enrichCertificateDomains(cert)
		response = append(response, maskCertificateSecrets(certWithDomains))
	}

	// 追加内置 fallback 自签证书
	if fallbackInfo := utils.GetCertificateManager().GetFallbackCertificateInfo(); fallbackInfo != nil {
		response = append(response, *fallbackInfo)
	}

	WriteSuccess(w, response)
}

func GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/"):]
	cert := config.GetManager().GetCertificate(id)
	if cert == nil {
		WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	WriteSuccess(w, *cert)
}

func CreateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	req, parseErr := parseCertificateUpsertRequest(r)
	if parseErr != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	manager := utils.GetCertificateManager()
	certConfig := buildCertificateConfig(*req)

	var (
		created *models.CertificateConfig
		err     error
	)

	switch req.Source {
	case models.CertificateSourceImported:
		if req.CertPEM == "" || req.KeyPEM == "" {
			WriteError(w, http.StatusBadRequest, "Certificate PEM and key PEM are required")
			return
		}
		created, err = manager.ImportCertificate(certConfig, req.CertPEM, req.KeyPEM)
	case models.CertificateSourceACME:
		// 检查泛域名是否使用了文件校验
		if req.ChallengeType == models.CertificateChallengeHTTP {
			for _, domain := range req.Domains {
				if strings.HasPrefix(domain, "*.") {
					WriteError(w, http.StatusBadRequest, "泛域名证书必须使用DNS校验方式")
					return
				}
			}
		}
		created, err = manager.IssueACMECertificate(certConfig)
	default:
		WriteError(w, http.StatusBadRequest, "Unsupported certificate source")
		return
	}

	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "新增证书", created.Name, fmt.Sprintf("新增证书: %s (域名: %v)", created.Name, created.Domains), true, nil)

	WriteSuccess(w, maskCertificateSecrets(*created))
}

func UpdateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/"):]
	req, err := parseCertificateUpsertRequest(r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	updated, err := utils.GetCertificateManager().UpdateCertificate(id, buildCertificateConfig(*req), req.CertPEM, req.KeyPEM)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "修改证书", updated.Name, fmt.Sprintf("修改证书: %s", updated.Name), true, nil)

	WriteSuccess(w, maskCertificateSecrets(*updated))
}

func DeleteCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/"):]
	cert := config.GetManager().GetCertificate(id)
	if err := utils.GetCertificateManager().DeleteCertificate(id); err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	certName := id
	if cert != nil {
		certName = cert.Name
	}
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "删除证书", certName, fmt.Sprintf("删除证书: %s", certName), true, nil)

	WriteSuccess(w, nil)
}

func RenewCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/") : len(r.URL.Path)-len("/renew")]
	updated, err := utils.GetCertificateManager().RenewCertificate(id)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "续期证书", updated.Name, fmt.Sprintf("续期证书: %s", updated.Name), true, nil)

	WriteSuccess(w, maskCertificateSecrets(*updated))
}

// GetCertificateIssueProgressHandler 获取证书申请进度
func GetCertificateIssueProgressHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/") : len(r.URL.Path)-len("/progress")]
	progress := utils.GetCertificateManager().GetIssueProgress(id)
	if progress == nil {
		WriteError(w, http.StatusNotFound, "未找到证书申请进度")
		return
	}
	WriteSuccess(w, progress)
}

// VerifyManualDNSHandler 验证手动DNS记录
func VerifyManualDNSHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/") : len(r.URL.Path)-len("/verify-manual-dns")]
	
	// 获取手动DNS验证信息
	challenge := utils.GetCertificateManager().GetManualDNSChallenge(id)
	if challenge == nil {
		WriteError(w, http.StatusNotFound, "未找到手动DNS验证信息")
		return
	}
	
	// 触发DNS验证
	if err := utils.GetCertificateManager().TriggerManualDNSVerification(id); err != nil {
		WriteError(w, http.StatusInternalServerError, "触发DNS验证失败: "+err.Error())
		return
	}
	
	WriteSuccess(w, map[string]string{"message": "DNS验证已触发"})
}

// enrichCertificateDomains 从证书文件中读取域名信息（针对导入和外部同步的证书）
func enrichCertificateDomains(cert models.CertificateConfig) models.CertificateConfig {
	// 只有导入的证书或外部同步的证书才需要从文件读取域名
	if cert.Source != models.CertificateSourceImported && cert.Source != models.CertificateSourceFileSync {
		return cert
	}

	// 如果证书路径为空，无法读取
	if cert.CertPath == "" {
		return cert
	}

	// 尝试从证书文件读取域名
	meta, err := utils.GetCertificateMetadata(cert.CertPath, cert.KeyPath)
	if err != nil {
		// 读取失败，保持原有域名信息
		return cert
	}

	// 使用证书文件中的域名
	if len(meta.Domains) > 0 {
		cert.Domains = meta.Domains
		// 使用第一个域名作为证书名称
		cert.Name = meta.Domains[0]
	}
	if meta.Issuer != "" {
		cert.Issuer = meta.Issuer
	}
	if meta.ExpiresAt != nil {
		cert.ExpiresAt = meta.ExpiresAt
	}

	return cert
}

func maskCertificateSecrets(cert models.CertificateConfig) models.CertificateConfig {
	cert.DNSConfig.TencentSecretID = MaskSecret(cert.DNSConfig.TencentSecretID)
	cert.DNSConfig.TencentSecretKey = MaskSecret(cert.DNSConfig.TencentSecretKey)
	cert.DNSConfig.TencentSessionToken = MaskSecret(cert.DNSConfig.TencentSessionToken)
	cert.DNSConfig.AliAccessKey = MaskSecret(cert.DNSConfig.AliAccessKey)
	cert.DNSConfig.AliSecretKey = MaskSecret(cert.DNSConfig.AliSecretKey)
	cert.DNSConfig.AliSecurityToken = MaskSecret(cert.DNSConfig.AliSecurityToken)
	cert.DNSConfig.CloudflareAPIKey = MaskSecret(cert.DNSConfig.CloudflareAPIKey)
	cert.DNSConfig.CloudflareDNSAPIToken = MaskSecret(cert.DNSConfig.CloudflareDNSAPIToken)
	cert.DNSConfig.CloudflareZoneToken = MaskSecret(cert.DNSConfig.CloudflareZoneToken)
	return cert
}

func buildCertificateConfig(req certificateUpsertRequest) models.CertificateConfig {
	// 默认使用 Let's Encrypt
	ca := req.CA
	if ca == "" {
		ca = models.CertificateCALetsEncrypt
	}
	return models.CertificateConfig{
		Name:            req.Name,
		Domains:         req.Domains,
		Source:          req.Source,
		ChallengeType:   req.ChallengeType,
		DNSProvider:     req.DNSProvider,
		DNSConfig:       req.DNSConfig,
		AccountEmail:    req.AccountEmail,
		AutoRenew:       req.AutoRenew,
		RenewBeforeDays: req.RenewBeforeDays,
		CA:              ca,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

func parseCertificateUpsertRequest(r *http.Request) (*certificateUpsertRequest, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		return parseCertificateMultipartRequest(r)
	}

	var req certificateUpsertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	req.Source = normalizeCertificateSource(req.Source)
	return &req, nil
}

func parseCertificateMultipartRequest(r *http.Request) (*certificateUpsertRequest, error) {
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		return nil, err
	}

	req := &certificateUpsertRequest{
		Name:            strings.TrimSpace(r.FormValue("name")),
		Source:          normalizeCertificateSource(models.CertificateSource(strings.TrimSpace(r.FormValue("source")))),
		ChallengeType:   models.CertificateChallengeType(strings.TrimSpace(r.FormValue("challenge_type"))),
		DNSProvider:     models.CertificateDNSProvider(strings.TrimSpace(r.FormValue("dns_provider"))),
		AccountEmail:    strings.TrimSpace(r.FormValue("account_email")),
		AutoRenew:       strings.EqualFold(strings.TrimSpace(r.FormValue("auto_renew")), "true"),
		RenewBeforeDays: 30,
	}

	if value := strings.TrimSpace(r.FormValue("renew_before_days")); value != "" {
		if _, err := fmt.Sscanf(value, "%d", &req.RenewBeforeDays); err != nil {
			req.RenewBeforeDays = 30
		}
	}

	req.Domains = parseDomainsField(r.FormValue("domains"))

	if certPEM, err := readUploadedTextFile(r, "cert_file"); err == nil {
		req.CertPEM = certPEM
	}
	if keyPEM, err := readUploadedTextFile(r, "key_file"); err == nil {
		req.KeyPEM = keyPEM
	}

	return req, nil
}

func readUploadedTextFile(r *http.Request, field string) (string, error) {
	file, _, err := r.FormFile(field)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func parseDomainsField(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	var domains []string
	if strings.HasPrefix(value, "[") {
		if err := json.Unmarshal([]byte(value), &domains); err == nil {
			return domains
		}
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func normalizeCertificateSource(source models.CertificateSource) models.CertificateSource {
	switch source {
	case "import":
		return models.CertificateSourceImported
	default:
		return source
	}
}

// DownloadCertificateHandler 下载证书文件（ZIP格式）
func DownloadCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/certificates/"):]
	id = strings.TrimSuffix(id, "/download")
	
	cert := config.GetManager().GetCertificate(id)
	if cert == nil {
		WriteError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	// 创建ZIP文件
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// 添加证书文件
	certFileName := cert.ID + ".crt"
	if data, err := os.ReadFile(cert.CertPath); err == nil {
		w, _ := zipWriter.Create(certFileName)
		w.Write(data)
	}

	// 添加私钥文件
	keyFileName := cert.ID + ".key"
	if data, err := os.ReadFile(cert.KeyPath); err == nil {
		w, _ := zipWriter.Create(keyFileName)
		w.Write(data)
	}

	// 添加CA证书（如果是ACME证书）
	if cert.Source == models.CertificateSourceACME {
		// 尝试读取issuer证书
		issuerPath := strings.TrimSuffix(cert.CertPath, ".crt") + "-issuer.crt"
		if data, err := os.ReadFile(issuerPath); err == nil {
			w, _ := zipWriter.Create(cert.ID + "-ca.crt")
			w.Write(data)
		}
	}

	zipWriter.Close()

	// 设置响应头
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zip\"", cert.ID))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Write(buf.Bytes())
}

// GenerateSelfSignedCertificateHandler 生成自签证书
func GenerateSelfSignedCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Domains) == 0 {
		WriteError(w, http.StatusBadRequest, "Domains are required")
		return
	}

	manager := utils.GetCertificateManager()
	cert, err := manager.GenerateSelfSignedCertificate(req.Domains)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 记录安全日志
	security.GetAuditLogger().LogSystemOperate("system", r.RemoteAddr, "create", cert.ID, "生成自签证书", true, map[string]any{
		"domains": req.Domains,
	})

	WriteSuccess(w, cert)
}
