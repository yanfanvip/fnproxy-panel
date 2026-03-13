package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"caddy-panel/config"
	"caddy-panel/models"
	"caddy-panel/security"
	"caddy-panel/utils"
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
	CertPEM         string                          `json:"cert_pem"`
	KeyPEM          string                          `json:"key_pem"`
}

func ListCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	certs := config.GetManager().GetCertificates()
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].UpdatedAt.After(certs[j].UpdatedAt)
	})

	response := make([]models.CertificateConfig, 0, len(certs))
	for _, cert := range certs {
		response = append(response, maskCertificateSecrets(cert))
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

func maskCertificateSecrets(cert models.CertificateConfig) models.CertificateConfig {
	cert.DNSConfig.TencentSecretID = maskSecret(cert.DNSConfig.TencentSecretID)
	cert.DNSConfig.TencentSecretKey = maskSecret(cert.DNSConfig.TencentSecretKey)
	cert.DNSConfig.TencentSessionToken = maskSecret(cert.DNSConfig.TencentSessionToken)
	cert.DNSConfig.AliAccessKey = maskSecret(cert.DNSConfig.AliAccessKey)
	cert.DNSConfig.AliSecretKey = maskSecret(cert.DNSConfig.AliSecretKey)
	cert.DNSConfig.AliSecurityToken = maskSecret(cert.DNSConfig.AliSecurityToken)
	cert.DNSConfig.CloudflareAPIKey = maskSecret(cert.DNSConfig.CloudflareAPIKey)
	cert.DNSConfig.CloudflareDNSAPIToken = maskSecret(cert.DNSConfig.CloudflareDNSAPIToken)
	cert.DNSConfig.CloudflareZoneToken = maskSecret(cert.DNSConfig.CloudflareZoneToken)
	return cert
}

func maskSecret(value string) string {
	if len(value) <= 4 {
		if value == "" {
			return ""
		}
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

func buildCertificateConfig(req certificateUpsertRequest) models.CertificateConfig {
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
