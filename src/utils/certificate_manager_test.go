package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestMatchCertificateDomain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "exact", pattern: "example.com", host: "example.com", want: true},
		{name: "wildcard one level", pattern: "*.example.com", host: "api.example.com", want: true},
		{name: "wildcard deep level", pattern: "*.example.com", host: "a.b.example.com", want: false},
		{name: "different host", pattern: "*.example.com", host: "example.net", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := matchCertificateDomain(tc.pattern, tc.host); got != tc.want {
				t.Fatalf("matchCertificateDomain(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
			}
		})
	}
}

func TestParseCertificatePEM(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := generateTestCertificate(t, []string{"example.com", "*.example.com"})
	loaded, metadata, err := parseCertificatePEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertificatePEM returned error: %v", err)
	}

	if loaded == nil || loaded.Leaf == nil {
		t.Fatalf("expected parsed TLS certificate with leaf")
	}
	if metadata.Issuer == "" {
		t.Fatalf("expected issuer to be populated")
	}
	if metadata.ExpiresAt == nil || metadata.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expected certificate to have a future expiration time")
	}
	if len(metadata.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(metadata.Domains))
	}
}

func TestEmbeddedFallbackCertificatePEM(t *testing.T) {
	t.Parallel()

	loaded, err := tls.X509KeyPair([]byte(embeddedFallbackCertPEM), []byte(embeddedFallbackKeyPEM))
	if err != nil {
		t.Fatalf("embedded fallback certificate invalid: %v", err)
	}
	if len(loaded.Certificate) == 0 {
		t.Fatalf("expected embedded fallback certificate chain to be loaded")
	}
}

func generateTestCertificate(t *testing.T, dnsNames []string) ([]byte, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   dnsNames[0],
			Organization: []string{"fnproxy Panel Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
