package unauthenticated

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/scepman/terraform-provider-scepman/internal/client/scepman"
	"github.com/scepman/terraform-provider-scepman/internal/types"
)

func TestNewClientTransport(t *testing.T) {
	c, transport := testClient(t, "https://localhost")
	config := transport.TLSClientConfig
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS12 {
		t.Fatal("CA transport must use TLS 1.2 for App Service renegotiation")
	}
	if config.Renegotiation != tls.RenegotiateOnceAsClient {
		t.Fatal("CA transport must permit exactly one renegotiation")
	}
	if config.InsecureSkipVerify || config.RootCAs != nil || config.ServerName != "" {
		t.Fatal("CA transport must retain system trust and URL hostname verification")
	}
	if transport.Protocols == nil || !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() || transport.Protocols.UnencryptedHTTP2() {
		t.Fatal("CA transport must use HTTP/1.1 only")
	}
	if transport.Proxy == nil || transport.DialContext == nil || transport.TLSHandshakeTimeout == 0 {
		t.Fatal("CA transport lost SDK proxy, dialer, or timeout behavior")
	}
	if c.Authorizer != nil || len(config.Certificates) != 0 || config.GetClientCertificate != nil {
		t.Fatal("CA client must remain unauthenticated")
	}
	_, otherTransport := testClient(t, "https://localhost")
	if transport == otherTransport || config == otherTransport.TLSClientConfig || c.Transport == http.DefaultTransport {
		t.Fatal("CA clients must not share mutable transport configuration")
	}
	authenticated, err := scepman.NewClient(environments.NewApiEndpoint("scepman", "https://localhost", nil))
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.Transport != nil {
		t.Fatal("authenticated client must retain the SDK's default transport")
	}
}

func TestGetRootCaCertificateHTTPS(t *testing.T) {
	for _, clientAuth := range []tls.ClientAuthType{tls.NoClientCert, tls.RequestClientCert} {
		t.Run(clientAuth.String(), func(t *testing.T) {
			cert := testCertificate(t)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/ca" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if r.ProtoMajor != 1 || r.TLS == nil || r.TLS.Version != tls.VersionTLS12 {
					t.Error("expected HTTP/1.1 over TLS 1.2, even when the server offers HTTP/2 and TLS 1.3")
				}
				if r.Header.Get("Authorization") != "" || r.UserAgent() == "" {
					t.Error("expected user agent and no authorization header")
				}
				w.Header().Set("Content-Type", "application/pkix-cert")
				if _, err := w.Write(cert.Leaf.Raw); err != nil {
					t.Error(err)
				}
			}))
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: clientAuth}
			server.StartTLS()
			defer server.Close()
			c, transport := testClient(t, server.URL)
			trustCertificate(transport, cert.Leaf)

			// Repeat to exercise the reusable transport as well as parsing.
			for range 2 {
				info, err := c.GetRootCaCertificate(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				assertCertificate(t, info, cert.Leaf)
			}
		})
	}
}

func TestGetRootCaCertificateRejectsInvalidServerCertificate(t *testing.T) {
	for _, name := range []string{"untrusted", "wrong hostname", "expired"} {
		t.Run(name, func(t *testing.T) {
			cert := testCertificate(t)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("request must not reach the handler when TLS verification fails")
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			server.StartTLS()
			defer server.Close()
			c, transport := testClient(t, server.URL)
			switch name {
			case "untrusted":
				transport.TLSClientConfig.RootCAs = x509.NewCertPool()
			case "wrong hostname":
				trustCertificate(transport, cert.Leaf)
				transport.TLSClientConfig.ServerName = "wrong.example"
			case "expired":
				trustCertificate(transport, cert.Leaf)
				transport.TLSClientConfig.Time = func() time.Time { return cert.Leaf.NotAfter.Add(time.Hour) }
			}
			info, err := c.GetRootCaCertificate(t.Context())
			var verificationError *tls.CertificateVerificationError
			if info != nil || !errors.As(err, &verificationError) {
				t.Fatalf("expected a preserved TLS verification error and no certificate, got %v", err)
			}
		})
	}
}

func TestGetRootCaCertificateRequiresClientCertificate(t *testing.T) {
	cert := testCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a server requiring mTLS must not accept the unauthenticated request")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	c, transport := testClient(t, server.URL)
	trustCertificate(transport, cert.Leaf)
	// Keep the SDK's retry budget to one attempt for this permanent TLS failure.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	info, err := c.GetRootCaCertificate(ctx)
	// The CA transport uses TLS 1.2: Go sends handshake_failure when the
	// client omits a required certificate. certificate_required is TLS 1.3 only.
	if info != nil || err == nil || !strings.Contains(err.Error(), "does not supply a TLS client certificate") || !strings.Contains(err.Error(), "handshake failure") {
		t.Fatalf("expected an actionable client-certificate error preserving the TLS failure, got %v", err)
	}
}

func TestGetRootCaCertificateForbidden(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "client certificate required", http.StatusForbidden)
	}))
	defer server.Close()
	c, transport := testClient(t, server.URL)
	trustCertificate(transport, server.Certificate())
	info, err := c.GetRootCaCertificate(t.Context())
	if info != nil || err == nil || !strings.Contains(err.Error(), "403") ||
		!strings.Contains(err.Error(), "client certificate required") || !strings.Contains(err.Error(), "does not supply a TLS client certificate") {
		t.Fatalf("expected HTTP status, server explanation, and client-certificate hint, got %v", err)
	}
}

func TestGetRootCaCertificateRejectsInvalidDER(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("not a DER certificate")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	c, transport := testClient(t, server.URL)
	trustCertificate(transport, server.Certificate())
	info, err := c.GetRootCaCertificate(t.Context())
	if info != nil || err == nil || !strings.Contains(err.Error(), "parsing certificate") {
		t.Fatalf("expected certificate parsing failure, got %v", err)
	}
}

func testClient(t *testing.T, endpoint string) (*Client, *http.Transport) {
	t.Helper()
	c, err := NewClient(environments.NewApiEndpoint("scepman", endpoint, nil))
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected a dedicated HTTP transport, got %T", c.Transport)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return c, transport
}

func trustCertificate(transport *http.Transport, cert *x509.Certificate) {
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(cert)
}

func assertCertificate(t *testing.T, info *types.CertificateInfo, want *x509.Certificate) {
	t.Helper()
	if info == nil || info.Certificate == nil || info.CertificatePem == nil {
		t.Fatal("missing parsed certificate")
	}
	if !bytes.Equal(info.CertificateDer, want.Raw) || !info.Certificate.Equal(want) ||
		info.CertificatePem.Type != "CERTIFICATE" || !bytes.Equal(info.CertificatePem.Bytes, want.Raw) {
		t.Fatal("DER, PEM, or parsed certificate differs from the response")
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SCEPman test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
