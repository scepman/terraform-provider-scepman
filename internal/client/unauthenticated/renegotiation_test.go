package unauthenticated

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scepman/terraform-provider-scepman/internal/types"
)

// Go's TLS server cannot initiate renegotiation. OpenSSL's interactive R command
// requests a client certificate after the HTTP request, like OptionalInteractiveUser.
// All certificates are generated locally; no deployment or credentials are needed.
func TestGetRootCaCertificateRenegotiation(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("install OpenSSL to run the TLS renegotiation regression test")
	}
	version, err := exec.CommandContext(t.Context(), openssl, "version").Output()
	if err != nil {
		t.Fatalf("checking OpenSSL version: %v", err)
	}
	// The interactive stdin fixture is validated with OpenSSL 3.x. In
	// particular, the native Windows OpenSSL 4 server can stall with piped stdin.
	if !strings.HasPrefix(string(version), "OpenSSL 3.") {
		t.Skipf("TLS renegotiation fixture requires OpenSSL 3.x on PATH; found %s", strings.TrimSpace(string(version)))
	}
	for _, tc := range []struct {
		name               string
		disableRenegotiate bool
		renegotiations     int
		wantError          bool
	}{
		{name: "disabled reproduces issue 62", disableRenegotiate: true, renegotiations: 1, wantError: true},
		{name: "optional client certificate", renegotiations: 1},
		{name: "second renegotiation rejected", renegotiations: 2, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := testCertificate(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			address, stdin, output := startOpenSSL(t, ctx, openssl, cert)
			c, transport := testClient(t, "https://"+address)
			trustCertificate(transport, cert.Leaf)
			if tc.disableRenegotiate {
				transport.TLSClientConfig.Renegotiation = tls.RenegotiateNever
			}
			var certificateRequests atomic.Int32
			transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				certificateRequests.Add(1)
				// Match the unauthenticated client's default response: no certificate.
				return &tls.Certificate{}, nil
			}

			// ACCEPT can be printed before the listening socket is ready. Establish
			// the test's only TCP connection first, without probing and consuming it.
			conn := connectOpenSSL(t, ctx, address)
			t.Cleanup(func() { _ = conn.Close() })
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return conn, nil }
			// A budget below three seconds gives the SDK zero retries, so the
			// negative controls report the original TLS error, not a retry failure.
			requestCtx, requestCancel := context.WithTimeout(ctx, 2*time.Second)
			defer requestCancel()
			type result struct {
				info *types.CertificateInfo
				err  error
			}
			results := make(chan result, 1)
			go func() {
				info, err := c.GetRootCaCertificate(requestCtx)
				results <- result{info, err}
			}()

			output.wait(t, ctx, "handshake")
			output.wait(t, ctx, "request")
			if got := certificateRequests.Load(); got != 0 {
				t.Fatalf("initial handshake requested a client certificate %d times; want none before renegotiation", got)
			}
			for i := 0; i < tc.renegotiations; i++ {
				if _, err := io.WriteString(stdin, "R\n"); err != nil {
					t.Fatal(err)
				}
				if tc.wantError && i == tc.renegotiations-1 {
					break
				}
				// Do not interleave response data with the TLS handshake.
				output.wait(t, ctx, "handshake")
				if got := certificateRequests.Load(); got != int32(i+1) {
					t.Fatalf("client certificate requests after renegotiation = %d, want %d", got, i+1)
				}
			}
			if !tc.wantError {
				response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(cert.Leaf.Raw)))
				response = append(response, cert.Leaf.Raw...)
				if _, err := stdin.Write(response); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case got := <-results:
				if tc.wantError {
					// Go's handleRenegotiation sends the same no_renegotiation alert
					// for RenegotiateNever and an exhausted RenegotiateOnceAsClient.
					// Keep the exact error check so unrelated failures cannot pass.
					if got.info != nil || got.err == nil || !strings.Contains(got.err.Error(), "tls: no renegotiation") {
						t.Fatalf("expected tls: no renegotiation, got %v", got.err)
					}
				} else {
					if got.err != nil {
						t.Fatal(got.err)
					}
					assertCertificate(t, got.info, cert.Leaf)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for CA retrieval")
			}
		})
	}
}

func startOpenSSL(t *testing.T, ctx context.Context, openssl string, cert tls.Certificate) (string, io.WriteCloser, *opensslOutput) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Leaf.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	// Select an unused loopback port rather than a fixed port shared by test runs.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// Do not use -verify: that would request a certificate in the initial
	// handshake. Uppercase R enables optional client authentication later;
	// lowercase r would only renegotiate without requesting a certificate.
	// https://docs.openssl.org/3.0/man1/openssl-s_server/#connected-commands
	cmd := exec.CommandContext(ctx, openssl, "s_server", "-accept", address,
		"-cert", certPath, "-key", keyPath, "-tls1_2", "-state", "-no_ticket", "-naccept", "1")
	output := &opensslOutput{events: make(chan string, 16)}
	cmd.Stdout = output
	cmd.Stderr = output
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("OpenSSL output:\n%s", output.String())
		}
	})
	output.wait(t, ctx, "ready")
	return address, stdin, output
}

func connectOpenSSL(t *testing.T, ctx context.Context, address string) net.Conn {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err == nil {
			return conn
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("connecting to OpenSSL: %v", err)
		}
	}
}

type opensslOutput struct {
	mu        sync.Mutex
	all       bytes.Buffer
	partial   string
	inRequest bool
	events    chan string
}

func (o *opensslOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = o.all.Write(p)
	o.partial += string(p)
	for {
		line, rest, ok := strings.Cut(o.partial, "\n")
		if !ok {
			break
		}
		o.partial = rest
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ACCEPT"):
			o.events <- "ready"
		case line == "SSL_accept:SSLv3/TLS write finished":
			o.events <- "handshake"
		case line == "GET /ca HTTP/1.1":
			o.inRequest = true
		case line == "" && o.inRequest:
			o.inRequest = false
			o.events <- "request"
		}
	}
	return len(p), nil
}

func (o *opensslOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.all.String()
}

func (o *opensslOutput) wait(t *testing.T, ctx context.Context, want string) {
	t.Helper()
	select {
	case got := <-o.events:
		if got != want {
			t.Fatalf("OpenSSL event = %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for OpenSSL %s", want)
	}
}
