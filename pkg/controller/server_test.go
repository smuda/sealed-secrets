package controller

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	certUtil "k8s.io/client-go/util/cert"
)

type testCertStore struct {
	sync.Mutex
	cert *x509.Certificate
}

func (c *testCertStore) getCert() ([]*x509.Certificate, error) {
	c.Lock()
	defer c.Unlock()
	return []*x509.Certificate{c.cert}, nil
}

func (c *testCertStore) setCert(cert *x509.Certificate) {
	c.Lock()
	defer c.Unlock()
	c.cert = cert
}

func shutdownServer(server *http.Server, t *testing.T) {
	err := server.Shutdown(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestHttpCert(t *testing.T) {
	validFor := time.Hour
	cn := "my-cn"
	_, certBefore, err := generatePrivateKeyAndCert(2048, validFor, cn)
	if err != nil {
		t.Fatal(err)
	}

	_, certAfter, err := generatePrivateKeyAndCert(2048, validFor, cn)
	if err != nil {
		t.Fatal(err)
	}

	cs := &testCertStore{}
	server, mux := httpHealthServer()
	httpAddRoutes(mux, cs.getCert, nil, nil, 2, 2)
	defer shutdownServer(server, t)
	hp := *listenAddr
	if strings.HasPrefix(hp, ":") {
		hp = fmt.Sprintf("localhost%s", hp)
	}

	time.Sleep(1 * time.Second) // TODO(mkm) find a better way, e.g. retries

	// Verify the /healthz endpoint returns 200 with "ok\n"
	healthResp, err := http.Get(fmt.Sprintf("http://%s/healthz", hp))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := healthResp.StatusCode, http.StatusOK; got != want {
		t.Fatalf("healthz status: got %v, want %v", got, want)
	}
	healthBody, err := io.ReadAll(healthResp.Body)
	healthResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(healthBody), "ok\n"; got != want {
		t.Fatalf("healthz body: got %q, want %q", got, want)
	}

	check := func(cert *x509.Certificate) {
		resp, err := http.Get(fmt.Sprintf("http://%s/v1/cert.pem", hp))
		if err != nil {
			t.Fatal(err)
		}

		if got, want := resp.StatusCode, http.StatusOK; got != want {
			t.Fatalf("got: %v, want: %v", got, want)
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		certs, err := certUtil.ParseCertsPEM(b)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := len(certs), 1; got != want {
			t.Fatalf("got: %v, want: %v", got, want)
		}
		if got, want := certs[0], cert; !got.Equal(want) {
			t.Fatalf("got: %v, want: %v", got, want)
		}
	}

	cs.setCert(certBefore)
	check(certBefore)

	cs.setCert(certAfter)
	check(certAfter)
}
