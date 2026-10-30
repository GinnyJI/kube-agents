package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"k8s.io/client-go/rest"

	"github.com/gke-labs/kube-agents/k8s-api-proxy/pkg/k8sapiproxy"
)

const (
	testClusterID = "gke_proj_us-central1_c1"
	testToken     = "google-token"
	testSAToken   = "in-cluster-token"
)

// fakeAPIServer is a TLS API server that records each request's Authorization header and URL.
type fakeAPIServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newFakeAPIServer(t *testing.T, handler http.HandlerFunc) *fakeAPIServer {
	t.Helper()
	s := &fakeAPIServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Header.Get("Authorization")+" "+r.URL.RequestURI())
		s.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *fakeAPIServer) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
}

// selfSignedCAPEM returns a CA certificate that signed none of the test servers' certificates.
// Every httptest TLS server shares one certificate, so another server's would not do.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "other-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (s *fakeAPIServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// fakeContainerAPI describes every cluster as desc returns it and counts the calls.
type fakeContainerAPI struct {
	*httptest.Server
	calls atomic.Int32
}

func newFakeContainerAPI(t *testing.T, status int, desc func() clusterDescription) *fakeContainerAPI {
	t.Helper()
	f := &fakeContainerAPI{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v1/projects/proj/locations/us-central1/clusters/c1" {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "failed", status)
			return
		}
		_ = json.NewEncoder(w).Encode(desc())
	}))
	t.Cleanup(f.Close)
	return f
}

func ipEndpoint(s *fakeAPIServer) func() clusterDescription {
	return func() clusterDescription {
		var d clusterDescription
		d.Endpoint = strings.TrimPrefix(s.URL, "https://")
		d.MasterAuth.ClusterCACertificate = base64.StdEncoding.EncodeToString(s.caPEM())
		return d
	}
}

func newTestTransport(t *testing.T, inCluster, gke *fakeAPIServer, api *fakeContainerAPI, mutate func(*Config)) *Transport {
	t.Helper()
	cfg := Config{
		InCluster: &rest.Config{
			Host:            inCluster.URL,
			BearerToken:     testSAToken,
			TLSClientConfig: rest.TLSClientConfig{CAData: inCluster.caPEM()},
		},
		TokenSource:     oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testToken}),
		ContainerAPIURL: api.URL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	tr, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if gke != nil {
		tr.dnsCAData = gke.caPEM()
	}
	return tr
}

func roundTrip(t *testing.T, tr *Transport, clusterID, path string) (*http.Response, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RequestURI = ""
	req.URL.Scheme, req.URL.Host, req.Host = "", "", ""
	resp, err := tr.RoundTripCluster(context.Background(), clusterID, req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return resp, err
}

func TestRoundTripGKEClusterByIPEndpoint(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, nil)
	api := newFakeContainerAPI(t, http.StatusOK, ipEndpoint(gke))
	tr := newTestTransport(t, inCluster, nil, api, nil)

	for range 2 {
		resp, err := roundTrip(t, tr, testClusterID, "/api/v1/namespaces/default/pods?limit=5")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("RoundTripCluster = %v, %v", resp, err)
		}
	}
	want := "Bearer " + testToken + " /api/v1/namespaces/default/pods?limit=5"
	if got := gke.requests(); len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("GKE API server saw %q, want %q twice", got, want)
	}
	if n := api.calls.Load(); n != 1 {
		t.Errorf("Container API calls = %d, want 1: the endpoint is cached", n)
	}
	if got := inCluster.requests(); len(got) != 0 {
		t.Errorf("in-cluster API server saw %q, want nothing", got)
	}
}

func TestRoundTripGKEClusterByDNSEndpoint(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, nil)
	yes := true
	api := newFakeContainerAPI(t, http.StatusOK, func() clusterDescription {
		var d clusterDescription
		// The IP endpoint is unreachable and has no CA; rule 1 must not use it.
		d.Endpoint = "192.0.2.1"
		d.ControlPlaneEndpointsConfig.DNSEndpointConfig.Endpoint = strings.TrimPrefix(gke.URL, "https://")
		d.ControlPlaneEndpointsConfig.DNSEndpointConfig.AllowExternalTraffic = &yes
		return d
	})
	tr := newTestTransport(t, inCluster, gke, api, nil)

	if resp, err := roundTrip(t, tr, testClusterID, "/version"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("RoundTripCluster = %v, %v", resp, err)
	}
	if got := gke.requests(); len(got) != 1 || got[0] != "Bearer "+testToken+" /version" {
		t.Errorf("GKE API server saw %q", got)
	}
}

func TestRoundTripInCluster(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	api := newFakeContainerAPI(t, http.StatusOK, nil)
	tr := newTestTransport(t, inCluster, nil, api, func(c *Config) { c.HostClusterID = testClusterID })

	for _, id := range []string{k8sapiproxy.InClusterID, testClusterID} {
		if resp, err := roundTrip(t, tr, id, "/api"); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("RoundTripCluster(%q) = %v, %v", id, resp, err)
		}
	}
	want := "Bearer " + testSAToken + " /api"
	if got := inCluster.requests(); len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("in-cluster API server saw %q, want %q twice", got, want)
	}
	if n := api.calls.Load(); n != 0 {
		t.Errorf("Container API calls = %d, want 0", n)
	}
}

func TestRoundTripRefusesKindCluster(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	api := newFakeContainerAPI(t, http.StatusOK, nil)
	tr := newTestTransport(t, inCluster, nil, api, nil)

	if _, err := roundTrip(t, tr, "kind-dev", "/api"); err == nil {
		t.Fatal("RoundTripCluster(kind-dev) succeeded")
	}
	if got := inCluster.requests(); len(got) != 0 {
		t.Errorf("in-cluster API server saw %q: a kind cluster must not fall back to it", got)
	}
}

func TestRoundTripCachesDiscoveryFailure(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	api := newFakeContainerAPI(t, http.StatusForbidden, nil)
	tr := newTestTransport(t, inCluster, nil, api, nil)

	for range 3 {
		if _, err := roundTrip(t, tr, testClusterID, "/api"); err == nil {
			t.Fatal("RoundTripCluster succeeded with a failing Container API")
		}
	}
	if n := api.calls.Load(); n != 1 {
		t.Errorf("Container API calls = %d, want 1: the failure is cached", n)
	}
}

func TestRoundTripSharesConcurrentDiscovery(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, nil)
	release := make(chan struct{})
	describe := ipEndpoint(gke)
	api := newFakeContainerAPI(t, http.StatusOK, func() clusterDescription {
		<-release
		return describe()
	})
	tr := newTestTransport(t, inCluster, nil, api, nil)

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			if _, err := roundTrip(t, tr, testClusterID, "/api"); err != nil {
				errs <- err
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("RoundTripCluster: %v", err)
	}
	if n := api.calls.Load(); n != 1 {
		t.Errorf("Container API calls = %d, want 1", n)
	}
}

func TestRoundTripRediscoversAfterTransportError(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, nil)
	api := newFakeContainerAPI(t, http.StatusOK, ipEndpoint(gke))
	tr := newTestTransport(t, inCluster, nil, api, nil)

	if _, err := roundTrip(t, tr, testClusterID, "/api"); err != nil {
		t.Fatalf("RoundTripCluster: %v", err)
	}
	gke.Close()
	if _, err := roundTrip(t, tr, testClusterID, "/api"); err == nil {
		t.Fatal("RoundTripCluster succeeded against a closed API server")
	}
	if _, err := roundTrip(t, tr, testClusterID, "/api"); err == nil {
		t.Fatal("RoundTripCluster succeeded against a closed API server")
	}
	if n := api.calls.Load(); n != 2 {
		t.Errorf("Container API calls = %d, want 2: a transport error drops the cached endpoint", n)
	}
}

func TestRoundTripRefusesRedirect(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/api", http.StatusFound)
	})
	api := newFakeContainerAPI(t, http.StatusOK, ipEndpoint(gke))
	tr := newTestTransport(t, inCluster, nil, api, nil)

	if resp, err := roundTrip(t, tr, testClusterID, "/api"); err == nil {
		t.Fatalf("RoundTripCluster relayed a %d", resp.StatusCode)
	}
}

func TestRoundTripRefusesPlainHTTPEndpoint(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	yes := true
	api := newFakeContainerAPI(t, http.StatusOK, func() clusterDescription {
		var d clusterDescription
		d.ControlPlaneEndpointsConfig.DNSEndpointConfig.Endpoint = "http://gke-x.goog"
		d.ControlPlaneEndpointsConfig.DNSEndpointConfig.AllowExternalTraffic = &yes
		return d
	})
	tr := newTestTransport(t, inCluster, nil, api, nil)

	if _, err := roundTrip(t, tr, testClusterID, "/api"); err == nil {
		t.Fatal("RoundTripCluster used an http:// endpoint")
	}
}

func TestRoundTripRejectsUntrustedCertificate(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, nil)
	api := newFakeContainerAPI(t, http.StatusOK, func() clusterDescription {
		d := ipEndpoint(gke)()
		d.MasterAuth.ClusterCACertificate = base64.StdEncoding.EncodeToString(selfSignedCAPEM(t))
		return d
	})
	tr := newTestTransport(t, inCluster, nil, api, nil)

	if _, err := roundTrip(t, tr, testClusterID, "/api"); err == nil {
		t.Fatal("RoundTripCluster trusted a certificate the cluster CA did not sign")
	}
	if got := gke.requests(); len(got) != 0 {
		t.Errorf("GKE API server saw %q", got)
	}
}

func TestRoundTripUpgradeBodyIsReadWriteCloser(t *testing.T) {
	inCluster := newFakeAPIServer(t, nil)
	gke := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n')
		_, _ = rw.WriteString("echo " + line)
		_ = rw.Flush()
	})
	api := newFakeContainerAPI(t, http.StatusOK, ipEndpoint(gke))
	tr := newTestTransport(t, inCluster, nil, api, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces/default/pods/p/exec", nil)
	req.RequestURI = ""
	req.URL.Scheme, req.URL.Host, req.Host = "", "", ""
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "SPDY/3.1")
	resp, err := tr.RoundTripCluster(context.Background(), testClusterID, req)
	if err != nil {
		t.Fatalf("RoundTripCluster: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	stream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("101 body is %T, not an io.ReadWriteCloser", resp.Body)
	}
	if _, err := io.WriteString(stream, "hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("echo hello\n"))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != "echo hello\n" {
		t.Errorf("read %q, %v", got, err)
	}
}
