package k8sapiproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/endpoints/request"
)

const (
	authFailedMessage   = messagePrefix + "caller authentication failed"
	unclassifiedMessage = messagePrefix + "the request path could not be classified"
	upstreamFailed      = "kube-proxy could not reach cluster %q: %v"

	// flushImmediately streams each upstream write to the caller, which watch and log
	// follow need.
	flushImmediately = -1
)

// Config configures NewHandler.
type Config struct {
	// Authenticator identifies the caller. Required.
	Authenticator CallerAuthenticator
	// Upstream forwards an admitted request to its cluster. Required.
	Upstream UpstreamTransport
	// DefaultClusterID is the cluster a path without a /clusters/{id} prefix targets;
	// InClusterID when empty.
	DefaultClusterID string
	// Policy decides which requests are forwarded. Its Mode must be set.
	Policy Policy
}

type clusterIDKey struct{}

type handler struct {
	authenticator    CallerAuthenticator
	defaultClusterID string
	policy           Policy
	factory          *request.RequestInfoFactory
	proxy            *httputil.ReverseProxy
}

// NewHandler returns the proxy's HTTP handler. Each request is authenticated, routed to a
// cluster by SplitClusterPath, classified, evaluated by cfg.Policy, stripped of the caller's
// credentials and identity headers, and forwarded through cfg.Upstream. Every refusal is a
// metav1.Status.
func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.Authenticator == nil {
		return nil, errors.New("k8sapiproxy: Config.Authenticator is required")
	}
	if cfg.Upstream == nil {
		return nil, errors.New("k8sapiproxy: Config.Upstream is required")
	}
	switch cfg.Policy.Mode {
	case ModeReadOnly, ModeReadOnlyWithDryRun, ModeReadWrite:
	default:
		return nil, fmt.Errorf("k8sapiproxy: invalid Config.Policy.Mode %q", cfg.Policy.Mode)
	}
	if cfg.DefaultClusterID != "" && !validClusterID.MatchString(cfg.DefaultClusterID) {
		return nil, fmt.Errorf("k8sapiproxy: invalid Config.DefaultClusterID %q", cfg.DefaultClusterID)
	}

	upstream := cfg.Upstream
	return &handler{
		authenticator:    cfg.Authenticator,
		defaultClusterID: cfg.DefaultClusterID,
		policy:           cfg.Policy,
		factory:          NewRequestInfoFactory(),
		proxy: &httputil.ReverseProxy{
			// Rewrite rather than Director: the reverse proxy then also drops the caller's
			// Forwarded and X-Forwarded-* headers.
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.Host = ""
			},
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				clusterID, _ := req.Context().Value(clusterIDKey{}).(string)
				return upstream.RoundTripCluster(req.Context(), clusterID, req)
			}),
			FlushInterval: flushImmediately,
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				clusterID, _ := req.Context().Value(clusterIDKey{}).(string)
				writeStatus(w, http.StatusBadGateway, metav1.StatusReasonInternalError,
					fmt.Sprintf(upstreamFailed, clusterID, err))
			},
		},
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if caller, err := h.authenticator.AuthenticateRequest(r); err != nil || caller == nil {
		msg := authFailedMessage
		if err != nil {
			msg += ": " + err.Error()
		}
		writeStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized, msg)
		return
	}

	clusterID, apiPath, perr := SplitClusterPath(r.URL, h.defaultClusterID)
	if perr != nil {
		writePolicyError(w, perr)
		return
	}

	out := r.Clone(r.Context())
	out.URL.Path = apiPath
	out.URL.RawPath = ""

	info, err := h.factory.NewRequestInfo(out)
	if err != nil {
		writeStatus(w, http.StatusBadRequest, metav1.StatusReasonBadRequest, unclassifiedMessage)
		return
	}
	if perr := h.policy.Evaluate(out, info); perr != nil {
		writePolicyError(w, perr)
		return
	}

	sanitizeRequestHeaders(out.Header, h.policy.permitsUpgrade(info))
	out = out.WithContext(context.WithValue(out.Context(), clusterIDKey{}, clusterID))
	h.proxy.ServeHTTP(w, out)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
