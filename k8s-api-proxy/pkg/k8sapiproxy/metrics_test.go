package k8sapiproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func requestCount(m *Metrics, verb, resource, subresource, outcome, reason, code string) float64 {
	return testutil.ToFloat64(m.requests.WithLabelValues(verb, resource, subresource, outcome, reason, code))
}

func TestMetricsRecordLabels(t *testing.T) {
	for _, tc := range []struct {
		name                                             string
		event                                            AuditEvent
		verb, resource, subresource, outcome, reason, cd string
	}{
		{
			name:  "forwarded list",
			event: AuditEvent{Verb: "list", Resource: "pods", Outcome: OutcomeForwarded, StatusCode: http.StatusOK},
			verb:  "list", resource: "pods", subresource: "none", outcome: "forwarded", reason: "none", cd: "2xx",
		},
		{
			name: "refused Secret patch",
			event: AuditEvent{Verb: "patch", Resource: "secrets", Outcome: OutcomeRefused,
				Reason: ReasonSecretWriteBlocked, StatusCode: http.StatusForbidden},
			verb: "patch", resource: "secrets", subresource: "none", outcome: "refused",
			reason: "secret_write_blocked", cd: "4xx",
		},
		{
			name:  "unauthenticated, never classified",
			event: AuditEvent{Outcome: OutcomeUnauthenticated, StatusCode: http.StatusUnauthorized},
			verb:  "none", resource: "none", subresource: "none", outcome: "unauthenticated", reason: "none", cd: "4xx",
		},
		{
			name: "caller-chosen names fold to other",
			event: AuditEvent{Verb: "frobnicate", Resource: "widgets", Subresource: "knobs",
				Outcome: "made-up", Reason: "made-up", StatusCode: http.StatusOK},
			verb: "other", resource: "other", subresource: "other", outcome: "other", reason: "other", cd: "2xx",
		},
		{
			name:  "canceled before a status",
			event: AuditEvent{Verb: "get", Resource: "pods", Subresource: "log", Outcome: OutcomeCanceled},
			verb:  "get", resource: "pods", subresource: "log", outcome: "canceled", reason: "none", cd: "none",
		},
		{
			name:  "upgrade",
			event: AuditEvent{Verb: "create", Resource: "pods", Subresource: "exec", Outcome: OutcomeForwarded, StatusCode: http.StatusSwitchingProtocols},
			verb:  "create", resource: "pods", subresource: "exec", outcome: "forwarded", reason: "none", cd: "1xx",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMetrics()
			m.Record(context.Background(), tc.event)
			if got := requestCount(m, tc.verb, tc.resource, tc.subresource, tc.outcome, tc.reason, tc.cd); got != 1 {
				t.Errorf("requests_total{%s,%s,%s,%s,%s,%s} = %v, want 1", tc.verb, tc.resource, tc.subresource, tc.outcome, tc.reason, tc.cd, got)
			}
			if n := testutil.CollectAndCount(m.requests); n != 1 {
				t.Errorf("requests_total has %d series, want 1", n)
			}
		})
	}
}

func TestMetricsDurationLeavesOutStreams(t *testing.T) {
	m := NewMetrics()
	ctx := context.Background()
	m.Record(ctx, AuditEvent{Verb: "list", Resource: "pods", Outcome: OutcomeForwarded, StatusCode: http.StatusOK, Duration: 20 * time.Millisecond})
	m.Record(ctx, AuditEvent{Verb: "watch", Resource: "pods", Outcome: OutcomeForwarded, StatusCode: http.StatusOK, Duration: time.Hour})
	m.Record(ctx, AuditEvent{Verb: "create", Resource: "pods", Subresource: "exec", Outcome: OutcomeForwarded,
		StatusCode: http.StatusSwitchingProtocols, Duration: time.Hour})

	if n := testutil.CollectAndCount(m.duration); n != 1 {
		t.Fatalf("request_duration_seconds has %d series, want 1 (the list only)", n)
	}
	if n := testutil.CollectAndCount(m.requests); n != 3 {
		t.Errorf("requests_total has %d series, want 3: streams are still counted", n)
	}
}

func TestMetricsInFlight(t *testing.T) {
	m := NewMetrics()
	inside := make(chan float64, 1)
	h := m.InFlight(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		inside <- testutil.ToFloat64(m.inFlight)
	}))
	serve(h, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))
	if got := <-inside; got != 1 {
		t.Errorf("requests_in_flight during the request = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.inFlight); got != 0 {
		t.Errorf("requests_in_flight after the request = %v, want 0", got)
	}
}

func TestMultiAuditSink(t *testing.T) {
	a, b := &recordingSink{}, &recordingSink{}
	MultiAuditSink(a, b).Record(context.Background(), AuditEvent{Path: "/api"})
	if a.only(t).Path != "/api" || b.only(t).Path != "/api" {
		t.Errorf("events = %+v, %+v; want the event in both sinks", a.events, b.events)
	}
}

// TestHandlerMetrics runs requests through a handler wired as the binary will wire it and
// reads them back from the exposition format.
func TestHandlerMetrics(t *testing.T) {
	m := NewMetrics()
	h, _ := newTestHandler(t, Config{Audit: MultiAuditSink(NewSlogAuditSink(slog.New(slog.DiscardHandler)), m)})
	h = m.InFlight(h)
	serve(h, httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil))
	serve(h, httptest.NewRequest(http.MethodDelete, "/api/v1/namespaces/default/pods/p", nil))

	denied, _ := newTestHandler(t, Config{Audit: m, Authenticator: staticAuthenticator{err: errors.New("bad token")}})
	serve(denied, httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil))

	rec := serve(m.Handler(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{
		`kubeagents_k8s_api_proxy_requests_total{code="2xx",outcome="forwarded",reason="none",resource="pods",subresource="none",verb="list"} 1`,
		`kubeagents_k8s_api_proxy_requests_total{code="4xx",outcome="refused",reason="verb_blocked",resource="pods",subresource="none",verb="delete"} 1`,
		`kubeagents_k8s_api_proxy_requests_total{code="4xx",outcome="unauthenticated",reason="none",resource="none",subresource="none",verb="none"} 1`,
		`kubeagents_k8s_api_proxy_request_duration_seconds_count{outcome="forwarded",resource="pods",verb="list"} 1`,
		`kubeagents_k8s_api_proxy_requests_in_flight 0`,
		`go_goroutines`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics output lacks %q", want)
		}
	}
}

func TestStatusClass(t *testing.T) {
	for code, want := range map[int]string{0: "none", 99: "none", 101: "1xx", 200: "2xx", 304: "3xx", 503: "5xx", 599: "5xx", 600: "none"} {
		if got := statusClass(code); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", code, got, want)
		}
	}
}
