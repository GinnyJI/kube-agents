package k8sapiproxy

import (
	"context"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	metricsNamespace = "kubeagents"
	metricsSubsystem = "k8s_api_proxy"

	labelVerb        = "verb"
	labelResource    = "resource"
	labelSubresource = "subresource"
	labelOutcome     = "outcome"
	labelReason      = "reason"
	labelCode        = "code"

	// metricsLabelNone is a label the request did not get far enough to have, such as the
	// verb of an unauthenticated request.
	metricsLabelNone = "none"
	// metricsLabelOther is a value outside the label's known set. Verbs, resources and
	// subresources come from the caller's path, so an unknown value is folded here to keep
	// the series bounded.
	metricsLabelOther = "other"

	statusClassDivisor = 100
	statusClassSuffix  = "xx"

	// metricsMaxScrapesInFlight bounds concurrent scrapes of the metrics handler.
	metricsMaxScrapesInFlight = 4
)

var (
	// durationBuckets cover a request from a cached discovery read to a slow list across a
	// large cluster, in seconds.
	durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

	knownVerbs = labelSet(
		"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection",
		"head", "post", "put", "options",
	)

	knownResources = labelSet(
		"bindings", "certificatesigningrequests", "clusterrolebindings", "clusterroles",
		"configmaps", "cronjobs", "customresourcedefinitions", "daemonsets", "deployments",
		"endpoints", "endpointslices", "events", "horizontalpodautoscalers", "ingresses", "jobs",
		"leases", "localsubjectaccessreviews", "namespaces", "networkpolicies", "nodes",
		"persistentvolumeclaims", "persistentvolumes", "poddisruptionbudgets", "pods",
		"replicasets", "replicationcontrollers", "resourcequotas", "rolebindings", "roles",
		"secrets", "selfsubjectaccessreviews", "selfsubjectreviews", "selfsubjectrulesreviews",
		"serviceaccounts", "services", "statefulsets", "storageclasses", "subjectaccessreviews",
		"tokenreviews",
	)

	knownSubresources = labelSet(
		"attach", "binding", "ephemeralcontainers", "eviction", "exec", "log", "portforward",
		"proxy", "scale", "status", "token",
	)

	knownOutcomes = labelSet(
		string(OutcomeForwarded), string(OutcomeUnauthenticated), string(OutcomeRefused),
		string(OutcomeUpstreamError), string(OutcomeAborted), string(OutcomeCanceled),
	)

	knownReasons = labelSet(
		string(ReasonInvalidRoute), string(ReasonInvalidMode), string(ReasonProtocolUpgradeBlocked),
		string(ReasonDiscoveryPathBlocked), string(ReasonAuthResourceBlocked),
		string(ReasonResourceBlocked), string(ReasonSecretSubresourceBlocked),
		string(ReasonSecretWriteBlocked), string(ReasonSubresourceBlocked),
		string(ReasonDryRunRequired), string(ReasonVerbBlocked),
	)
)

// Metrics counts the requests the handler finishes, from their AuditEvents, and the requests in
// flight. It is an AuditSink: pass it to the handler with MultiAuditSink beside the log sink,
// and wrap the handler with InFlight. Its registry holds only the proxy's collectors and the Go
// and process collectors.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
}

// NewMetrics returns Metrics with its own registry.
func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "requests_total",
			Help: "Requests the proxy finished, by verb, resource, subresource, outcome, " +
				"rejection reason and status class.",
		}, []string{labelVerb, labelResource, labelSubresource, labelOutcome, labelReason, labelCode}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "request_duration_seconds",
			Help: "How long the proxy took to finish a request, by verb, resource and outcome. " +
				"Watches and upgraded streams are left out: their duration is how long the " +
				"stream stayed open.",
			Buckets: durationBuckets,
		}, []string{labelVerb, labelResource, labelOutcome}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "requests_in_flight",
			Help:      "Requests the proxy is serving, open watches and upgraded streams included.",
		}),
	}
	m.registry.MustRegister(
		m.requests, m.duration, m.inFlight,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Record counts e. It implements AuditSink.
func (m *Metrics) Record(_ context.Context, e AuditEvent) {
	verb := boundedLabel(e.Verb, knownVerbs)
	resource := boundedLabel(e.Resource, knownResources)
	outcome := boundedLabel(string(e.Outcome), knownOutcomes)
	m.requests.WithLabelValues(
		verb, resource, boundedLabel(e.Subresource, knownSubresources), outcome,
		boundedLabel(string(e.Reason), knownReasons), statusClass(e.StatusCode),
	).Inc()
	if e.Verb != verbWatch && e.StatusCode != http.StatusSwitchingProtocols {
		m.duration.WithLabelValues(verb, resource, outcome).Observe(e.Duration.Seconds())
	}
}

// InFlight wraps next so that requests_in_flight counts the requests it is serving.
func (m *Metrics) InFlight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.inFlight.Inc()
		defer m.inFlight.Dec()
		next.ServeHTTP(w, r)
	})
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		MaxRequestsInFlight: metricsMaxScrapesInFlight,
	})
}

type multiAuditSink []AuditSink

// MultiAuditSink returns an AuditSink that records each event to every sink, in order.
func MultiAuditSink(sinks ...AuditSink) AuditSink {
	return multiAuditSink(sinks)
}

func (s multiAuditSink) Record(ctx context.Context, e AuditEvent) {
	for _, sink := range s {
		sink.Record(ctx, e)
	}
}

func labelSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

func boundedLabel(value string, known map[string]struct{}) string {
	if value == "" {
		return metricsLabelNone
	}
	if _, ok := known[value]; ok {
		return value
	}
	return metricsLabelOther
}

// statusClass is "2xx" and the like, or none when the handler never wrote a status.
func statusClass(code int) string {
	if code < minStatusCode || code > maxStatusCode {
		return metricsLabelNone
	}
	return strconv.Itoa(code/statusClassDivisor) + statusClassSuffix
}
