package k8sapiproxy

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// Outcome says how the handler finished a request.
type Outcome string

const (
	// OutcomeForwarded is a request the upstream answered; StatusCode is its status.
	OutcomeForwarded Outcome = "forwarded"
	// OutcomeUnauthenticated is a request whose caller was not authenticated.
	OutcomeUnauthenticated Outcome = "unauthenticated"
	// OutcomeRefused is a request the route or the policy refused; Reason says why.
	OutcomeRefused Outcome = "refused"
	// OutcomeUpstreamError is a request the upstream transport failed to answer.
	OutcomeUpstreamError Outcome = "upstream_error"
	// OutcomeAborted is a response that stopped while it was being copied, because the
	// caller went away or the upstream failed mid-stream.
	OutcomeAborted Outcome = "aborted"
)

const (
	auditMessage = "kube-proxy request"

	auditKeyOutcome     = "outcome"
	auditKeyStatus      = "status_code"
	auditKeyMethod      = "http_method"
	auditKeyPath        = "path"
	auditKeyDurationMS  = "duration_ms"
	auditKeyCluster     = "cluster"
	auditKeyVerb        = "verb"
	auditKeyAPIGroup    = "api_group"
	auditKeyAPIVersion  = "api_version"
	auditKeyResource    = "resource"
	auditKeySubresource = "subresource"
	auditKeyNamespace   = "namespace"
	auditKeyName        = "name"
	auditKeyDryRun      = "dry_run"
	auditKeyReason      = "rejection_reason"
	auditKeyUsername    = "caller_username"
	auditKeyUID         = "caller_uid"
	auditKeyGroups      = "caller_groups"
	auditKeyUserAgent   = "user_agent"
	auditKeyError       = "error"
)

// AuditEvent describes one request the handler finished. It carries no request or response
// body and no credential.
type AuditEvent struct {
	Caller     *CallerIdentity
	ClusterID  string
	HTTPMethod string
	// Path is the API server path, without the /clusters/{id} prefix once the route is parsed,
	// and without the query.
	Path      string
	UserAgent string
	// Verb through Name are the API server's classification of the request, when it got that
	// far.
	Verb        string
	APIGroup    string
	APIVersion  string
	Resource    string
	Subresource string
	Namespace   string
	Name        string
	DryRun      bool
	Outcome     Outcome
	Reason      RejectionReason
	StatusCode  int
	// Duration runs to the end of the response, so for a watch or an upgraded stream it is
	// how long the stream stayed open.
	Duration time.Duration
	// Err is why authentication or the upstream failed. It can name the upstream endpoint, so
	// it goes to the operator's log and never to the caller.
	Err error
}

// AuditSink receives an AuditEvent for every request the handler finishes. It is called on
// the request's goroutine, so it must be safe for concurrent use and should not block.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent)
}

type slogAuditSink struct {
	logger *slog.Logger
}

// NewSlogAuditSink returns an AuditSink that writes each event as one record to logger:
// refusals at warn, upstream errors and aborted responses at error, the rest at info.
func NewSlogAuditSink(logger *slog.Logger) AuditSink {
	if logger == nil {
		logger = slog.Default()
	}
	return slogAuditSink{logger: logger}
}

func (s slogAuditSink) Record(ctx context.Context, e AuditEvent) {
	attrs := []slog.Attr{
		slog.String(auditKeyOutcome, string(e.Outcome)),
		slog.Int(auditKeyStatus, e.StatusCode),
		slog.String(auditKeyMethod, e.HTTPMethod),
		slog.String(auditKeyPath, e.Path),
		slog.Float64(auditKeyDurationMS, float64(e.Duration)/float64(time.Millisecond)),
	}
	optional := []struct{ key, value string }{
		{auditKeyCluster, e.ClusterID},
		{auditKeyVerb, e.Verb},
		{auditKeyAPIGroup, e.APIGroup},
		{auditKeyAPIVersion, e.APIVersion},
		{auditKeyResource, e.Resource},
		{auditKeySubresource, e.Subresource},
		{auditKeyNamespace, e.Namespace},
		{auditKeyName, e.Name},
		{auditKeyReason, string(e.Reason)},
		{auditKeyUserAgent, e.UserAgent},
	}
	for _, o := range optional {
		if o.value != "" {
			attrs = append(attrs, slog.String(o.key, o.value))
		}
	}
	if e.DryRun {
		attrs = append(attrs, slog.Bool(auditKeyDryRun, true))
	}
	if e.Caller != nil {
		attrs = append(attrs, slog.String(auditKeyUsername, e.Caller.Username))
		if e.Caller.UID != "" {
			attrs = append(attrs, slog.String(auditKeyUID, e.Caller.UID))
		}
		if len(e.Caller.Groups) > 0 {
			attrs = append(attrs, slog.Any(auditKeyGroups, e.Caller.Groups))
		}
	}
	if e.Err != nil {
		attrs = append(attrs, slog.String(auditKeyError, e.Err.Error()))
	}
	s.logger.LogAttrs(ctx, auditLevel(e.Outcome), auditMessage, attrs...)
}

func auditLevel(o Outcome) slog.Level {
	switch o {
	case OutcomeUnauthenticated, OutcomeRefused:
		return slog.LevelWarn
	case OutcomeUpstreamError, OutcomeAborted:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// statusRecorder keeps the status the handler or the upstream answered with. Unwrap lets
// http.ResponseController, which the reverse proxy flushes and hijacks through, reach the
// underlying writer.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	// An interim 1xx, which the reverse proxy relays, is not the answer; 101 is, since the
	// connection is handed over after it.
	if s.code == 0 && (code >= http.StatusOK || code == http.StatusSwitchingProtocols) {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}
