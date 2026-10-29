package k8sapiproxy

import (
	"net/http"
	"strings"
)

const (
	headerUpgrade     = "Upgrade"
	headerConnection  = "Connection"
	upgradeToken      = "upgrade"
	connectionUpgrade = "Upgrade"
)

// credentialHeaders carry the caller's own credentials, which never reach the API server.
var credentialHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie"}

// identityHeaderPrefixes start the headers an API server reads as the requesting identity:
// impersonation, and the X-Remote-* headers of an authenticating front proxy.
var identityHeaderPrefixes = []string{"impersonate-", "x-remote-"}

// HasUpgradeHeader reports whether r asks for a protocol upgrade (SPDY or WebSocket), through
// either an Upgrade header or an `upgrade` token in Connection.
func HasUpgradeHeader(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get(headerUpgrade)) != "" {
		return true
	}
	for _, v := range r.Header.Values(headerConnection) {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), upgradeToken) {
				return true
			}
		}
	}
	return false
}

// sanitizeRequestHeaders removes from h what must not reach the API server: the caller's
// credentials, identity headers, the headers the caller named in Connection, Connection
// itself, and Upgrade unless preserveUpgrade. It runs before the handler sets any header of
// its own: the reverse proxy drops every header Connection names, so a caller listing one
// the handler sets could otherwise make it disappear.
func sanitizeRequestHeaders(h http.Header, preserveUpgrade bool) {
	for _, v := range h.Values(headerConnection) {
		for _, token := range strings.Split(v, ",") {
			name := strings.TrimSpace(token)
			if name == "" || (preserveUpgrade && strings.EqualFold(name, upgradeToken)) {
				continue
			}
			h.Del(name)
		}
	}
	h.Del(headerConnection)
	for _, name := range credentialHeaders {
		h.Del(name)
	}
	for key := range h {
		lower := strings.ToLower(key)
		for _, prefix := range identityHeaderPrefixes {
			if strings.HasPrefix(lower, prefix) {
				delete(h, key)
				break
			}
		}
	}
	if preserveUpgrade && strings.TrimSpace(h.Get(headerUpgrade)) != "" {
		h.Set(headerConnection, connectionUpgrade)
	} else {
		h.Del(headerUpgrade)
	}
}
