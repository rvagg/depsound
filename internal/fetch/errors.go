package fetch

import (
	"fmt"
	"net/http"
)

// Acquisition-failure kinds. The distinction matters: an ABSENT
// artifact (a takedown, or never-published) is a fact worth preserving for a
// forensic/advisory fallback; a DENIED one is actionable (auth/policy); a
// TRANSIENT one is retryable. Collapsing them into one opaque error loses all
// of that.
const (
	Absent    = "absent"    // 404 / 410: the bytes are gone (or never existed)
	Denied    = "denied"    // 401 / 403: authentication or policy
	Transient = "transient" // 5xx, rate limits, and anything else retryable
)

// HTTPError is a classified acquisition failure carrying the exact requested
// URL and status, so a downstream fact/degradation can distinguish absent from
// denied from transient rather than seeing one stringified error.
type HTTPError struct {
	URL    string
	Status int
	Hint   string // optional extra context, e.g. "set GITHUB_TOKEN"
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("GET %s: %d %s", e.URL, e.Status, http.StatusText(e.Status))
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

// Kind classifies the failure for the signal ledger.
func (e *HTTPError) Kind() string {
	switch e.Status {
	case http.StatusNotFound, http.StatusGone:
		return Absent
	case http.StatusUnauthorized, http.StatusForbidden:
		return Denied
	default:
		return Transient
	}
}

// statusErr builds an *HTTPError for a non-success response.
func statusErr(u string, status int, hint string) *HTTPError {
	return &HTTPError{URL: u, Status: status, Hint: hint}
}
