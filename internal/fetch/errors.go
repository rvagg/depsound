package fetch

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rvagg/depsound/internal/manifest"
)

// Acquisition-failure kinds. The distinction matters: an ABSENT artifact
// (missing registry metadata, a 404/410, a takedown, or never-published) is a
// fact worth preserving for a forensic/advisory fallback; a DENIED one is
// actionable (auth/policy); a TRANSIENT one is retryable. Collapsing them into
// one opaque error loses all of that.
const (
	Absent    = "absent"    // registry metadata missing, or URL returned 404/410
	Denied    = "denied"    // 401 / 403: authentication or policy
	Transient = "transient" // 5xx, rate limits, and anything else retryable
)

// AcquisitionFailure is the observed outcome of a request that could not
// yield an artifact. URL is always the URL requested; ArtifactURL names an
// intended download separately when metadata established one.
type AcquisitionFailure struct {
	Kind         string `json:"kind"`
	Stage        string `json:"stage,omitempty"`
	URL          string `json:"url"`
	ArtifactURL  string `json:"artifactUrl,omitempty"`
	Status       int    `json:"status,omitempty"`
	Reason       string `json:"reason,omitempty"`
	PolicyReason string `json:"policyReason,omitempty"`
	Hint         string `json:"hint,omitempty"`
}

// Public returns a copy safe to emit in reports.
func (f AcquisitionFailure) Public() AcquisitionFailure {
	f.Hint = redactRelatedURLs(f.Hint, f.URL, f.ArtifactURL)
	f.URL = manifest.PublicURL(f.URL)
	f.ArtifactURL = manifest.PublicURL(f.ArtifactURL)
	return f
}

// UnavailableError is any acquisition failure that can survive as structured
// report data while independent metadata and advisory lookups continue.
type UnavailableError interface {
	error
	Unavailable() AcquisitionFailure
}

// HTTPError is a classified acquisition failure carrying the exact requested
// URL and status.
type HTTPError struct {
	URL          string
	Stage        string
	ArtifactURL  string
	Status       int
	Reason       string
	PolicyReason string
	Hint         string // optional extra context, e.g. "set GITHUB_TOKEN"
}

func (e *HTTPError) Error() string {
	failure := e.Unavailable()
	msg := fmt.Sprintf("GET %s: %d %s", failure.URL, failure.Status, http.StatusText(failure.Status))
	if failure.Hint != "" {
		msg += " (" + failure.Hint + ")"
	}
	return msg
}

// Kind classifies the failure for the signal ledger.
func (e *HTTPError) Kind() string {
	if e.Reason == "policy-blocked" {
		return Denied
	}
	switch e.Status {
	case http.StatusNotFound, http.StatusGone:
		return Absent
	case http.StatusUnauthorized:
		return Denied
	case http.StatusForbidden:
		if e.Reason == "rate-limited" {
			return Transient
		}
		return Denied
	default:
		return Transient
	}
}

func (e *HTTPError) Unavailable() AcquisitionFailure {
	return AcquisitionFailure{
		Kind: e.Kind(), Stage: e.Stage, URL: e.URL, ArtifactURL: e.ArtifactURL,
		Status: e.Status, Reason: e.Reason, PolicyReason: e.PolicyReason, Hint: e.Hint,
	}.Public()
}

// acquisitionError records a transport or parse failure where no HTTP error
// classification exists.
type acquisitionError struct {
	AcquisitionFailure
	err error
}

func (e *acquisitionError) Error() string {
	return fmt.Sprintf("%s: %s", manifest.PublicURL(e.URL), transportHint(e.err, e.URL))
}
func (e *acquisitionError) Unwrap() error { return e.err }
func (e *acquisitionError) Unavailable() AcquisitionFailure {
	return e.AcquisitionFailure
}

func failedAcquisition(stage, u string, status int, err error) error {
	return &acquisitionError{
		AcquisitionFailure: AcquisitionFailure{
			Kind: Transient, Stage: stage, URL: u, Status: status,
			Hint: transportHint(err, u),
		}.Public(),
		err: err,
	}
}

func failedArtifactAcquisition(u string, status int, err error) error {
	var local *os.PathError
	if errors.Is(err, errArtifactCeiling) || errors.As(err, &local) {
		return err
	}
	return failedAcquisition("artifact", u, status, err)
}

func withArtifactURL(err error, artifactURL string) error {
	if artifactURL == "" {
		return err
	}
	var unavailable UnavailableError
	if !errors.As(err, &unavailable) {
		return err
	}
	failure := unavailable.Unavailable()
	failure.ArtifactURL = artifactURL
	return &acquisitionError{AcquisitionFailure: failure, err: err}
}

// RegistryMissing records a version absent from an observed registry index.
// ArtifactURL is the intended archive, which was not requested.
type RegistryMissing struct {
	URL         string
	ArtifactURL string
	Status      int
	Hint        string
}

func (e *RegistryMissing) Error() string {
	return e.Hint
}

func (e *RegistryMissing) Unavailable() AcquisitionFailure {
	return AcquisitionFailure{
		Kind: Absent, Stage: "registry-index", URL: e.URL, ArtifactURL: e.ArtifactURL,
		Status: e.Status, Reason: "version-absent", Hint: e.Hint,
	}.Public()
}

func statusErrAt(stage, u string, status int, hint string) *HTTPError {
	return &HTTPError{URL: u, Stage: stage, Status: status, Hint: hint}
}

func transportHint(err error, requestedURL string) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return redactRelatedURLs(urlErr.Err.Error(), requestedURL, urlErr.URL)
	}
	return redactRelatedURLs(err.Error(), requestedURL)
}

func redactRelatedURLs(value string, urls ...string) string {
	for _, raw := range urls {
		if raw != "" {
			value = strings.ReplaceAll(value, raw, manifest.PublicURL(raw))
		}
	}
	return value
}
