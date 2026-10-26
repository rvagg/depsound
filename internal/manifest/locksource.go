package manifest

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// LockSource records declared acquisition metadata, not verified package bytes.
// Empty fields are unknown; Location identifies an entry within the lockfile.
type LockSource struct {
	Location           string `json:"location,omitempty"`
	Resolved           string `json:"resolved"`
	Host               string `json:"host"`
	Integrity          string `json:"integrity"`
	Link               bool   `json:"link,omitempty"`
	CredentialsPresent bool   `json:"credentialsPresent,omitempty"`
}

// PublicResolved excludes credentials while retaining the acquisition's
// structural address for a metadata-only review.
func (s LockSource) PublicResolved() string {
	return PublicURL(s.Resolved)
}

// PublicURL excludes URL userinfo and recognised credential query fields.
// Invalid URLs are replaced rather than returned raw because their credential
// boundary cannot be parsed safely.
func PublicURL(raw string) string {
	prefix, raw := lockSourcePrefix(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL redacted]"
	}
	u.User = nil
	u.RawQuery = publicRawQuery(u.RawQuery)
	return prefix + u.String()
}

// PublicLocator preserves declaration and lock-key syntax around an embedded URL.
func PublicLocator(raw string) string {
	end := strings.Index(raw, "://")
	if end < 0 {
		return raw
	}
	start := end
	for start > 0 {
		c := raw[start-1]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-') {
			break
		}
		start--
	}
	return raw[:start] + PublicURL(raw[start:])
}

func (s LockSource) PublicLocation() string { return PublicLocator(s.Location) }

func publicRawQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	out := parts[:0]
	for _, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil || credentialQueryKey(decoded) {
			continue
		}
		out = append(out, part)
	}
	return strings.Join(out, "&")
}

// PublicHost excludes any userinfo carried by a direct LockSource literal.
func (s LockSource) PublicHost() string {
	if s.Host != "" {
		u, err := url.Parse("//" + s.Host)
		if err != nil {
			return "[invalid host redacted]"
		}
		if u.Hostname() != "" {
			return u.Hostname()
		}
		return "[invalid host redacted]"
	}
	_, raw := lockSourcePrefix(s.Resolved)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil {
		return u.Hostname()
	}
	return "[invalid host redacted]"
}

func (s LockSource) hasCredentials() bool {
	if s.CredentialsPresent {
		return true
	}
	if s.Host != "" {
		host, err := url.Parse("//" + s.Host)
		if err != nil {
			return false
		}
		if host.User != nil {
			return true
		}
	}
	_, raw := lockSourcePrefix(s.Resolved)
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.User != nil {
		return true
	}
	for key := range u.Query() {
		if credentialQueryKey(key) {
			return true
		}
	}
	return false
}

// MarshalJSON redacts credentials from emitted lockfile metadata. Resolved is
// deliberately retained raw in memory so comparisons can observe rotations.
func (s LockSource) MarshalJSON() ([]byte, error) {
	type publicLockSource struct {
		Location           string `json:"location,omitempty"`
		Resolved           string `json:"resolved"`
		Host               string `json:"host"`
		Integrity          string `json:"integrity"`
		Link               bool   `json:"link,omitempty"`
		CredentialsPresent bool   `json:"credentialsPresent,omitempty"`
	}
	return json.Marshal(publicLockSource{
		Location:           s.PublicLocation(),
		Resolved:           s.PublicResolved(),
		Host:               s.PublicHost(),
		Integrity:          s.Integrity,
		Link:               s.Link,
		CredentialsPresent: s.hasCredentials(),
	})
}

// LockChange records a declared source or version movement. It never claims
// artifact or advisory evidence.
type LockChange struct {
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`
	Kind        string `json:"kind,omitempty"`
	Version     string `json:"version,omitempty"`
	FromVersion string `json:"fromVersion,omitempty"`
	ToVersion   string `json:"toVersion,omitempty"`
	// ToRegistry retains a source-only baseline while permitting an exact
	// census of the supported registry target. It never authorizes an old
	// artifact fetch or a diff.
	ToRegistry         bool         `json:"toRegistry,omitempty"`
	CredentialsChanged bool         `json:"credentialsChanged,omitempty"`
	From               []LockSource `json:"from"`
	To                 []LockSource `json:"to"`
	Files              []string     `json:"files,omitempty"`
}

// Ref formats the declared identity and known version facts for display.
func (c LockChange) Ref() string {
	ref := c.Ecosystem + ":" + c.Name
	from, to := c.FromVersion, c.ToVersion
	if from == "" && to == "" && c.Version != "" {
		return ref + " " + c.Version
	}
	switch {
	case from != "" && to != "":
		return ref + " " + from + " -> " + to
	case to != "":
		return ref + " " + to
	case from != "":
		return ref + " " + from
	default:
		return ref
	}
}

// CredentialsChanged reports a credential addition, removal or rotation from
// raw in-memory lock sources. It never emits a credential value or hash.
func CredentialsChanged(from, to []LockSource) bool {
	return !sameCredentialValues(from, to)
}

func sameCredentialValues(a, b []LockSource) bool {
	values := func(sources []LockSource) []string {
		var out []string
		for _, source := range sources {
			if credentials := sourceCredentialValues(source); credentials != "" {
				out = append(out, sourceCredentialKey(source)+"\x00"+credentials)
			}
		}
		sort.Strings(out)
		return out
	}
	av, bv := values(a), values(b)
	if len(av) != len(bv) {
		return false
	}
	for i := range av {
		if av[i] != bv[i] {
			return false
		}
	}
	return true
}

func sourceCredentialValues(s LockSource) string {
	var values []string
	if s.Host != "" {
		host, err := url.Parse("//" + s.Host)
		switch {
		case err != nil:
			values = append(values, "invalid-host")
		case host.User != nil:
			values = append(values, "host-userinfo="+host.User.String())
		}
	}
	_, raw := lockSourcePrefix(s.Resolved)
	u, err := url.Parse(raw)
	if err != nil {
		if raw != "" {
			values = append(values, "invalid-url")
		}
		return strings.Join(values, "\x00")
	}
	if u.User != nil {
		values = append(values, "userinfo="+u.User.String())
	}
	for key, vals := range u.Query() {
		if credentialQueryKey(key) {
			for _, value := range vals {
				values = append(values, strings.ToLower(key)+"="+value)
			}
		}
	}
	sort.Strings(values)
	return strings.Join(values, "\x00")
}

func sourceCredentialKey(s LockSource) string {
	if s.Location != "" {
		return "location=" + s.Location
	}
	return "resolved=" + s.PublicResolved()
}

func lockSourcePrefix(resolved string) (string, string) {
	for _, prefix := range []string{"registry+", "sparse+", "git+"} {
		if raw, ok := strings.CutPrefix(resolved, prefix); ok {
			return prefix, raw
		}
	}
	return "", resolved
}

// credentialQueryKey is deliberately an explicit conservative list: generic
// tokens plus AWS and Google signed-URL credential fields.
func credentialQueryKey(key string) bool {
	switch strings.ToLower(key) {
	case "token", "access_token", "password", "secret", "api_key", "apikey",
		"auth", "authorization", "signature", "sig",
		"x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires",
		"x-amz-security-token", "x-amz-signature", "x-amz-signedheaders",
		"x-goog-algorithm", "x-goog-credential", "x-goog-date", "x-goog-expires",
		"x-goog-security-token", "x-goog-signature", "x-goog-signedheaders",
		"googleaccessid":
		return true
	}
	return false
}

func NewLockSource(location, resolved, integrity string) LockSource {
	s := LockSource{Location: location, Resolved: resolved, Integrity: integrity}
	_, raw := lockSourcePrefix(resolved)
	if u, err := url.Parse(raw); err == nil {
		s.Host = u.Hostname()
	}
	return s
}
