package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicLocatorPreservesDeclarationSyntax(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"github.com/fork/x v1.2.3", "github.com/fork/x v1.2.3"},
		{"git=https://github.com/x/y", "git=https://github.com/x/y"},
		{"git=https://u:SECRET@github.com/x/y?token=TOKEN&ref=main", "git=https://github.com/x/y?ref=main"},
		{"@scope/pkg@https://ci:SECRET@host/x.tgz", "@scope/pkg@https://host/x.tgz"},
		{"git=https://u:SECRET@host/x%zz", "git=[invalid URL redacted]"},
	} {
		if got := PublicLocator(tc.raw); got != tc.want {
			t.Errorf("PublicLocator(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestMalformedSourceDoesNotClaimCredentialPresence(t *testing.T) {
	raw, err := json.Marshal(LockSource{Resolved: "https://host/x%zz"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"credentialsPresent":true`) {
		t.Fatalf("invalid URL is not proof of credentials: %s", raw)
	}
}

func TestCredentialPresenceSurvivesSanitizedJSONRoundtrip(t *testing.T) {
	original := LockSource{Resolved: "https://ci:SECRET@host/x.tgz"}
	first, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded LockSource
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.CredentialsPresent || !strings.Contains(string(second), `"credentialsPresent":true`) || strings.Contains(string(second), "SECRET") {
		t.Fatalf("lost redaction evidence: %s", second)
	}
}
