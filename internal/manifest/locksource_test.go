package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLockSourceJSONRedactsCredentialsWithoutErasingRotation(t *testing.T) {
	from := LockSource{
		Location: "lock/x", Resolved: "https://ci-user:FAKE_USERINFO@registry.example/x.tgz?token=FAKE_TOKEN&keep=value&X-Amz-Signature=FAKE_SIGNATURE",
		Host: "ci-user:FAKE_USERINFO@registry.example", Integrity: "sha512-x",
	}
	to := from
	to.Resolved = "https://ci-user:ROTATED_USERINFO@registry.example/x.tgz?token=ROTATED_TOKEN&keep=value&X-Amz-Signature=ROTATED_SIGNATURE"
	if !CredentialsChanged([]LockSource{from}, []LockSource{to}) {
		t.Fatal("raw credential rotation was not retained for comparison")
	}
	raw, err := json.Marshal(LockChange{Ecosystem: "npm", Name: "x", Version: "1", CredentialsChanged: true, From: []LockSource{from}, To: []LockSource{to}})
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, secret := range []string{"FAKE_USERINFO", "FAKE_TOKEN", "FAKE_SIGNATURE", "ROTATED_USERINFO", "ROTATED_TOKEN", "ROTATED_SIGNATURE"} {
		if strings.Contains(out, secret) {
			t.Errorf("credential leaked in JSON: %s", secret)
		}
	}
	for _, want := range []string{"registry.example", "keep=value", "credentialsPresent", "credentialsChanged"} {
		if !strings.Contains(out, want) {
			t.Errorf("public metadata missing %q: %s", want, out)
		}
	}
}

func TestLockSourceJSONInputRetainsRawComparisonAndRedactsOutput(t *testing.T) {
	var source LockSource
	if err := json.Unmarshal([]byte(`{"resolved":"https://ci:JSON_SECRET@registry.example/x.tgz?token=JSON_TOKEN","host":"registry.example"}`), &source); err != nil {
		t.Fatal(err)
	}
	if !CredentialsChanged([]LockSource{source}, nil) {
		t.Fatal("credential-bearing JSON input was not detected")
	}
	out, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "JSON_SECRET") || strings.Contains(string(out), "JSON_TOKEN") {
		t.Errorf("credential leaked from JSON input: %s", out)
	}
}

func TestPublicURLPreservesStructureWithoutCredentials(t *testing.T) {
	got := PublicURL("git+https://ci:SECRET@host.example/path?keep=1&signature=SIGNED")
	if strings.Contains(got, "SECRET") || strings.Contains(got, "SIGNED") {
		t.Errorf("PublicURL leaked credentials: %s", got)
	}
	for _, want := range []string{"git+https://host.example/path", "keep=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("PublicURL lost structural value %q: %s", want, got)
		}
	}
}

func TestPublicURLFailsClosedAndPreservesPublicQueryBytes(t *testing.T) {
	malformed := PublicURL("https://u:SECRET@host.example/x%zz?token=TOKEN")
	if strings.Contains(malformed, "SECRET") || strings.Contains(malformed, "TOKEN") {
		t.Errorf("malformed URL leaked credentials: %s", malformed)
	}
	raw := "https://host.example/x?z=%2B&a=two+words&token=TOKEN&flag"
	public := PublicURL(raw)
	if public != "https://host.example/x?z=%2B&a=two+words&flag" {
		t.Errorf("public query structure changed: %s", public)
	}
	encoded, err := json.Marshal(LockSource{Resolved: "https://u:SECRET@host.example/x%zz", Host: "u:SECRET@host.example/x%zz"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SECRET") {
		t.Errorf("malformed source leaked credential: %s", encoded)
	}
}

func TestCredentialsChangedBindsValuesToSourceLocation(t *testing.T) {
	from := []LockSource{
		{Location: "a", Resolved: "https://host.example/a?token=one"},
		{Location: "b", Resolved: "https://host.example/b?token=two"},
	}
	to := []LockSource{
		{Location: "a", Resolved: "https://host.example/a?token=two"},
		{Location: "b", Resolved: "https://host.example/b?token=one"},
	}
	if !CredentialsChanged(from, to) {
		t.Fatal("credential swap across stable source locations was not detected")
	}
}

func TestLockChangeRefUsesKnownVersions(t *testing.T) {
	for _, tc := range []struct {
		change LockChange
		want   string
	}{
		{LockChange{Ecosystem: "npm", Name: "x", Version: "1"}, "npm:x 1"},
		{LockChange{Ecosystem: "npm", Name: "x", FromVersion: "1", ToVersion: "2"}, "npm:x 1 -> 2"},
		{LockChange{Ecosystem: "npm", Name: "x", ToVersion: "2"}, "npm:x 2"},
		{LockChange{Ecosystem: "npm", Name: "x", FromVersion: "1"}, "npm:x 1"},
	} {
		if got := tc.change.Ref(); got != tc.want {
			t.Errorf("Ref() = %q, want %q", got, tc.want)
		}
	}
}

func TestCredentialsChangedIgnoresNonCredentialSourceChanges(t *testing.T) {
	from := []LockSource{{Resolved: "https://registry.example/old.tgz?keep=1"}}
	to := []LockSource{{Resolved: "https://mirror.example/new.tgz?keep=2"}}
	if CredentialsChanged(from, to) {
		t.Fatal("ordinary acquisition change must not claim credentials changed")
	}
}
