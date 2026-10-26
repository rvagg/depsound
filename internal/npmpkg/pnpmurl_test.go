package npmpkg

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPnpmURLIdentityKeepsCredentialsOutOfNamesAndOutput(t *testing.T) {
	raw := []byte("lockfileVersion: '9.0'\npackages:\n  'priv@https://ci:PNSECRET@host/priv.tgz': {}\n  '@scope/priv@https://ci:SCOPEDSECRET@host/priv.tgz': {}\n")
	deps, nonRegistry, err := ParsePnpmLock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 || nonRegistry != 2 {
		t.Fatalf("lost URL acquisitions: %+v, %d", deps, nonRegistry)
	}
	for _, dep := range deps {
		if dep.Name != "priv" && dep.Name != "@scope/priv" {
			t.Fatalf("URL userinfo became a package name: %q", dep.Name)
		}
		if dep.Source.Resolved == "" || !dep.NonRegistry {
			t.Fatalf("raw acquisition evidence lost: %+v", dep)
		}
	}
	encoded, err := json.Marshal(deps)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PNSECRET") || strings.Contains(string(encoded), "SCOPEDSECRET") {
		t.Fatalf("URL key leaked credentials: %s", encoded)
	}
	if _, ok := pnpmID("priv", "https://ci:PNSECRET@1.2.3"); ok {
		t.Fatal("URL credential tail became a registry graph id")
	}
}
