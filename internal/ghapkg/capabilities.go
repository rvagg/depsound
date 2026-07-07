package ghapkg

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// capCategory groups the grep markers for one kind of sensitive thing an
// action's code can touch on the CI runner: the OIDC token, secrets, the
// network, and so on. A marker match is a REFERENCE, not proof of malicious
// use, and an attacker can obfuscate past it, so this is a lead (a
// HEURISTIC), most valuable as a DELTA: a capability NEWLY introduced by a
// bump is the tj-actions shape (exfil secrets via a new network + OIDC path).
type capCategory struct {
	name    string
	markers []string
}

var capCategories = []capCategory{
	{"OIDC token request (cloud federation)", []string{"ACTIONS_ID_TOKEN_REQUEST", "getIDToken", "id-token"}},
	{"secrets / runner tokens", []string{"GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "RUNNER_TOKEN", "ACTIONS_RUNTIME_URL"}},
	{"step injection ($GITHUB_ENV/OUTPUT/PATH into later steps)", []string{"GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STATE"}},
	{"network egress", []string{"fetch(", "http.request", "https.request", "net.connect", "axios", "XMLHttpRequest", "node-fetch", "got(", "\"https\"", "'https'"}},
	{"process execution", []string{"child_process", "execSync(", "spawnSync(", "spawn(", "eval(", "\"vm\"", "'vm'"}},
}

// scanExts are the files an action executes or that carry its shell.
var scanExts = map[string]bool{".js": true, ".cjs": true, ".mjs": true, ".ts": true, ".sh": true}

const maxScanBytes = 8 << 20 // dist bundles are large but bounded

// ScanCapabilities greps the action's executed code (the committed dist
// bundle, scripts, and action.yml shell) for the capability categories it
// references, returning category name -> number of files it appeared in.
func ScanCapabilities(tree string) map[string]int {
	present := map[string]int{}
	_ = filepath.WalkDir(tree, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		base := strings.ToLower(d.Name())
		if !scanExts[filepath.Ext(base)] && base != "action.yml" && base != "action.yaml" {
			return nil
		}
		content := readCapped(p)
		if content == "" {
			return nil
		}
		for _, c := range capCategories {
			for _, m := range c.markers {
				if strings.Contains(content, m) {
					present[c.name]++
					break
				}
			}
		}
		return nil
	})
	return present
}

// Capabilities returns the present categories (sorted) for a single version.
func Capabilities(tree string) []string {
	return sortedKeys(ScanCapabilities(tree))
}

// CapabilityDelta returns the categories present in the new version and the
// subset NEWLY introduced (present in new, absent in old): the delta is the
// load-bearing signal.
func CapabilityDelta(oldTree, newTree string) (present, introduced []string) {
	old := ScanCapabilities(oldTree)
	niu := ScanCapabilities(newTree)
	present = sortedKeys(niu)
	for _, name := range present {
		if _, wasThere := old[name]; !wasThere {
			introduced = append(introduced, name)
		}
	}
	return present, introduced
}

func readCapped(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxScanBytes)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
