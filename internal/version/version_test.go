package version

import "testing"

// A build that is not at a release tag must not name a release. Since Go 1.24
// a working-tree build carries a VCS pseudo-version, whose base is the tag
// AFTER the newest reachable one: a version that was never published and never
// will be. Reporting it verbatim stamped stats.json with a fetchable-looking
// lie, and the old "(devel)" guard stopped catching it.
func TestFromBuildInfo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		modVersion string
		revision   string
		want       string
	}{
		{"released module version", "v0.35.0", "f067f01deadbeef", "0.35.0"},
		{"released, no revision recorded", "v0.35.0", "", "0.35.0"},
		{"pre-1.24 local build", "(devel)", "f067f01deadbeef", "dev-f067f01"},
		{"pseudo-version from a working tree", "v0.28.3-0.20260730064108-ab3273c310cc", "f067f01deadbeef", "dev-f067f01"},
		{"pseudo-version, dirty tree", "v0.28.3-0.20260730064108-ab3273c310cc+dirty", "f067f01deadbeef", "dev-f067f01"},
		{"pseudo-version with no reachable tag", "v0.0.0-20260730064108-ab3273c310cc", "f067f01deadbeef", "dev-f067f01"},
		{"dirty release tag is still a working tree", "v0.35.0+dirty", "f067f01deadbeef", "dev-f067f01"},
		{"pseudo-version, no revision recorded", "v0.28.3-0.20260730064108-ab3273c310cc", "", "dev"},
		// a real prerelease is a published version and must survive
		{"prerelease", "v0.36.0-rc.1", "f067f01deadbeef", "0.36.0-rc.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fromBuildInfo(tc.modVersion, tc.revision); got != tc.want {
				t.Errorf("fromBuildInfo(%q, %q) = %q, want %q", tc.modVersion, tc.revision, got, tc.want)
			}
		})
	}
}
