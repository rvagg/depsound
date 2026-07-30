package provenance

import "testing"

// The same "publisher differs" fact points in opposite directions. Moving onto
// a trusted publisher retires a long-lived token; moving off one is the
// takeover tell. Reading both as one anomaly reported hardening as compromise.
func TestPublisherShift(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		cur, prev             string
		curConfig, prevConfig string
		maintainerChange      bool
		want                  PublisherShift
	}{
		{"user to trusted publisher", "github", "", "oidc:a", "", true, ShiftHardened},
		{"trusted publisher to user", "", "github", "", "oidc:a", true, ShiftRelaxed},
		{"provider changed", "gitlab", "github", "oidc:b", "oidc:a", false, ShiftRepinned},
		// the case every other field hides: same provider, same publisher name,
		// but a different repo/workflow was authorised
		{"config repointed within one provider", "github", "github", "oidc:b", "oidc:a", false, ShiftRepinned},
		{"user to a different user", "", "", "", "", true, ShiftUser},
		{"same user throughout", "", "", "", "", false, ShiftNone},
		{"same config throughout", "github", "github", "oidc:a", "oidc:a", false, ShiftNone},
		// an older release predating the config field must not read as a repin
		{"config unknown on one side", "github", "github", "oidc:a", "", false, ShiftNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Result{
				TrustedPublisher: tc.cur, PrevTrustedPublisher: tc.prev,
				TrustedConfig: tc.curConfig, PrevTrustedConfig: tc.prevConfig,
				MaintainerChanged: tc.maintainerChange,
			}
			if got := r.Shift(); got != tc.want {
				t.Errorf("Shift() = %q, want %q", got, tc.want)
			}
		})
	}
}
