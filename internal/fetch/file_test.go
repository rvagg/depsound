package fetch

import (
	"context"
	"net/http"
	"testing"
)

func TestGitHubContentsPolicyBlock(t *testing.T) {
	client := githubTestClient(http.StatusForbidden, nil, `{"message":"Repository access blocked","block":{"reason":"tos"}}`)

	_, err := GitHubContents(context.Background(), client, "owner/repo", "v1", "go.mod")
	failure := unavailableHTTPError(t, err)
	if failure.Kind() != Denied || failure.Stage != "input" || failure.Reason != "policy-blocked" {
		t.Fatalf("classification = %#v", failure)
	}
	if failure.PolicyReason != "tos" {
		t.Fatalf("policy reason = %q", failure.PolicyReason)
	}
}

func TestGitHubContentsUnknownForbidden(t *testing.T) {
	client := githubTestClient(http.StatusForbidden, nil, `{"message":"forbidden"}`)

	_, err := GitHubContents(context.Background(), client, "owner/repo", "v1", "go.mod")
	failure := unavailableHTTPError(t, err)
	if failure.Kind() != Denied || failure.Reason != "" || failure.Hint != "" {
		t.Fatalf("classification = %#v", failure)
	}
}
