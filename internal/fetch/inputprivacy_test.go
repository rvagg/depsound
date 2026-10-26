package fetch

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type inputFailureTransport struct{}

func (inputFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestInputURLFailureMessagesRedactCredentials(t *testing.T) {
	client := &http.Client{Transport: inputFailureTransport{}}
	for _, raw := range []string{
		"https://INPUT_USER:INPUT_SECRET@host/input?token=INPUT_QUERY",
		"https://INPUT_USER:INPUT_SECRET@host/x%zz?token=INPUT_QUERY",
		"http://INPUT_USER:INPUT_SECRET@host/input?token=INPUT_QUERY",
	} {
		_, err := GetURL(context.Background(), client, raw)
		if err == nil {
			t.Fatal("failed input unexpectedly succeeded")
		}
		for _, secret := range []string{"INPUT_USER", "INPUT_SECRET", "INPUT_QUERY"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("input error leaked %s: %s", secret, err)
			}
		}
	}
}
