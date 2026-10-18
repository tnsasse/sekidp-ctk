package oauth

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBasicAuthFormEncodes(t *testing.T) {
	got := BasicAuth(Credentials{ID: "a:b", Secret: "p w+%"})
	raw, _ := base64.StdEncoding.DecodeString(got[len("Basic "):])
	if string(raw) != "a%3Ab:p+w%2B%25" {
		t.Fatalf("decoded credentials = %q", raw)
	}
}

func TestAppendQueryRetainsExisting(t *testing.T) {
	v := url.Values{"a": {"1"}}
	for in, want := range map[string]string{
		"https://x/t":      "https://x/t?a=1",
		"https://x/t?k=v":  "https://x/t?k=v&a=1",
		"https://x/t?":     "https://x/t?a=1",
		"https://x/t?k=v&": "https://x/t?k=v&a=1",
	} {
		if got := AppendQuery(in, v); got != want {
			t.Errorf("AppendQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDoAuthMethods(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_request","expires_in":5}`))
	}))
	defer srv.Close()
	c := Credentials{ID: "id", Secret: "sec"}
	ctx := context.Background()

	r, err := Do(ctx, srv.Client(), TokenRequest{Endpoint: srv.URL, Form: url.Values{"grant_type": {"x"}}, Auth: AuthBody, Client: c})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" || gotBody != "client_id=id&client_secret=sec&grant_type=x" {
		t.Fatalf("body auth: auth=%q body=%q", gotAuth, gotBody)
	}
	if r.ErrorCode() != "invalid_request" {
		t.Fatalf("ErrorCode = %q", r.ErrorCode())
	}

	_, _ = Do(ctx, srv.Client(), TokenRequest{Endpoint: srv.URL, RawBody: "grant_type=x&grant_type=x", Auth: AuthNone, Client: c})
	if gotBody != "grant_type=x&grant_type=x&client_id=id" {
		t.Fatalf("raw body: %q", gotBody)
	}

	_, _ = Do(ctx, srv.Client(), TokenRequest{Endpoint: srv.URL, Form: url.Values{"grant_type": {"x"}}, Auth: AuthBasic, Client: c})
	if gotAuth == "" || gotBody != "grant_type=x" {
		t.Fatalf("basic auth: auth=%q body=%q", gotAuth, gotBody)
	}
}
