package gematik

import (
	"context"
	"net/http"
	"sort"

	"sekidp-ctk/internal/useragent"
)

// Authenticator authenticates the resource owner at the authorization
// endpoint. It starts at authURL (authorization_endpoint with client_id and
// request_uri) and returns once the IdP redirects to one of stopOrigins (the
// Fachdienst), or ends on a page it cannot continue from.
//
// Implementations for the TI authentication methods (eGK+PIN, online eID,
// EUDI wallet, SCRAM test accounts, ...) plug in here; register them in
// authenticators.
type Authenticator interface {
	Authenticate(ctx context.Context, rt http.RoundTripper, authURL string, stopOrigins []string) (*useragent.Outcome, error)
	// Interactive reports whether the method can actually log a user in
	// (false: it only follows redirects, e.g. no steps configured).
	Interactive() bool
}

// authenticators maps login.method values to constructors.
var authenticators = map[string]func(Login) Authenticator{
	"form": func(l Login) Authenticator { return &formAuthenticator{login: l} },
}

func authenticatorNames() []string {
	var names []string
	for n := range authenticators {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// formAuthenticator drives HTML login/consent forms with the generic user
// agent, for test environments that offer a web login with test identities.
type formAuthenticator struct{ login Login }

func (f *formAuthenticator) Interactive() bool { return len(f.login.Steps) > 0 }

func (f *formAuthenticator) Authenticate(ctx context.Context, rt http.RoundTripper, authURL string, stopOrigins []string) (*useragent.Outcome, error) {
	agent := &useragent.Agent{
		Transport:   rt,
		Steps:       f.login.Steps,
		Vars:        map[string]string{"username": f.login.Username, "password": f.login.Password},
		StopOrigins: stopOrigins,
	}
	return agent.Run(ctx, authURL)
}

// newAuthenticator returns the configured method, or one without steps (it
// only follows redirects) when unauthenticatedOnly is set.
func newAuthenticator(l Login, unauthenticatedOnly bool) Authenticator {
	if unauthenticatedOnly {
		return &formAuthenticator{}
	}
	return authenticators[l.Method](l)
}
