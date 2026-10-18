package gematik

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"sekidp-ctk/internal/oauth"
	"sekidp-ctk/internal/suite"
)

const (
	loaHigh        = "gematik-ehealth-loa-high"
	loaSubstantial = "gematik-ehealth-loa-substantial"
	professionVers = "1.2.276.0.76.4.49"
)

// amrLevels: allowed acr values per amr value (Table 7, A_23129-06).
var amrLevels = map[string][]string{
	"urn:telematik:auth:eGK":        {loaHigh},
	"urn:telematik:auth:eID":        {loaHigh},
	"urn:telematik:auth:guest:eGK":  {loaHigh},
	"urn:telematik:auth:eudiWallet": {loaHigh},
	"urn:telematik:auth:other":      {loaHigh, loaSubstantial},
	"urn:telematik:auth:sso":        {loaHigh, loaSubstantial},
	"urn:telematik:auth:mEW":        {loaSubstantial},
}

// Claims that may appear in any ID token besides the scope claims.
var protocolClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "acr", "amr", "auth_time",
	"at_hash", "c_hash", "azp", "jti", "sid", "urn:telematik:auth:consent", "urn:telematik:auth:interactive"}

// expectRejected asserts a 4xx error with a JSON error member (RFC 6749 §5.2
// format, as RFC 9126 §2.3 and OpenID Federation require).
func expectRejected(t *suite.T, r *oauth.Response, section, what string, wantStatus int, wantCodes ...string) bool {
	rejected := r.Status >= 400 && r.Status < 500 && !r.Has("request_uri") && !r.Has("id_token")
	if !t.Must(section, rejected, "%s is rejected with a 4xx error (got %s)", what, r.Summary()) {
		return false
	}
	t.Must("6749/5.2", r.ErrorCode() != "" && isJSONResponse(r.Header), "error response is JSON with an \"error\" member (Content-Type %q)", r.Header.Get("Content-Type"))
	if wantStatus != 0 {
		t.Must(section, r.Status == wantStatus, "%s is answered with HTTP %d (got %d)", what, wantStatus, r.Status)
	}
	if len(wantCodes) > 0 {
		t.Should(section, slices.Contains(wantCodes, r.ErrorCode()), "error code is %s (got %q)", strings.Join(wantCodes, " or "), r.ErrorCode())
	}
	return true
}

func entropyBits(s string) float64 {
	var digit, lower, upper, other bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		default:
			other = true
		}
	}
	n := 0
	for b, size := range map[*bool]int{&digit: 10, &lower: 26, &upper: 26, &other: 33} {
		if *b {
			n += size
		}
	}
	if n < 2 {
		return 0
	}
	return float64(len(s)) * math.Log2(float64(n))
}

func parTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GPR-01", Spec: spec, Section: "A_22992", Title: "Valid pushed authorization request gets 201 with request_uri",
			Expect: "The IdP MUST accept pushed authorization requests (A_22651) from a registered Fachdienst authenticated via self_signed_tls_client_auth and answer a valid one with HTTP 201 (A_22992) and a JSON body with request_uri and expires_in (RFC 9126 §2.2).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				r := newPAR(fd).send(t, &fd.cert)
				if !t.Must(afo("A_22992"), r.Status == 201, "valid PAR is answered with HTTP 201 (got %s)", r.Summary()) {
					return
				}
				t.Must("9126/2.2", isJSONResponse(r.Header), "response is application/json (got %q)", r.Header.Get("Content-Type"))
				ru, ok := r.Str("request_uri")
				t.Must("9126/2.2", ok && ru != "", "request_uri is a non-empty string")
				_, ok = numClaim(r.JSON, "expires_in")
				t.Must("9126/2.2", ok, "expires_in is a number")
			},
		},
		{
			ID: "GPR-02", Spec: spec, Section: "A_22993", Title: "request_uri lifetime is at most 90 seconds",
			Expect: "The validity of a request_uri issued by the IdP MUST NOT exceed 90 seconds (A_22993); expires_in in the PAR response states it.",
			Run: func(t *suite.T) {
				_, r := newPAR(fachdienst(t)).pushOK(t)
				n, ok := numClaim(r.JSON, "expires_in")
				t.Must(afo("A_22993"), ok && n > 0 && n <= 90, "expires_in is between 1 and 90 seconds (got %v)", r.JSON["expires_in"])
			},
		},
		{
			ID: "GPR-03", Spec: spec, Section: "A_22649", Title: "PAR without a client certificate gets 401",
			Expect: "Pushed authorization requests from clients that are not authenticated as registered federation members MUST be rejected with HTTP 401 Unauthorized (A_22649). A request without a TLS client certificate cannot be authenticated via self_signed_tls_client_auth.",
			Run: func(t *suite.T) {
				ensureRegistered(t, fachdienst(t))
				r := newPAR(fachdienst(t)).send(t, nil)
				expectRejected(t, r, afo("A_22649"), "PAR without a client certificate", http.StatusUnauthorized, "invalid_client")
				t.Must(afo("A_22844"), r.Status != 201, "the VAU accepts pushed requests only over mTLS")
			},
		},
		{
			ID: "GPR-04", Spec: spec, Section: "A_22991", Title: "PAR with a certificate not in the Fachdienst's entity statement is rejected",
			Expect: "The PAR endpoint MUST verify the TLS client certificate against the Fachdienst's entity statement and check its validity period (A_22991). A self-signed certificate that the Fachdienst did not publish must not authenticate it; the request is rejected as from an unknown client (401, A_22649).",
			Run: func(t *suite.T) {
				ensureRegistered(t, fachdienst(t))
				r := newPAR(fachdienst(t)).send(t, foreignCert(t))
				expectRejected(t, r, afo("A_22991"), "PAR with an unpublished client certificate", 0, "invalid_client")
				t.Should(afo("A_22649"), r.Status == http.StatusUnauthorized, "rejection uses HTTP 401 (got %d)", r.Status)
			},
		},
		{
			ID: "GPR-05", Spec: spec, Section: "A_22649", Title: "PAR from a client_id unknown to the federation gets 401",
			Expect: "A client that is neither registered in the federation nor directly at the IdP MUST be rejected with HTTP 401 (A_22649). Automatic registration (A_22650-01) must fail for an entity the Federation Master does not know.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				p.params.Set("client_id", "https://ctk-unknown-"+randString()[:12]+".invalid")
				expectRejected(t, p.send(t, &fd.cert), afo("A_22649"), "PAR from an unknown client_id", http.StatusUnauthorized)
			},
		},
		{
			ID: "GPR-06", Spec: spec, Section: "A_22966-02", Title: "PAR with an unregistered redirect_uri is rejected",
			Expect: "The PAR endpoint MUST validate redirect_uri: it must exactly match (simple string comparison) one of the redirect URIs the Federation Master lists for the Fachdienst (A_22966-02). Otherwise the request is rejected per RFC 9126 §2.3 (invalid_request).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				p.params.Set("redirect_uri", fd.UnregisteredRedirectURI)
				expectRejected(t, p.send(t, &fd.cert), afo("A_22966-02"), "PAR with redirect_uri "+fd.UnregisteredRedirectURI, 0, "invalid_request")
			},
		},
		{
			ID: "GPR-07", Spec: spec, Section: "A_22966-02", Title: "PAR with a scope not registered for the Fachdienst is rejected",
			Expect: "scope (and claims) in a pushed request MUST be a subset of what the Federation Master lists for this Fachdienst (A_22966-02). Requesting a supported but unregistered scope must be rejected (invalid_scope).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				if fd.UnregisteredScope == "" {
					t.SkipFixture("fachdienst.unregistered_scope not configured")
				}
				p := newPAR(fd)
				p.params.Set("scope", fd.Scope+" "+fd.UnregisteredScope)
				expectRejected(t, p.send(t, &fd.cert), afo("A_22966-02"), "PAR with scope "+fd.UnregisteredScope, 0, "invalid_scope")
			},
		},
		{
			ID: "GPR-08", Spec: spec, Section: "A_22321", Title: "PAR with code_challenge_method=plain is rejected",
			Expect: "The token endpoint MUST verify the code_verifier with S256 (A_22321), so the flow only works with S256 challenges. A pushed request with code_challenge_method=plain must be rejected instead of producing a code that can never be redeemed correctly.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				p.params.Set("code_challenge", p.pkce.verifier)
				p.params.Set("code_challenge_method", "plain")
				expectRejected(t, p.send(t, &fd.cert), afo("A_22321"), "PAR with code_challenge_method=plain", 0, "invalid_request")
			},
		},
		{
			ID: "GPR-09", Spec: spec, Section: "A_22966-02", Title: "PAR without PKCE is rejected",
			Expect: "A pushed request carries the CODE_CHALLENGE derived from the Fachdienst's CODE_VERIFIER (§4.3.2); the IdP validates incoming requests (A_22966-02) and verifies the verifier at the token endpoint (A_22321). A request without code_challenge must be rejected.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				p.params.Del("code_challenge")
				p.params.Del("code_challenge_method")
				expectRejected(t, p.send(t, &fd.cert), afo("A_22966-02"), "PAR without code_challenge", 0, "invalid_request")
			},
		},
		{
			ID: "GPR-10", Spec: spec, Section: "A_24404", Title: "PAR with a claims parameter is accepted",
			Expect: "The IdP MUST process the claims parameter in pushed requests (A_24404), e.g. to request specific authentication methods via the amr claim (A_24547-01).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{
					"amr": map[string]any{"essential": false, "values": []string{"urn:telematik:auth:eGK", "urn:telematik:auth:eID"}},
				}})
				p.params.Set("claims", string(claims))
				r := p.send(t, &fd.cert)
				t.Must(afo("A_24404"), r.Status == 201, "PAR with a claims parameter is accepted (got %s)", r.Summary())
			},
		},
		{
			ID: "GPR-11", Spec: spec, Section: "A_22651", Title: "request_uri inside a pushed request is rejected",
			Expect: "PAR is implemented per RFC 9126 §2 (A_22651), which forbids the request_uri parameter in a pushed request; the IdP must reject it.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				p.params.Set("request_uri", "urn:ietf:params:oauth:request_uri:ctk-"+randString())
				expectRejected(t, p.send(t, &fd.cert), "9126/2.1", "PAR containing request_uri", 0, "invalid_request")
			},
		},
		{
			ID: "GPR-12", Spec: spec, Section: "A_22966-02", Title: "Invalid pushed requests get a JSON error response",
			Expect: "Invalid pushed requests MUST be rejected with an error response per RFC 9126 §2.3 (A_22966-02), i.e. the RFC 6749 §5.2 JSON format. gematik probes availability with such invalid requests and expects an error code (§3.3).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				p.params.Set("response_type", "ctk_unknown")
				expectRejected(t, p.send(t, &fd.cert), afo("A_22966-02"), "PAR with an unknown response_type", 0, "unsupported_response_type", "invalid_request")
			},
		},
		{
			ID: "GPR-13", Spec: spec, Section: "A_23019", Title: "request_uri values are unique and cannot be guessed",
			Expect: "Neither third parties nor the operator may learn what is encoded in the request_uri (A_23019); RFC 9126 §2.2/§7.1 require a cryptographically random, unguessable part. Each push yields a fresh value with at least 128 bits of possible entropy.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				seen := map[string]bool{}
				minBits := math.Inf(1)
				for i := 0; i < 3; i++ {
					ru, _ := newPAR(fd).pushOK(t)
					t.Must("9126/2.2", !seen[ru], "each push yields a new request_uri")
					seen[ru] = true
					minBits = math.Min(minBits, entropyBits(strings.TrimPrefix(ru, "urn:ietf:params:oauth:request_uri:")))
				}
				t.Must("9126/7.1", minBits >= 128, "request_uri has room for >= 128 bits of randomness (bound %.0f bits)", minBits)
			},
		},
	}
}

// maliciousInputs are values A_23023 expects the IdP to check (length,
// character set, keywords, control characters).
var maliciousInputs = []struct{ name, param, value string }{
	{"overlong state", "state", strings.Repeat("A", 20000)},
	{"control characters in state", "state", "ctk\x00\x1b[31m\x07"},
	{"CRLF injection in redirect_uri", "redirect_uri", "https://ctk.invalid/\r\nSet-Cookie: ctk=1"},
	{"markup in scope", "scope", "openid <script>alert(1)</script>"},
	{"SQL keyword in nonce", "nonce", "' OR '1'='1'; DROP TABLE users;--"},
	{"invalid UTF-8 in nonce", "nonce", "ctk\xff\xfe\xfd"},
}

func inputTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GPR-14", Spec: spec, Section: "A_23023", Title: "Malicious input is rejected without errors or reflection",
			Expect: "All input received via external interfaces MUST be checked for malicious values (A_23023); the note asks for checks of length, character set, keywords and control characters. Malformed values at the PAR and token endpoints must never cause a server error (5xx) or be reflected unescaped, and should be rejected with a 4xx error.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				for _, in := range maliciousInputs {
					p := newPAR(fd)
					p.params.Set(in.param, in.value)
					r := p.send(t, &fd.cert)
					t.Must(afo("A_23023"), r.Status < 500, "PAR with %s causes no server error (got HTTP %d)", in.name, r.Status)
					t.Must(afo("A_23023"), !strings.Contains(string(r.Body), "<script>"), "PAR response does not reflect markup (%s)", in.name)
					if in.name != "overlong state" && in.name != "SQL keyword in nonce" {
						t.Should(afo("A_23023"), r.Status >= 400, "PAR with %s is rejected with 4xx (got %s)", in.name, r.Summary())
					}
				}
				tr := redeem(t, fd, strings.Repeat("\x00", 64)+strings.Repeat("A", 20000), "ctk\xff", &fd.cert)
				t.Must(afo("A_23023"), tr.Status >= 400 && tr.Status < 500, "token request with malformed code and verifier is rejected with 4xx (got HTTP %d)", tr.Status)
			},
		},
	}
}

func authzTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GAZ-01", Spec: spec, Section: "A_22312-02", Title: "Authorization requests without PAR are refused",
			Expect: "The IdP requires PAR (require_pushed_authorization_requests = true, Table 4) and implements the authorization endpoint per RFC 9126 §4 (A_22312-02). A classic authorization request with all parameters in the URL must not lead to a code.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				p := newPAR(fd)
				out := authorize(t, fd, oauth.AppendQuery(endpoint(t, "authorization_endpoint"), p.params), false)
				t.Must(afo("A_22312-02"), codeFrom(out) == "", "no code is issued for a request without request_uri (%s)", out)
			},
		},
		{
			ID: "GAZ-02", Spec: spec, Section: "A_22312-02", Title: "Unknown request_uri is refused",
			Expect: "An authorization request referencing a request_uri the IdP never issued must not be processed (RFC 9126 §4, A_22312-02).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				out := authorize(t, fd, authURL(t, fd.ClientID, "urn:ietf:params:oauth:request_uri:ctk-"+randString()), false)
				t.Must(afo("A_22312-02"), codeFrom(out) == "", "no code is issued for an unknown request_uri (%s)", out)
			},
		},
		{
			ID: "GAZ-03", Spec: spec, Section: "A_22312-02", Title: "request_uri cannot be used with another client_id",
			Expect: "A request_uri is bound to the client that pushed it (RFC 9126 §2.2). Presenting it with a different client_id at the authorization endpoint must not be accepted.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				ru, _ := newPAR(fd).pushOK(t)
				other := "https://ctk-other-" + randString()[:12] + ".invalid"
				if b := gcfg(t).FachdienstB; b != nil {
					other = b.ClientID
				}
				out := authorize(t, fd, authURL(t, other, ru), gcfg(t).Login.Steps != nil)
				t.Must("9126/2.2", codeFrom(out) == "", "no code is issued when client_id does not match the pushed request (%s)", out)
			},
		},
		{
			ID: "GAZ-04", Spec: spec, Section: "A_22257", Title: "No code is issued without user authentication",
			Expect: "Authorization requests MUST only be answered with an AUTHORIZATION_CODE after the user authenticated successfully (A_22257). Following the flow without logging in must never reach the Fachdienst with a code.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				ru, _ := newPAR(fd).pushOK(t)
				out := authorize(t, fd, authURL(t, fd.ClientID, ru), false)
				t.Must(afo("A_22257"), codeFrom(out) == "", "no code reaches the Fachdienst without authentication (%s)", out)
			},
		},
		{
			ID: "GAZ-05", Spec: spec, Section: "A_22324", Title: "Successful authorization returns code and state to the redirect_uri",
			Expect: "After successful authentication the IdP redirects to the pushed redirect_uri with the AUTHORIZATION_CODE and the unchanged state (A_22324, A_22325-01: answered on the same channel the request came in).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				f := runFlow(t, fd, nil)
				q := f.out.Redirect.Query()
				red := *f.out.Redirect
				red.RawQuery = ""
				t.Must(afo("A_22325-01"), strings.HasPrefix(f.out.Redirect.String(), fd.RedirectURI), "the code is delivered to the pushed redirect_uri %s (got %s)", fd.RedirectURI, red.String())
				t.Must(afo("A_22324"), q.Get("state") == f.par.state, "state is returned unchanged (sent %q, got %q)", f.par.state, q.Get("state"))
				// gemSpec_IDP_Sek 3.2.0 Table 44: the code has at most 2000 characters.
				t.Must(afo("A_22325-01"), len(q.Get("code")) <= 2000, "authorization code is at most 2000 characters (got %d)", len(q.Get("code")))
			},
		},
		{
			ID: "GAZ-06", Spec: spec, Section: "A_25753", Title: "prompt=login and max_age=0 force authentication and yield auth_time",
			Expect: "The IdP MUST support max_age=0 and prompt=login to enforce user authentication, including the resulting obligations of OpenID Connect Core such as returning auth_time in the ID token (A_25753).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				for _, mod := range []url.Values{{"prompt": {"login"}}, {"max_age": {"0"}}} {
					f := runFlow(t, fd, func(v url.Values) {
						for k, vs := range mod {
							v[k] = vs
						}
					})
					resp := redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert)
					raw, _ := resp.Str("id_token")
					tok := decodeIDToken(fd, raw)
					if tok.Err == errNoEncKey {
						t.Must(afo("A_25753"), resp.Status == 200, "flow with %s succeeds (got %s)", mod.Encode(), resp.Summary())
						continue
					}
					if !t.Must(afo("A_25753"), tok.Err == nil, "ID token of the %s flow can be decoded (%v)", mod.Encode(), tok.Err) {
						continue
					}
					_, has := numClaim(tok.Claims, "auth_time")
					t.Must(afo("A_25753"), has, "ID token for %s contains auth_time", mod.Encode())
				}
			},
		},
		{
			ID: "GAZ-08", Spec: spec, Section: "A_22744", Title: "Browsers without the Authenticator get a web frontend",
			Expect: "If the Authenticator runs on another device than the Fachdienst frontend, the IdP MUST offer a web frontend at the authorization endpoint that continues the authentication via the other device (A_22744). If the Authenticator is not installed, that web frontend MUST say where to get it and for which platforms (A_22306-01).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				ru, _ := newPAR(fd).pushOK(t)
				out := authorize(t, fd, authURL(t, fd.ClientID, ru), false)
				if !t.Must(afo("A_22744"), out.Redirect == nil && out.PageStatus == 200 && len(out.Pages) > 0,
					"authorization endpoint serves an HTML web frontend (%s)", out) {
					return
				}
				body := strings.ToLower(out.Pages[len(out.Pages)-1].Body)
				t.Should(afo("A_22306-01"), strings.Contains(body, "apps.apple.com") || strings.Contains(body, "play.google.com"),
					"web frontend links to the Authenticator in the app stores")
			},
		},
		{
			ID: "GAZ-07", Spec: spec, Section: "A_22993", Title: "Expired request_uri is refused",
			Tags:   []string{suite.TagSlow},
			Expect: "A request_uri is valid for at most 90 seconds (A_22993) and an expired one MUST be rejected (RFC 9126 §4). After the lifetime, logging in must not produce a code.",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				requireLogin(t)
				ru, r := newPAR(fd).pushOK(t)
				n, _ := numClaim(r.JSON, "expires_in")
				if n <= 0 || n > 600 {
					n = 90
				}
				wait := time.Duration(n)*time.Second + 5*time.Second
				t.Logf("waiting %s for the request_uri to expire", wait)
				select {
				case <-time.After(wait):
				case <-t.Ctx.Done():
					t.Fatalf("interrupted")
				}
				out := authorize(t, fd, authURL(t, fd.ClientID, ru), true)
				t.Must(afo("A_22993"), codeFrom(out) == "", "expired request_uri yields no code (%s)", out)
			},
		},
	}
}

func tokenTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GTK-01", Spec: spec, Section: "A_22706-02", Title: "Code exchange returns an ID token",
			Expect: "The token endpoint MUST accept AUTHORIZATION_CODE and CODE_VERIFIER (A_22653) and, after successful verification, return an ID token per OpenID Connect Core (A_22706-02) in a JSON token response with Cache-Control: no-store.",
			Run: func(t *suite.T) {
				r := sharedToken(t)
				t.Must(afo("A_22706-02"), r.resp.Status == 200 && isJSONResponse(r.resp.Header), "token response is HTTP 200 JSON (got %s)", r.resp.Summary())
				raw, _ := r.resp.Str("id_token")
				t.Must(afo("A_22706-02"), raw != "", "token response contains id_token")
				cc := strings.ToLower(strings.Join(r.resp.Header.Values("Cache-Control"), ","))
				t.Must("6749/5.1", strings.Contains(cc, "no-store"), "Cache-Control: no-store (got %q)", cc)
				pragma := strings.ToLower(strings.Join(r.resp.Header.Values("Pragma"), ","))
				t.Must("6749/5.1", strings.Contains(pragma, "no-cache"), "Pragma: no-cache (got %q)", pragma)
				tt, _ := r.resp.Str("token_type")
				t.Must("6749/5.1", strings.EqualFold(tt, "Bearer"), "token_type is Bearer (got %q)", tt)
				at, _ := r.resp.Str("access_token")
				t.Should("6749/5.1", at != "", "token response contains access_token (gemSpec_IDP_Sek 3.2.0 step 11; the Fachdienst ignores it)")
			},
		},
		{
			ID: "GTK-02", Spec: spec, Section: "A_23193-01", Title: "ID token is encrypted with ECDH-ES / A256GCM for the Fachdienst",
			Expect: "The IdP MUST encrypt the ID token with an encryption key (use=enc) from the Fachdienst's jwks using ECDH-ES, reference that key with kid in the JWE header (A_23193-01) and use A256GCM content encryption (Table 4).",
			Run: func(t *suite.T) {
				r := sharedToken(t)
				raw := r.token.Raw
				t.Must(afo("A_23193-01"), strings.Count(raw, ".") == 4, "ID token is a compact JWE (5 parts, got %d)", strings.Count(raw, ".")+1)
				h := r.token.JWEHeader
				t.Must(afo("A_23193-01"), hstr(h, "alg") == "ECDH-ES", "JWE alg is ECDH-ES (got %q)", hstr(h, "alg"))
				t.Must(afo("A_22643-02"), hstr(h, "enc") == "A256GCM", "JWE enc is A256GCM (got %q)", hstr(h, "enc"))
				kid := hstr(h, "kid")
				t.Must(afo("A_23193-01"), kid != "", "JWE header references the encryption key with kid")
				// gemSpec_IDP_Sek 3.2.0 Table 47.
				t.Should(afo("A_23193-01"), hstr(h, "cty") == "JWT", "JWE header has cty JWT (nested signed JWT, got %q)", hstr(h, "cty"))
				epk := obj(h["epk"])
				t.Must(afo("A_23337-01"), epk != nil && epk["kty"] == "EC" && (epk["crv"] == "P-256" || epk["crv"] == "P-384"),
					"ephemeral key epk is an EC P-256/P-384 key (got %v)", h["epk"])
				if want := fachdienst(t).EncKeyID; want != "" {
					t.Must(afo("A_23193-01"), kid == want, "kid %q is the Fachdienst's encryption key %q", kid, want)
				}
			},
		},
		{
			ID: "GTK-03", Spec: spec, Section: "A_27713-01", Title: "JWE header states the negotiated ID token version",
			Expect: "The IdP MUST choose the highest ID token version supported by both itself (ti_features_supported) and the Fachdienst (A_27598) and state it in the custom \"version\" claim of the JWE protected header (A_27713-01). For the default version 1.0.0 the claim may be omitted.",
			Run: func(t *suite.T) {
				r := sharedToken(t)
				idp := strList(obj(op(t)["ti_features_supported"])["id_token_version_supported"])
				if len(idp) == 0 {
					idp = []string{"1.0.0"}
				}
				want := ""
				for _, v := range fachdienst(t).IDTokenVersions {
					if slices.Contains(idp, v) && v > want {
						want = v
					}
				}
				got := hstr(r.token.JWEHeader, "version")
				if want == "1.0.0" {
					t.Must(afo("A_27713-01"), got == "" || got == "1.0.0", "version is absent or 1.0.0 (got %q)", got)
				} else {
					t.Must(afo("A_27598"), got == want, "version is the highest common version %q (got %q)", want, got)
				}
			},
		},
		{
			ID: "GTK-04", Spec: spec, Section: "A_22655-03", Title: "ID token is signed with ES256 by a published IdP key with x5c",
			Expect: "The decrypted ID token MUST be signed with ECDSA on P-256 (ES256, A_22983) using a key published under openid_provider.jwks or signed_jwks_uri; its JWS header MUST carry the C.FD.SIG certificate (role oid_idpd_sek) for that key in x5c (A_22655-03).",
			Run: func(t *suite.T) {
				r := decrypted(t)
				h := r.token.JWSHeader
				t.Must(afo("A_22983"), hstr(h, "alg") == "ES256", "JWS alg is ES256 (got %q)", hstr(h, "alg"))
				// gemSpec_IDP_Sek 3.2.0 Table 48: the signature header consists of
				// exactly alg, typ (JWT), kid and x5c.
				t.Must(afo("A_22655-03"), hstr(h, "typ") == "JWT", "JWS typ is JWT (got %q)", hstr(h, "typ"))
				var extra []string
				for k := range h {
					if !slices.Contains([]string{"alg", "typ", "kid", "x5c"}, k) {
						extra = append(extra, k)
					}
				}
				slices.Sort(extra)
				t.Should(afo("A_22655-03"), len(extra) == 0, "JWS header has only alg, typ, kid and x5c (extra: %v)", extra)
				key, err := verifyJWS(r.token.JWS, idpSigningKeys(t))
				t.Must(afo("A_22655-03"), err == nil, "signature verifies with the IdP's published signing keys (%v)", err)
				x5c := strList(h["x5c"])
				if !t.Must(afo("A_22655-03"), len(x5c) > 0, "JWS header contains x5c") {
					return
				}
				der, err := base64.StdEncoding.DecodeString(x5c[0])
				cert, err2 := x509.ParseCertificate(der)
				if !t.Must(afo("A_22655-03"), err == nil && err2 == nil, "x5c[0] is a DER certificate (%v %v)", err, err2) {
					return
				}
				if key != nil {
					pub, _ := key.Key.(*ecdsa.PublicKey)
					cpub, _ := cert.PublicKey.(*ecdsa.PublicKey)
					t.Must(afo("A_22655-03"), pub != nil && cpub != nil && pub.Equal(cpub), "x5c certificate belongs to the signing key %s", key.KeyID)
				}
				t.Logf("signing certificate: subject %s, issuer %s", cert.Subject, cert.Issuer)
				if pool := gcfg(t).IDP.tiPool; pool != nil {
					inter := x509.NewCertPool()
					for _, c := range x5c[1:] {
						if d, err := base64.StdEncoding.DecodeString(c); err == nil {
							if ic, err := x509.ParseCertificate(d); err == nil {
								inter.AddCert(ic)
							}
						}
					}
					_, err := cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
					t.Must(afo("A_22655-03"), err == nil, "certificate chains to the configured TI component PKI (%v)", err)
				}
				if oid := gcfg(t).IDP.SigningCertRoleOID; oid != "" {
					t.Must(afo("A_22655-03"), certHasOID(cert, oid), "certificate contains the technical role OID %s", oid)
				}
			},
		},
		{
			ID: "GTK-05", Spec: spec, Section: "A_22316", Title: "ID token core claims are valid and lifetime is at most 300s",
			Expect: "The IdP MUST NOT issue ID tokens valid for more than 300 seconds (A_22316). As an OpenID Connect ID token (A_22706-02) it must carry iss = the IdP issuer, aud containing the Fachdienst client_id, the nonce from the request, sub, and iat/exp.",
			Run: func(t *suite.T) {
				r := decrypted(t)
				c := r.token.Claims
				iat, okI := numClaim(c, "iat")
				exp, okE := numClaim(c, "exp")
				if t.Must("OIDC-Core/2", okI && okE, "iat and exp are numbers") {
					t.Must(afo("A_22316"), exp-iat <= 300, "exp - iat is at most 300s (got %ds)", exp-iat)
					t.Must("OIDC-Core/3.1.3.7", time.Unix(iat, 0).Before(time.Now().Add(clockSkew)), "iat is not in the future")
				}
				t.Must("OIDC-Core/3.1.3.7", c["iss"] == op(t)["issuer"], "iss %v is the IdP issuer %v", c["iss"], op(t)["issuer"])
				var aud []string
				switch v := c["aud"].(type) {
				case string:
					aud = []string{v}
				default:
					aud = strList(v)
				}
				t.Must("OIDC-Core/3.1.3.7", slices.Contains(aud, fachdienst(t).ClientID), "aud %v contains the client_id", aud)
				t.Must("OIDC-Core/3.1.3.7", c["nonce"] == r.flow.par.nonce, "nonce is returned (sent %q, got %v)", r.flow.par.nonce, c["nonce"])
				sub, _ := c["sub"].(string)
				t.Must("OIDC-Core/2", sub != "", "sub is present")
			},
		},
		{
			ID: "GTK-06", Spec: spec, Section: "A_23129-06", Title: "acr and amr follow the gematik coding",
			Expect: "acr MUST be gematik-ehealth-loa-high or gematik-ehealth-loa-substantial, matching the authentication strength (A_22987, A_22988). amr MUST be a JSON array coded per Table 7 (A_23129-06), and each method must be permitted for the stated acr (e.g. eGK/eID only for loa-high).",
			Run: func(t *suite.T) {
				c := decrypted(t).token.Claims
				acr, _ := c["acr"].(string)
				t.Must(afo("A_22988"), acr == loaHigh || acr == loaSubstantial, "acr is a gematik level (got %q)", acr)
				amr, isArr := c["amr"].([]any)
				if !t.Must(afo("A_23129-06"), isArr && len(amr) > 0, "amr is a non-empty JSON array (got %T)", c["amr"]) {
					return
				}
				for _, v := range strList(c["amr"]) {
					levels, known := amrLevels[v]
					if t.Must(afo("A_23129-06"), known, "amr value %q is defined in Table 7", v) {
						t.Must(afo("A_23129-06"), slices.Contains(levels, acr), "amr %q is permitted for acr %q (allowed: %v)", v, acr, levels)
					}
				}
			},
		},
		{
			ID: "GTK-07", Spec: spec, Section: "A_22989-02", Title: "Insured-person claims use the specified formats",
			Expect: "Claims for insured persons follow Table 6 (A_22989-02): birthdate as YYYY-MM-DD, alter as age in years, geschlecht one of M/W/X/D, profession 1.2.276.0.76.4.49 for insured persons, id the unchangeable part of the KVNR (letter + 9 digits), organization the IK number of the health insurer.",
			Run: func(t *suite.T) {
				c := decrypted(t).token.Claims
				checks := map[string]*regexp.Regexp{
					"birthdate":                         regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`),
					"urn:telematik:claims:alter":        regexp.MustCompile(`^\d{1,3}$`),
					"urn:telematik:claims:geschlecht":   regexp.MustCompile(`^[MWXD]$`),
					"urn:telematik:claims:id":           regexp.MustCompile(`^[A-Z]\d{9}$`),
					"urn:telematik:claims:email":        regexp.MustCompile(`^[^@\s]+@[^@\s]+$`),
					"urn:telematik:claims:display_name": regexp.MustCompile(`\S`),
					"urn:telematik:claims:family_name":  regexp.MustCompile(`\S`),
					"urn:telematik:claims:given_name":   regexp.MustCompile(`\S`),
				}
				n := 0
				for k, re := range checks {
					v, ok := c[k]
					if !ok {
						continue
					}
					n++
					s, isStr := v.(string)
					t.Must(afo("A_22989-02"), isStr && re.MatchString(s), "%s has the specified format (got %v)", k, v)
				}
				if v, ok := c["urn:telematik:claims:profession"]; ok {
					n++
					t.Must(afo("A_22989-02"), v == professionVers, "profession is %s for insured persons (got %v)", professionVers, v)
				}
				if v, ok := c["urn:telematik:claims:organization"]; ok {
					n++
					s, _ := v.(string)
					t.Should(afo("A_22989-02"), regexp.MustCompile(`^\d{9}$`).MatchString(s), "organization is a 9-digit IK number (got %v)", v)
				}
				if n == 0 {
					t.Skipf("the ID token contains no insured-person claims (requested scope: %s)", fachdienst(t).Scope)
				}
			},
		},
		{
			ID: "GTK-08", Spec: spec, Section: "A_22990-01", Title: "ID token contains no claims beyond the requested scopes",
			Expect: "The ID token carries the requested scopes and claims only (A_22706-02); claims of scopes not requested, without a value, or not consented to MUST be suppressed (A_22990-01).",
			Run: func(t *suite.T) {
				r := decrypted(t)
				allowed := append([]string{}, protocolClaims...)
				for _, s := range strings.Fields(fachdienst(t).Scope) {
					allowed = append(allowed, scopeClaims[s]...)
				}
				var extra []string
				for k := range r.token.Claims {
					if !slices.Contains(allowed, k) {
						extra = append(extra, k)
					}
				}
				slices.Sort(extra)
				t.Must(afo("A_22990-01"), len(extra) == 0, "no claims outside the requested scopes (unexpected: %v)", extra)
				for k, v := range r.token.Claims {
					if s, ok := v.(string); ok && s == "" {
						t.Must(afo("A_22990-01"), false, "claim %s is present with an empty value", k)
					}
				}
			},
		},
		{
			ID: "GTK-09", Spec: spec, Section: "A_23197-01", Title: "Pairwise sub is stable for the same Fachdienst",
			Expect: "sub MUST be a pairwise subject identifier (OpenID Connect Core §8.1) that is fixed and unique per insured person and Fachdienst (A_23197-01): logging in twice for the same Fachdienst yields the same sub (except for guest logins with eGK, which use random values).",
			Run: func(t *suite.T) {
				r := decrypted(t)
				fd := fachdienst(t)
				f := runFlow(t, fd, nil)
				resp := redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert)
				raw, _ := resp.Str("id_token")
				tok := decodeIDToken(fd, raw)
				if tok.Err != nil {
					t.Fatalf("second ID token: %v", tok.Err)
				}
				if amr := strList(r.token.Claims["amr"]); slices.Contains(amr, "urn:telematik:auth:guest:eGK") {
					t.Skipf("guest login (urn:telematik:auth:guest:eGK) uses a random sub by design")
				}
				t.Must(afo("A_23197-01"), tok.Claims["sub"] == r.token.Claims["sub"], "sub is identical across logins (%v vs %v)", r.token.Claims["sub"], tok.Claims["sub"])
			},
		},
		{
			ID: "GTK-10", Spec: spec, Section: "A_23197-01", Title: "Pairwise sub differs between Fachdienste",
			Expect: "The pairwise subject of an insured person MUST differ for every Fachdienst (A_23197-01), so that Fachdienste cannot correlate users through sub.",
			Run: func(t *suite.T) {
				r := decrypted(t)
				b := gcfg(t).FachdienstB
				if b == nil {
					t.SkipFixture("fachdienst_b (a second registered Fachdienst) not configured")
				}
				f := runFlow(t, b, nil)
				resp := redeem(t, b, f.code, f.par.pkce.verifier, &b.cert)
				raw, _ := resp.Str("id_token")
				tok := decodeIDToken(b, raw)
				if tok.Err != nil {
					t.Fatalf("ID token for fachdienst_b: %v", tok.Err)
				}
				t.Must(afo("A_23197-01"), tok.Claims["sub"] != r.token.Claims["sub"], "sub differs between %s and %s", fachdienst(t).ClientID, b.ClientID)
			},
		},
		{
			ID: "GTK-16", Spec: spec, Section: "A_27591", Title: "Consent and SSO signalling matches the ID token version",
			Expect: "ID token 1.0.0 signals a substantial-level login for high-protection data with amr urn:telematik:auth:mEW (A_22867-01) and SSO with urn:telematik:auth:sso (A_23207-02). Version 2.0.0 instead uses the custom claims urn:telematik:auth:consent = loa-substantial (A_27591) and urn:telematik:auth:interactive = silent (A_27592), so it must not use the deprecated amr values.",
			Run: func(t *suite.T) {
				r := decrypted(t)
				c := r.token.Claims
				version := hstr(r.token.JWEHeader, "version")
				if version == "" {
					version = "1.0.0"
				}
				amr := strList(c["amr"])
				acr, _ := c["acr"].(string)
				consent, hasConsent := c["urn:telematik:auth:consent"]
				interactive, hasInteractive := c["urn:telematik:auth:interactive"]
				hasConsentValue := func() bool {
					if s, ok := consent.(string); ok {
						return s == "loa-substantial"
					}
					return slices.Contains(strList(consent), "loa-substantial")
				}
				switch version {
				case "2.0.0":
					t.Must(afo("A_27591"), !slices.Contains(amr, "urn:telematik:auth:mEW") && !slices.Contains(amr, "urn:telematik:auth:sso"),
						"version 2.0.0 does not use the deprecated amr values mEW/sso (amr %v)", amr)
					if hasConsent {
						_, isArr := consent.([]any)
						t.Must(afo("A_27591"), isArr, "urn:telematik:auth:consent is a JSON array (gemSpec_IDP_Sek 3.2.0 Table 49, got %T)", consent)
						t.Must(afo("A_27591"), hasConsentValue(), "urn:telematik:auth:consent contains loa-substantial (got %v)", consent)
					}
					if acr == loaSubstantial && fachdienst(t).ACRValues == loaHigh {
						t.Must(afo("A_27591"), hasConsent && hasConsentValue(), "a substantial login for a high-level request carries urn:telematik:auth:consent = loa-substantial")
					}
					if hasInteractive {
						t.Must(afo("A_27592"), interactive == "silent", "urn:telematik:auth:interactive is \"silent\" (got %v)", interactive)
					}
				default:
					t.Must(afo("A_22867-01"), !hasConsent && !hasInteractive, "version 1.0.0 does not use the 2.0.0 custom claims")
					if acr == loaSubstantial && fachdienst(t).ACRValues == loaHigh {
						t.Must(afo("A_22867-01"), slices.Contains(amr, "urn:telematik:auth:mEW"), "a substantial login for a high-level request adds amr urn:telematik:auth:mEW (amr %v)", amr)
					}
				}
				t.Logf("ID token version %s, acr %s, amr %v", version, acr, amr)
			},
		},
		{
			ID: "GTK-17", Spec: spec, Section: "A_24547-01", Title: "acr requested as essential claim is enforced",
			Expect: "A Fachdienst may request the level of assurance through the claims parameter instead of acr_values. If gematik-ehealth-loa-high is requested with essential=true, the IdP MUST NOT use weaker authentication methods and must reject the request if none is available (gemSpec_IDP_Sek 3.2.0 Table 34; A_24547-01 for essential claims).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				claims := `{"id_token":{"acr":{"essential":true,"values":["` + loaHigh + `"]}}}`
				f := runFlow(t, fd, func(v url.Values) {
					v.Del("acr_values")
					v.Set("claims", claims)
				})
				resp := redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert)
				raw, _ := resp.Str("id_token")
				tok := decodeIDToken(fd, raw)
				if tok.Err == errNoEncKey {
					t.SkipFixture("fachdienst.enc_key (to decrypt the ID token) not configured")
				}
				if tok.Err != nil {
					t.Fatalf("ID token: %v (%s)", tok.Err, resp.Summary())
				}
				t.Must(afo("A_24547-01"), tok.Claims["acr"] == loaHigh, "acr is %s when requested as essential (got %v)", loaHigh, tok.Claims["acr"])
			},
		},
		{
			ID: "GTK-11", Spec: spec, Section: "A_23162", Title: "Authorization code can be used only once",
			Expect: "The AUTHORIZATION_CODE MUST be invalidated after one use (A_23162). A second token request with the same code must fail (invalid_grant).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				f := runFlow(t, fd, nil)
				first := redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert)
				if first.Status != 200 {
					t.Fatalf("first redemption failed: %s", first.Summary())
				}
				second := redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert)
				expectRejected(t, second, afo("A_23162"), "second redemption of the code", 0, "invalid_grant")
			},
		},
		{
			ID: "GTK-12", Spec: spec, Section: "A_22321", Title: "Wrong or missing code_verifier is rejected",
			Expect: "The token endpoint MUST verify the CODE_VERIFIER against the CODE_CHALLENGE with S256 (A_22321); only a bit-identical hash proves that caller and initiator are the same. A wrong or missing verifier must be rejected (invalid_grant).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				f := runFlow(t, fd, nil)
				expectRejected(t, redeem(t, fd, f.code, newPKCE().verifier, &fd.cert), afo("A_22321"), "token request with a wrong code_verifier", 0, "invalid_grant")
				expectRejected(t, redeem(t, fd, f.code, "", &fd.cert), afo("A_22321"), "token request without code_verifier", 0, "invalid_grant", "invalid_request")
			},
		},
		{
			ID: "GTK-13", Spec: spec, Section: "A_22654", Title: "Token endpoint requires the Fachdienst's TLS client certificate",
			Expect: "The token endpoint MUST verify the self_signed_tls_client_auth certificate against the Fachdienst's entity statement and its validity (A_22654). Requests without a client certificate or with an unpublished one must be rejected (invalid_client).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				f := runFlow(t, fd, nil)
				expectRejected(t, redeem(t, fd, f.code, f.par.pkce.verifier, nil), afo("A_22654"), "token request without a client certificate", 0, "invalid_client")
				t.Logf("mTLS between Fachdienst and VAU: A_22843, A_22844, A_22864")
				expectRejected(t, redeem(t, fd, f.code, f.par.pkce.verifier, foreignCert(t)), afo("A_22654"), "token request with an unpublished client certificate", 0, "invalid_client")
			},
		},
		{
			ID: "GTK-14", Spec: spec, Section: "A_23007", Title: "Authorization code expires within 90 seconds",
			Tags:   []string{suite.TagSlow},
			Expect: "The validity of an AUTHORIZATION_CODE MUST NOT exceed 90 seconds (A_23007). Redeeming a code after 90 seconds must fail (invalid_grant).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				f := runFlow(t, fd, nil)
				t.Logf("waiting 95s for the code to expire")
				select {
				case <-time.After(95 * time.Second):
				case <-t.Ctx.Done():
					t.Fatalf("interrupted")
				}
				expectRejected(t, redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert), afo("A_23007"), "redemption after 95 seconds", 0, "invalid_grant")
			},
		},
		{
			ID: "GTK-15", Spec: spec, Section: "A_22653", Title: "Invalid token requests get a JSON error response",
			Expect: "gematik probes the token endpoint with invalid requests and expects an error code (§3.3). A token request with an unknown code from an authenticated Fachdienst must be rejected in RFC 6749 §5.2 JSON format (invalid_grant).",
			Run: func(t *suite.T) {
				fd := fachdienst(t)
				expectRejected(t, redeem(t, fd, "ctk-"+randString(), newPKCE().verifier, &fd.cert), afo("A_22653"), "token request with an unknown code", 0, "invalid_grant")
			},
		},
	}
}

// certHasOID reports whether oid appears in the certificate: as an extension
// ID, a policy, or encoded inside an extension value (e.g. the TI admission
// extension 1.3.36.8.3.3, which carries the technical role OIDs).
func certHasOID(cert *x509.Certificate, oid string) bool {
	var parsed asn1.ObjectIdentifier
	for _, part := range strings.Split(oid, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		parsed = append(parsed, n)
	}
	der, err := asn1.Marshal(parsed)
	if err != nil || len(der) < 2 {
		return false
	}
	for _, e := range cert.Extensions {
		if e.Id.Equal(parsed) || bytes.Contains(e.Value, der) {
			return true
		}
	}
	for _, p := range cert.Policies {
		if p.String() == oid {
			return true
		}
	}
	return false
}
