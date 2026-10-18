package gematik

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"sekidp-ctk/internal/oauth"
	"sekidp-ctk/internal/suite"
	"sekidp-ctk/internal/useragent"
)

func fachdienst(t *suite.T) *Fachdienst {
	fd := gcfg(t).Fachdienst
	if fd == nil {
		t.SkipFixture("fachdienst (a registered test Fachdienst with TLS client certificate) not configured")
	}
	return fd
}

// fdCert returns the Fachdienst's TLS client certificate, or nil.
func fdCert(t *suite.T) *tls.Certificate {
	if fd := gcfg(t).Fachdienst; fd != nil {
		return &fd.cert
	}
	return nil
}

// foreignCert creates a fresh self-signed certificate that is not published
// in any entity statement.
func foreignCert(t *suite.T) *tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "sekidp-ctk foreign client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a test certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type pkcePair struct{ verifier, challenge string }

func newPKCE() pkcePair {
	v := randString() + randString()
	sum := sha256.Sum256([]byte(v))
	return pkcePair{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// parRequest is a pushed authorization request of a Fachdienst.
type parRequest struct {
	fd           *Fachdienst
	params       url.Values
	pkce         pkcePair
	state, nonce string
}

func newPAR(fd *Fachdienst) *parRequest {
	// A_24833-01 (gemSpec_IDP_FD): nonce and code_verifier are random strings
	// of 43 to 128 characters.
	p := &parRequest{fd: fd, pkce: newPKCE(), state: randString() + randString(), nonce: randString() + randString()}
	p.params = url.Values{
		"client_id":             {fd.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {fd.RedirectURI},
		"scope":                 {fd.Scope},
		"state":                 {p.state},
		"nonce":                 {p.nonce},
		"code_challenge":        {p.pkce.challenge},
		"code_challenge_method": {"S256"},
		"acr_values":            {fd.ACRValues},
	}
	return p
}

// send pushes the request presenting cert (nil: no client certificate).
//
// When the registered Fachdienst pushes with its own certificate and the IdP
// answers 401, the IdP did not know the Fachdienst yet and has started the
// automatic registration (A_22649, A_22650-01); the Fachdienst MUST repeat
// the request (gemSpec_IDP_FD A_23500), so it is retried once.
func (p *parRequest) send(t *suite.T, cert *tls.Certificate) *oauth.Response {
	do := func() *oauth.Response {
		resp, err := oauth.Do(t.Ctx, mtlsClient(t, cert), oauth.TokenRequest{
			Endpoint: endpoint(t, "pushed_authorization_request_endpoint"),
			Form:     p.params,
		})
		if err != nil {
			t.Fatalf("PAR request failed: %v", err)
		}
		return resp
	}
	resp := do()
	registered := cert == &p.fd.cert && p.params.Get("client_id") == p.fd.ClientID
	if resp.Status == 401 && registered {
		if _, retried := t.Env.Cache.LoadOrStore("par-retried:"+p.fd.ClientID, true); !retried {
			t.Logf("first PAR answered 401: repeating it after automatic registration (gemSpec_IDP_FD A_23500)")
			time.Sleep(registrationDelay)
			resp = do()
		}
	}
	return resp
}

// registrationDelay is the pause before repeating a PAR that was answered
// with 401 during automatic registration.
var registrationDelay = 2 * time.Second

// ensureRegistered makes sure the IdP knows the Fachdienst before negative
// checks run: a first valid PAR may be answered with 401 while automatic
// registration happens (A_22649, gemSpec_IDP_FD A_23500), which must not be
// mistaken for a rejection caused by the condition under test.
func ensureRegistered(t *suite.T, fd *Fachdienst) {
	if _, done := t.Env.Cache.Load("registered:" + fd.ClientID); done {
		return
	}
	r := newPAR(fd).send(t, &fd.cert)
	if r.Status != 201 {
		t.Fatalf("the Fachdienst cannot push a valid request (needed before this negative check): %s", r.Summary())
	}
	t.Env.Cache.Store("registered:"+fd.ClientID, true)
}

// pushOK sends the request with the Fachdienst certificate and returns the
// request_uri, ending the test if the push fails.
func (p *parRequest) pushOK(t *suite.T) (string, *oauth.Response) {
	r := p.send(t, &p.fd.cert)
	ru, _ := r.Str("request_uri")
	if r.Status != 201 || ru == "" {
		t.Fatalf("pushed authorization request was not accepted: %s", r.Summary())
	}
	return ru, r
}

func authURL(t *suite.T, clientID, requestURI string) string {
	return oauth.AppendQuery(endpoint(t, "authorization_endpoint"), url.Values{"client_id": {clientID}, "request_uri": {requestURI}})
}

// requireLogin skips flows that need an authenticated user when no login is
// configured.
func requireLogin(t *suite.T) Authenticator {
	a := newAuthenticator(gcfg(t).Login, false)
	if !a.Interactive() {
		t.SkipFixture("login.steps (a scripted login with a test identity) not configured")
	}
	return a
}

// authorize drives the authorization endpoint. With login=false no
// authentication is attempted (redirects are only followed).
func authorize(t *suite.T, fd *Fachdienst, rawURL string, login bool) *useragent.Outcome {
	a := newAuthenticator(gcfg(t).Login, !login)
	if login {
		a = requireLogin(t)
	}
	var stops []string
	for _, f := range []*Fachdienst{gcfg(t).Fachdienst, gcfg(t).FachdienstB, fd} {
		if f == nil {
			continue
		}
		for _, r := range []string{f.RedirectURI, f.UnregisteredRedirectURI} {
			if u, err := url.Parse(r); err == nil && r != "" {
				stops = append(stops, useragent.Origin(u))
			}
		}
	}
	out, err := a.Authenticate(t.Ctx, t.Transport(), rawURL, stops)
	if err != nil {
		t.Fatalf("driving the authorization endpoint: %v", err)
	}
	t.Logf("authorization: steps=%v, %s", out.StepsUsed, out)
	return out
}

func codeFrom(out *useragent.Outcome) string {
	if out.Redirect == nil {
		return ""
	}
	return out.Redirect.Query().Get("code")
}

// flow is a completed PAR + authorization.
type flow struct {
	par        *parRequest
	requestURI string
	out        *useragent.Outcome
	code       string
}

// runFlow pushes a request (modified by mod) and authenticates the user. It
// ends the test if no code is issued.
func runFlow(t *suite.T, fd *Fachdienst, mod func(url.Values)) *flow {
	requireLogin(t)
	p := newPAR(fd)
	if mod != nil {
		mod(p.params)
	}
	ru, _ := p.pushOK(t)
	out := authorize(t, fd, authURL(t, fd.ClientID, ru), true)
	code := codeFrom(out)
	if code == "" {
		t.Fatalf("no authorization code issued: %s", out)
	}
	return &flow{par: p, requestURI: ru, out: out, code: code}
}

// redeem exchanges a code at the token endpoint.
func redeem(t *suite.T, fd *Fachdienst, code, verifier string, cert *tls.Certificate) *oauth.Response {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {fd.RedirectURI},
		"client_id":    {fd.ClientID},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	resp, err := oauth.Do(t.Ctx, mtlsClient(t, cert), oauth.TokenRequest{Endpoint: endpoint(t, "token_endpoint"), Form: form})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	return resp
}

// idToken is a decoded sector IdP ID token (JWE containing a signed JWT).
type idToken struct {
	Raw       string
	JWEHeader map[string]any
	JWS       string
	JWSHeader map[string]any
	Claims    map[string]any
	Err       error // decryption / parsing failure
}

func decodeIDToken(fd *Fachdienst, raw string) *idToken {
	tok := &idToken{Raw: raw}
	var err error
	if tok.JWEHeader, err = joseHeader(raw); err != nil {
		tok.Err = err
		return tok
	}
	if fd.encKey == nil {
		tok.Err = errNoEncKey
		return tok
	}
	jwe, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		tok.Err = err
		return tok
	}
	plain, err := jwe.Decrypt(fd.encKey)
	if err != nil {
		tok.Err = err
		return tok
	}
	tok.JWS = strings.TrimSpace(string(plain))
	if tok.JWSHeader, err = joseHeader(tok.JWS); err != nil {
		tok.Err = err
		return tok
	}
	tok.Claims, tok.Err = jwtPayload(tok.JWS)
	return tok
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoEncKey = errString("fachdienst.enc_key not configured")

// tokenResult is a successful flow with its token response, shared by the
// ID token content checks.
type tokenResult struct {
	flow  *flow
	resp  *oauth.Response
	token *idToken
}

// sharedToken runs one complete flow per run and caches the result.
func sharedToken(t *suite.T) *tokenResult {
	if v, ok := t.Env.Cache.Load("token"); ok {
		return v.(*tokenResult)
	}
	// Only successful flows are cached; a failure is retried (and reported)
	// by each test that needs the token.
	fd := fachdienst(t)
	f := runFlow(t, fd, nil)
	resp := redeem(t, fd, f.code, f.par.pkce.verifier, &fd.cert)
	raw, _ := resp.Str("id_token")
	if resp.Status != 200 || raw == "" {
		t.Fatalf("token request failed: %s", resp.Summary())
	}
	r := &tokenResult{flow: f, resp: resp, token: decodeIDToken(fd, raw)}
	t.Env.Cache.Store("token", r)
	return r
}

// decrypted returns the shared ID token claims or skips when no enc key.
func decrypted(t *suite.T) *tokenResult {
	r := sharedToken(t)
	if r.token.Err == errNoEncKey {
		t.SkipFixture("fachdienst.enc_key (to decrypt the ID token) not configured")
	}
	if r.token.Err != nil {
		t.Fatalf("ID token could not be decrypted/parsed: %v", r.token.Err)
	}
	return r
}
