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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
	"github.com/miekg/dns"

	"sekidp-ctk/internal/useragent"
	"sekidp-ctk/internal/yamlenv"
)

// defects switch individual spec violations on in the fake IdP, to prove
// that the corresponding checks detect them.
type defects struct {
	allowPlainPKCE     bool // accept code_challenge_method=plain
	reusableCode       bool // codes can be redeemed twice
	longRequestURI     bool // expires_in 300
	longIDToken        bool // ID token valid 3600s
	wildcardCert       bool // VAU certificate with *.example names
	noVersionHeader    bool // omit the JWE "version" header for 2.0.0
	extraClaim         bool // add a claim of an unrequested scope
	acceptAnyCert      bool // PAR accepts any client certificate
	plainSub           bool // same sub for every Fachdienst
	esTypWrong         bool // entity statement typ "JWT"
	noTiFeatures       bool // omit ti_features_supported
	redirectNoAuth     bool // issue a code without login
	noAppLinks         bool // 404 for app link files
	acrMismatch        bool // amr eGK with acr loa-substantial
	noCertRequest      bool // TLS server does not ask for client certificates
	crashOnInput       bool // 500 on malformed input instead of 400
	deprecatedAmrV2    bool // amr mEW in a 2.0.0 ID token
	notInIDPList       bool // Federation Master's IDP list omits the IdP
	jwsNoTyp           bool // ID token signature header without typ
	ignoreEssentialACR bool // loa-substantial although acr was requested as essential
}

func newUUID7(at time.Time) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	ms := uint64(at.UnixMilli())
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = 0x70 | (b[6] & 0x0f)
	b[8] = 0x80 | (b[8] & 0x3f)
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func mustKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func selfSigned(key *ecdsa.PrivateKey, cn string, dns []string, ips []net.IP, sct bool) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		DNSNames:              dns,
		IPAddresses:           ips,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if sct {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSCTList, Value: []byte{0x04, 0x02, 0x00, 0x00}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func signJWT(key *ecdsa.PrivateKey, kid, typ string, claims any, extra map[jose.HeaderKey]any) string {
	opts := (&jose.SignerOptions{}).WithHeader("kid", kid)
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	for k, v := range extra {
		opts = opts.WithHeader(k, v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := s.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

func pubJWK(key *ecdsa.PrivateKey, kid, use string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Use: use, Algorithm: "ES256"}
}

type fakeClient struct {
	id       string
	redirect string
	scopes   []string
	certDER  []byte
	encPub   *ecdsa.PublicKey
	encKid   string
	versions []string
}

type pushed struct {
	client  string
	params  url.Values
	expires time.Time
}

type issued struct {
	client      string
	challenge   string
	nonce       string
	scope       string
	authTime    bool
	created     time.Time
	used        bool
	redirect    string
	claimsParam string
}

// fakeIDP is a minimal gemSpec_IDP_Sek sector IdP plus Federation Master.
type fakeIDP struct {
	d       defects
	srv     *httptest.Server
	fm      *httptest.Server
	esKey   *ecdsa.PrivateKey
	esKid   string
	sigKey  *ecdsa.PrivateKey
	sigKid  string
	sigCert *x509.Certificate
	fmKey   *ecdsa.PrivateKey
	fmKid   string
	clients map[string]*fakeClient

	mu     sync.Mutex
	pushes map[string]*pushed
	codes  map[string]*issued
	known  map[string]bool // Fachdienste registered automatically after the first PAR
}

func (f *fakeIDP) issuer() string { return f.srv.URL }

func (f *fakeIDP) entityStatement() string {
	now := time.Now()
	op := map[string]any{
		"issuer":                                   f.issuer(),
		"jwks":                                     jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK(f.sigKey, f.sigKid, "sig")}},
		"authorization_endpoint":                   f.issuer() + "/auth",
		"token_endpoint":                           f.issuer() + "/token",
		"pushed_authorization_request_endpoint":    f.issuer() + "/par",
		"organization_name":                        "CTK Test-Krankenkasse",
		"keywords":                                 []string{"product_type_version:3.3.0", "product_type:IDP_Sek"},
		"contacts":                                 []string{"support@ctk.test"},
		"logo_uri":                                 f.issuer() + "/logo.png",
		"client_registration_types_supported":      []string{"automatic"},
		"subject_types_supported":                  []string{"pairwise"},
		"response_types_supported":                 []string{"code"},
		"response_modes_supported":                 []string{"query"},
		"grant_types_supported":                    []string{"authorization_code"},
		"require_pushed_authorization_requests":    true,
		"token_endpoint_auth_methods_supported":    []string{"self_signed_tls_client_auth"},
		"id_token_signing_alg_values_supported":    []string{"ES256"},
		"id_token_encryption_alg_values_supported": []string{"ECDH-ES"},
		"id_token_encryption_enc_values_supported": []string{"A256GCM"},
		"user_type_supported":                      []string{"IP"},
		"claims_parameter_supported":               true,
	}
	scopes := []string{"openid"}
	var claims []string
	for s, cl := range scopeClaims {
		scopes = append(scopes, s)
		claims = append(claims, cl...)
	}
	op["scopes_supported"], op["claims_supported"] = scopes, claims
	if !f.d.noTiFeatures {
		op["ti_features_supported"] = map[string]any{"id_token_version_supported": []string{"1.0.0", "2.0.0"}}
	}
	typ := typEntityStatement
	if f.d.esTypWrong {
		typ = "JWT"
	}
	return signJWT(f.esKey, f.esKid, typ, map[string]any{
		"iss": f.issuer(), "sub": f.issuer(), "iat": now.Unix(), "exp": now.Add(12 * time.Hour).Unix(),
		"jwks":            jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK(f.esKey, f.esKid, "sig")}},
		"authority_hints": []string{f.fm.URL},
		"metadata":        map[string]any{"openid_provider": op},
	}, nil)
}

func jsonError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// authClient implements self_signed_tls_client_auth.
func (f *fakeIDP) authClient(r *http.Request, clientID string) *fakeClient {
	c := f.clients[clientID]
	if c == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	if !f.d.acceptAnyCert && string(r.TLS.PeerCertificates[0].Raw) != string(c.certDER) {
		return nil
	}
	return c
}

func (f *fakeIDP) par(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	_ = r.ParseForm()
	q := r.PostForm
	for _, vs := range q {
		for _, v := range vs {
			if !validInput(v) {
				if f.d.crashOnInput {
					http.Error(w, "internal error", 500)
					return
				}
				jsonError(w, 400, "invalid_request", "malformed parameter")
				return
			}
		}
	}
	c := f.authClient(r, q.Get("client_id"))
	if c == nil {
		jsonError(w, http.StatusUnauthorized, "invalid_client", "unknown client or certificate")
		return
	}
	f.mu.Lock()
	firstContact := !f.known[c.id]
	f.known[c.id] = true
	f.mu.Unlock()
	if firstContact {
		// A_22649: unknown Fachdienst, automatic registration started.
		jsonError(w, http.StatusUnauthorized, "invalid_client", "client not yet registered")
		return
	}
	switch {
	case len(q.Get("nonce")) < 43:
		jsonError(w, 400, "invalid_request", "nonce too short")
		return
	case strings.ContainsAny(q.Get("scope"), "<>"):
		jsonError(w, 400, "invalid_scope", "malformed scope")
		return
	case q.Has("request_uri"):
		jsonError(w, 400, "invalid_request", "request_uri not allowed")
		return
	case q.Get("response_type") != "code":
		jsonError(w, 400, "unsupported_response_type", "only code")
		return
	case q.Get("redirect_uri") != c.redirect:
		jsonError(w, 400, "invalid_request", "redirect_uri not registered")
		return
	case q.Get("code_challenge") == "":
		jsonError(w, 400, "invalid_request", "PKCE required")
		return
	case q.Get("code_challenge_method") != "S256" && !f.d.allowPlainPKCE:
		jsonError(w, 400, "invalid_request", "S256 required")
		return
	}
	for _, s := range strings.Fields(q.Get("scope")) {
		ok := false
		for _, a := range c.scopes {
			ok = ok || a == s
		}
		if !ok {
			jsonError(w, 400, "invalid_scope", "scope not registered: "+s)
			return
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	ru := "urn:ietf:params:oauth:request_uri:" + base64.RawURLEncoding.EncodeToString(b)
	exp := 60
	if f.d.longRequestURI {
		exp = 300
	}
	f.mu.Lock()
	f.pushes[ru] = &pushed{client: c.id, params: q, expires: time.Now().Add(time.Duration(exp) * time.Second)}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": ru, "expires_in": exp})
}

// validInput rejects control characters, invalid UTF-8 and overlong values.
func validInput(v string) bool {
	if len(v) > 4096 || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func code() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func errorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(400)
	fmt.Fprintf(w, "<html><body><h1>Error</h1><p>%s</p></body></html>", msg)
}

func (f *fakeIDP) auth(w http.ResponseWriter, r *http.Request) {
	ru := r.URL.Query().Get("request_uri")
	f.mu.Lock()
	p := f.pushes[ru]
	f.mu.Unlock()
	if p == nil || p.client != r.URL.Query().Get("client_id") || time.Now().After(p.expires) {
		errorPage(w, "invalid or expired request")
		return
	}
	if f.d.redirectNoAuth {
		f.issueCode(w, r, p)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><body><form id="login" method="post" action="/login"><input type="hidden" name="ru" value="%s">
		<input name="username"><input type="password" name="password"><button name="go" value="1">Login</button></form>
		<p>Noch keine App? <a href="https://apps.apple.com/app/ctk">App Store</a> · <a href="https://play.google.com/store/apps/details?id=ctk">Google Play</a></p></body></html>`, ru)
}

func (f *fakeIDP) login(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	p := f.pushes[r.PostForm.Get("ru")]
	if p != nil {
		delete(f.pushes, r.PostForm.Get("ru")) // single use
	}
	f.mu.Unlock()
	if p == nil {
		errorPage(w, "unknown request")
		return
	}
	if r.PostForm.Get("username") != "versicherter" || r.PostForm.Get("password") != "secret" {
		errorPage(w, "wrong credentials")
		return
	}
	f.issueCode(w, r, p)
}

func (f *fakeIDP) issueCode(w http.ResponseWriter, r *http.Request, p *pushed) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)
	f.mu.Lock()
	f.codes[code] = &issued{client: p.client, challenge: p.params.Get("code_challenge"), nonce: p.params.Get("nonce"),
		scope: p.params.Get("scope"), authTime: p.params.Get("prompt") == "login" || p.params.Get("max_age") == "0",
		created: time.Now(), redirect: p.params.Get("redirect_uri"), claimsParam: p.params.Get("claims")}
	f.mu.Unlock()
	http.Redirect(w, r, p.params.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {p.params.Get("state")}}.Encode(), http.StatusSeeOther)
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.PostForm
	if !validInput(q.Get("code")) || !validInput(q.Get("code_verifier")) {
		jsonError(w, 400, "invalid_request", "malformed parameter")
		return
	}
	c := f.authClient(r, q.Get("client_id"))
	if c == nil {
		jsonError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	f.mu.Lock()
	ic := f.codes[q.Get("code")]
	valid := ic != nil && ic.client == c.id && (!ic.used || f.d.reusableCode) && time.Since(ic.created) < 60*time.Second
	if ic != nil {
		ic.used = true
	}
	f.mu.Unlock()
	if !valid || q.Get("redirect_uri") != ic.redirect {
		jsonError(w, 400, "invalid_grant", "invalid code")
		return
	}
	sum := sha256.Sum256([]byte(q.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ic.challenge {
		jsonError(w, 400, "invalid_grant", "PKCE verification failed")
		return
	}
	now := time.Now()
	life := 300 * time.Second
	if f.d.longIDToken {
		life = time.Hour
	}
	subBase := "versicherter|" + c.id
	if f.d.plainSub {
		subBase = "versicherter"
	}
	subSum := sha256.Sum256([]byte(subBase))
	acr := loaHigh
	if f.d.acrMismatch || (f.d.ignoreEssentialACR && strings.Contains(ic.claimsParam, `"acr"`)) {
		acr = loaSubstantial
	}
	claims := map[string]any{
		"iss": f.issuer(), "sub": hex.EncodeToString(subSum[:]), "aud": c.id, "iat": now.Unix(), "exp": now.Add(life).Unix(),
		"nonce": ic.nonce, "acr": acr, "amr": []string{"urn:telematik:auth:eGK"},
	}
	if f.d.deprecatedAmrV2 {
		claims["amr"] = []string{"urn:telematik:auth:eGK", "urn:telematik:auth:mEW"}
	}
	if ic.authTime {
		claims["auth_time"] = now.Unix()
	}
	values := map[string]any{
		"urn:telematik:claims:display_name": "Erika Mustermann", "urn:telematik:claims:profession": professionVers,
		"urn:telematik:claims:id": "X110411675", "urn:telematik:claims:organization": "109500969",
		"birthdate": "1964-08-12", "urn:telematik:claims:geschlecht": "W",
	}
	for _, s := range strings.Fields(ic.scope) {
		for _, cl := range scopeClaims[s] {
			if v, ok := values[cl]; ok {
				claims[cl] = v
			}
		}
	}
	if f.d.extraClaim {
		claims["birthdate"] = "1964-08-12"
	}
	x5c := base64.StdEncoding.EncodeToString(f.sigCert.Raw)
	typ := "JWT"
	if f.d.jwsNoTyp {
		typ = ""
	}
	jws := signJWT(f.sigKey, f.sigKid, typ, claims, map[jose.HeaderKey]any{"x5c": []string{x5c}})

	version := "1.0.0"
	for _, v := range c.versions {
		if v == "2.0.0" {
			version = "2.0.0"
		}
	}
	opts := (&jose.EncrypterOptions{}).WithContentType("JWT")
	if version == "2.0.0" && !f.d.noVersionHeader {
		opts = opts.WithHeader("version", version)
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: c.encPub, KeyID: c.encKid}, opts)
	if err != nil {
		jsonError(w, 500, "server_error", err.Error())
		return
	}
	obj, _ := enc.Encrypt([]byte(jws))
	idt, _ := obj.CompactSerialize()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{"id_token": idt, "access_token": "ctk-ignored-" + code(), "token_type": "Bearer", "expires_in": 300})
}

func (f *fakeIDP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctEntityStatement)
		_, _ = w.Write([]byte(f.entityStatement()))
	})
	mux.HandleFunc("/par", f.par)
	mux.HandleFunc("/auth", f.auth)
	mux.HandleFunc("/login", f.login)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "image/png") })
	for _, p := range []string{"/.well-known/assetlinks.json", "/.well-known/apple-app-site-association"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if f.d.noAppLinks {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		})
	}
	return mux
}

func (f *fakeIDP) fmHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		w.Header().Set("Content-Type", ctEntityStatement)
		_, _ = w.Write([]byte(signJWT(f.fmKey, f.fmKid, typEntityStatement, map[string]any{
			"iss": f.fm.URL, "sub": f.fm.URL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks":     jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK(f.fmKey, f.fmKid, "sig")}},
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": f.fm.URL + "/fetch", "idp_list_endpoint": f.fm.URL + "/idplist"}},
		}, nil)))
	})
	mux.HandleFunc("/idplist", func(w http.ResponseWriter, r *http.Request) {
		entries := []map[string]any{{"iss": "https://other-idp.ctk.test", "organization_name": "Andere Kasse"}}
		if !f.d.notInIDPList {
			entries = append(entries, map[string]any{"iss": f.issuer(), "organization_name": "CTK Test-Krankenkasse", "logo_uri": f.issuer() + "/logo.png", "user_type_supported": []string{"IP"}})
		}
		now := time.Now()
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(signJWT(f.fmKey, f.fmKid, "idp-list+jwt", map[string]any{
			"iss": f.fm.URL, "iat": now.Unix(), "exp": now.Add(24 * time.Hour).Unix(), "idp_entity": entries,
		}, nil)))
	})
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sub") != f.issuer() {
			http.NotFound(w, r)
			return
		}
		now := time.Now()
		w.Header().Set("Content-Type", ctEntityStatement)
		_, _ = w.Write([]byte(signJWT(f.fmKey, f.fmKid, typEntityStatement, map[string]any{
			"iss": f.fm.URL, "sub": f.issuer(), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubJWK(f.esKey, f.esKid, "sig")}},
		}, nil)))
	})
	return mux
}

// startFake starts the fake IdP and returns a matching test kit config.
func startFake(t *testing.T, d defects) (*fakeIDP, *Config) {
	t.Helper()
	f := &fakeIDP{d: d, esKey: mustKey(), sigKey: mustKey(), fmKey: mustKey(), clients: map[string]*fakeClient{},
		pushes: map[string]*pushed{}, codes: map[string]*issued{}, known: map[string]bool{}}
	now := time.Now()
	f.esKid, f.sigKid, f.fmKid = newUUID7(now.Add(-48*time.Hour)), newUUID7(now.Add(-24*time.Hour)), newUUID7(now)
	f.sigCert = selfSigned(f.sigKey, "CTK IDP Sek C.FD.SIG", nil, nil, false)

	tlsKey := mustKey()
	dns := []string{"localhost"}
	if d.wildcardCert {
		dns = append(dns, "*.ctk.test")
	}
	srvCert := selfSigned(tlsKey, "idp.ctk.test", dns, []net.IP{net.ParseIP("127.0.0.1")}, true)
	pool := x509.NewCertPool()
	pool.AddCert(srvCert)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: tlsKey}},
		ClientAuth:   tls.RequestClientCert,
	}
	if d.noCertRequest {
		serverTLS.ClientAuth = tls.NoClientCert
	}
	f.srv = httptest.NewUnstartedServer(f.handler())
	f.srv.TLS = serverTLS
	f.srv.StartTLS()
	f.fm = httptest.NewUnstartedServer(f.fmHandler())
	f.fm.TLS = &tls.Config{Certificates: serverTLS.Certificates}
	f.fm.StartTLS()
	t.Cleanup(func() { f.srv.Close(); f.fm.Close() })

	prevRoots, prevCAA, prevDelay := rootPool, lookupCAA, registrationDelay
	rootPool = func() *x509.CertPool { return pool }
	lookupCAA = fakeCAA
	registrationDelay = 10 * time.Millisecond
	t.Cleanup(func() { rootPool, lookupCAA, registrationDelay = prevRoots, prevCAA, prevDelay })

	mkFD := func(id string) *Fachdienst {
		ck := mustKey()
		cert := selfSigned(ck, id, nil, nil, false)
		ek := mustKey()
		ekid := newUUID7(now)
		f.clients[id] = &fakeClient{id: id, redirect: id + "/callback", certDER: cert.Raw, encPub: &ek.PublicKey, encKid: ekid,
			versions: []string{"1.0.0", "2.0.0"},
			scopes:   []string{"openid", "urn:telematik:display_name", "urn:telematik:versicherter"}}
		return &Fachdienst{ClientID: id, RedirectURI: id + "/callback", Scope: "openid urn:telematik:display_name urn:telematik:versicherter",
			UnregisteredScope: "urn:telematik:geburtsdatum", UnregisteredRedirectURI: id + "/other", ACRValues: loaHigh,
			EncKeyID: ekid, IDTokenVersions: []string{"1.0.0", "2.0.0"},
			cert: tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: ck}, encKey: ek}
	}
	cfg := &Config{
		IDP:              IDP{Name: "fake", EntityID: f.issuer(), EntityStatementURL: f.issuer() + "/.well-known/openid-federation"},
		FederationMaster: &FederationMaster{EntityID: f.fm.URL},
		Fachdienst:       mkFD("https://fd-a.ctk.test"),
		FachdienstB:      mkFD("https://fd-b.ctk.test"),
		Login: Login{Method: "form", Username: "versicherter", Password: "secret", Steps: []useragent.Step{{
			Name: "login", Form: "form#login", Fields: map[string]string{"username": "{{username}}", "password": "{{password}}"}, Submit: "go",
		}}},
		TLS:     TLS{InsecureSkipVerify: true},
		Timeout: yamlenv.Duration{Duration: 10 * time.Second},
	}
	return f, cfg
}

func fakeCAA(host string, _ time.Duration) (string, []*dns.CAA, error) {
	return host + ".", []*dns.CAA{{Tag: "issue", Value: "ctk-ca.test"}}, nil
}
