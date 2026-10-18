package gematik

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"sekidp-ctk/internal/suite"
)

const (
	spec = "gemSpec_IDP_Sek"
	// specFD is the Fachdienst usage spec, for checks derived from it.
	specFD = "gemSpec_IDP_FD"
	// OpenID Federation 1.1 section references.
	fed = "OpenID-Federation-1.1"

	typEntityStatement = "entity-statement+jwt"
	ctEntityStatement  = "application/entity-statement+jwt"
)

// afo qualifies a requirement ID for assertions, e.g. afo("A_22643-02").
func afo(id string) string { return spec + "/" + id }

func gcfg(t *suite.T) *Config { return t.Env.Data.(*Config) }

func randString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- JOSE helpers ----

// joseHeader decodes the (protected) header of a compact JWS or JWE.
func joseHeader(compact string) (map[string]any, error) {
	part, _, _ := strings.Cut(compact, ".")
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, fmt.Errorf("header is not base64url: %w", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("header is not JSON: %w", err)
	}
	return h, nil
}

func hstr(h map[string]any, k string) string {
	s, _ := h[k].(string)
	return s
}

// jwtPayload decodes the payload of a compact JWS without verifying it.
func jwtPayload(compact string) (map[string]any, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS must have 3 parts, has %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload is not base64url: %w", err)
	}
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("payload is not a JSON object: %w", err)
	}
	return m, nil
}

// verifyJWS verifies a compact ES256 JWS with the key of the given kid from
// the set. It returns the key used.
func verifyJWS(compact string, set jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	jws, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.PS256, jose.RS256})
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("expected one signature, got %d", len(jws.Signatures))
	}
	kid := jws.Signatures[0].Protected.KeyID
	keys := set.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key with kid %q in the key set", kid)
	}
	if _, err := jws.Verify(keys[0].Key); err != nil {
		return nil, fmt.Errorf("signature does not verify with kid %q: %w", kid, err)
	}
	return &keys[0], nil
}

// parseJWKS converts a JSON value (decoded with UseNumber or not) to a key set.
func parseJWKS(v any) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	raw, err := json.Marshal(v)
	if err != nil {
		return set, err
	}
	err = json.Unmarshal(raw, &set)
	return set, err
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// uuid7Time returns the timestamp of a UUIDv7 (RFC 9562 §5.7), or ok=false.
func uuid7Time(s string) (time.Time, bool) {
	s = strings.ToLower(s)
	if !uuidRe.MatchString(s) {
		return time.Time{}, false
	}
	hexTS := strings.ReplaceAll(s[:13], "-", "")
	var ms int64
	if _, err := fmt.Sscanf(hexTS, "%x", &ms); err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(ms), true
}

// keyStrength checks A_23337-01: ECC keys on P-256/P-384, everything at a
// 120-bit security level (RSA >= 3072 bits per gemSpec_Krypt).
func keyStrength(pub any) (string, bool) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		name := k.Curve.Params().Name
		return "EC " + name, k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return fmt.Sprintf("RSA %d", bits), bits >= 3072
	default:
		return fmt.Sprintf("%T", pub), false
	}
}

func numClaim(m map[string]any, k string) (int64, bool) {
	switch v := m[k].(type) {
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case float64:
		return int64(v), true
	}
	return 0, false
}

func strList(v any) []string {
	var out []string
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// ---- entity statements ----

type entityStatement struct {
	URL         string
	Status      int
	ContentType string
	Raw         string
	Header      map[string]any
	Claims      map[string]any
	JWKS        jose.JSONWebKeySet
	Err         error // fetch or parse error
}

func (es *entityStatement) metadata(kind string) map[string]any {
	return obj(obj(es.Claims["metadata"])[kind])
}

// fetchStatement GETs and parses an entity statement JWT; results are cached
// per URL for the run.
func fetchStatement(t *suite.T, rawURL string) *entityStatement {
	if v, ok := t.Env.Cache.Load("es:" + rawURL); ok {
		return v.(*entityStatement)
	}
	es := &entityStatement{URL: rawURL}
	defer t.Env.Cache.Store("es:"+rawURL, es)
	req, _ := http.NewRequestWithContext(t.Ctx, http.MethodGet, rawURL, nil)
	req.Header.Set("Accept", ctEntityStatement)
	resp, err := t.HTTPClient().Do(req)
	if err != nil {
		es.Err = err
		return es
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	es.Status, es.ContentType, es.Raw = resp.StatusCode, resp.Header.Get("Content-Type"), strings.TrimSpace(string(body))
	if resp.StatusCode != 200 {
		es.Err = fmt.Errorf("HTTP %d", resp.StatusCode)
		return es
	}
	if es.Header, err = joseHeader(es.Raw); err != nil {
		es.Err = err
		return es
	}
	if es.Claims, err = jwtPayload(es.Raw); err != nil {
		es.Err = err
		return es
	}
	es.JWKS, _ = parseJWKS(es.Claims["jwks"])
	return es
}

// idpStatement returns the IdP's entity statement or ends the test.
func idpStatement(t *suite.T) *entityStatement {
	es := fetchStatement(t, gcfg(t).IDP.EntityStatementURL)
	if es.Err != nil {
		t.Fatalf("entity statement %s could not be loaded: %v", es.URL, es.Err)
	}
	return es
}

// op returns metadata.openid_provider of the IdP or ends the test.
func op(t *suite.T) map[string]any {
	m := idpStatement(t).metadata("openid_provider")
	if m == nil {
		t.Fatalf("entity statement has no metadata.openid_provider")
	}
	return m
}

func endpoint(t *suite.T, key string) string {
	ep, _ := op(t)[key].(string)
	if ep == "" {
		t.Fatalf("metadata.openid_provider.%s is missing", key)
	}
	return ep
}

// idpSigningKeys returns the keys the IdP signs ID tokens with: jwks in the
// metadata, or the signed_jwks_uri set (verified with the entity keys).
func idpSigningKeys(t *suite.T) jose.JSONWebKeySet {
	m := op(t)
	if v, ok := m["jwks"]; ok {
		set, err := parseJWKS(v)
		if err != nil {
			t.Fatalf("metadata.openid_provider.jwks is not a JWK set: %v", err)
		}
		return set
	}
	uri, _ := m["signed_jwks_uri"].(string)
	if uri == "" {
		t.Fatalf("metadata.openid_provider has neither jwks nor signed_jwks_uri")
	}
	sj := fetchSignedJWKS(t, uri)
	if sj.Err != nil {
		t.Fatalf("signed_jwks_uri %s: %v", uri, sj.Err)
	}
	return sj.Set
}

type signedJWKS struct {
	Raw    string
	Header map[string]any
	Claims map[string]any
	Set    jose.JSONWebKeySet
	Err    error
}

func fetchSignedJWKS(t *suite.T, uri string) *signedJWKS {
	if v, ok := t.Env.Cache.Load("sjwks:" + uri); ok {
		return v.(*signedJWKS)
	}
	s := &signedJWKS{}
	defer t.Env.Cache.Store("sjwks:"+uri, s)
	req, _ := http.NewRequestWithContext(t.Ctx, http.MethodGet, uri, nil)
	resp, err := t.HTTPClient().Do(req)
	if err != nil {
		s.Err = err
		return s
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		s.Err = fmt.Errorf("HTTP %d", resp.StatusCode)
		return s
	}
	s.Raw = strings.TrimSpace(string(body))
	if s.Header, err = joseHeader(s.Raw); err != nil {
		s.Err = err
		return s
	}
	if s.Claims, err = jwtPayload(s.Raw); err != nil {
		s.Err = err
		return s
	}
	if _, err := verifyJWS(s.Raw, fetchStatement(t, gcfg(t).IDP.EntityStatementURL).JWKS); err != nil {
		s.Err = fmt.Errorf("signature: %w", err)
		return s
	}
	s.Set, err = parseJWKS(map[string]any{"keys": s.Claims["keys"]})
	if err != nil {
		s.Err = err
	}
	return s
}

func isJSONResponse(h http.Header) bool {
	mt, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

// ---- HTTP clients ----

// baseTLS returns the TLS config for connections of the test kit.
func baseTLS(c *Config) *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: c.TLS.InsecureSkipVerify} //nolint:gosec // opt-in for test environments
	if c.TLS.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if raw, err := os.ReadFile(c.TLS.CAFile); err == nil {
			pool.AppendCertsFromPEM(raw)
		}
		cfg.RootCAs = pool
	}
	return cfg
}

// NewTransport builds the default transport (no client certificate).
func NewTransport(c *Config) http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = baseTLS(c)
	tr.ResponseHeaderTimeout = c.Timeout.Duration
	return tr
}

// mtlsClient returns a recording, non-redirecting client presenting cert.
// A nil cert means no client certificate.
func mtlsClient(t *suite.T, cert *tls.Certificate) *http.Client {
	c := gcfg(t)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = baseTLS(c)
	if cert != nil {
		cc := *cert
		tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cc, nil }
	}
	tr.ResponseHeaderTimeout = c.Timeout.Duration
	return &http.Client{
		Transport:     t.Record(tr),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
