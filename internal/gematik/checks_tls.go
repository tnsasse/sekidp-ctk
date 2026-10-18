package gematik

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"sekidp-ctk/internal/suite"
)

const cryptoSHA256 = crypto.SHA256

// oidSCTList is the X.509 extension carrying embedded Signed Certificate
// Timestamps (RFC 6962 §3.3).
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type tlsProbe struct {
	Host       string
	VerifyErr  error // verification against the system roots (A_22943)
	State      *tls.ConnectionState
	DialErr    error
	Leaf       *x509.Certificate
	SCTsInTLS  int
	SCTsInCert bool
	// CertRequested is set when the server sent a CertificateRequest.
	CertRequested bool
}

// vauEndpoints are the endpoints that run in the VAU (A_23006, Table 1).
// Fachdienst-facing ones (PAR, token) use mTLS; the authorization endpoint
// is reached by browsers and Authenticator apps, and may live on its own
// host (gematik's reference IdP puts PAR/token on a separate "-mtls" host).
var (
	vauEndpoints  = []string{"authorization_endpoint", "pushed_authorization_request_endpoint", "token_endpoint"}
	mtlsEndpoints = []string{"pushed_authorization_request_endpoint", "token_endpoint"}
)

// addrOf returns host:port of a URL (port 443 by default).
func addrOf(raw string) string {
	u, _ := url.Parse(raw)
	if u.Port() == "" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return u.Host
}

// vauAddrs returns the distinct host:port of the given metadata endpoints.
func vauAddrs(t *suite.T, keys []string) []string {
	var out []string
	for _, k := range keys {
		a := addrOf(endpoint(t, k))
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// vauHost is the host of the PAR endpoint (for DNS checks).
func vauHost(t *suite.T) string {
	return hostOf(endpoint(t, "pushed_authorization_request_endpoint"))
}

// rootPool is the trust store for the A_22943 check (system roots; tests
// may replace it).
var rootPool = func() *x509.CertPool { p, _ := x509.SystemCertPool(); return p }

// probeTLS connects to addr twice: once verifying with the system roots only
// (the CAB Forum requirement), once without verification to inspect the
// certificate. The Fachdienst certificate is offered if the server asks.
func probeTLS(t *suite.T, addr string) *tlsProbe {
	if v, ok := t.Env.Cache.Load("tls:" + addr); ok {
		return v.(*tlsProbe)
	}
	host, _, _ := net.SplitHostPort(addr)
	p := &tlsProbe{Host: host}
	defer t.Env.Cache.Store("tls:"+addr, p)
	dialer := &net.Dialer{Timeout: gcfg(t).Timeout.Duration}
	cert := fdCert(t)
	cfg := &tls.Config{ServerName: host, RootCAs: rootPool()}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		p.CertRequested = true
		if cert != nil {
			return cert, nil
		}
		return &tls.Certificate{}, nil
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err == nil {
		st := conn.ConnectionState()
		p.State = &st
		conn.Close()
	} else {
		p.VerifyErr = err
		cfg.InsecureSkipVerify = true //nolint:gosec // inspection only
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err != nil {
			p.DialErr = err
			return p
		}
		st := conn.ConnectionState()
		p.State = &st
		conn.Close()
	}
	if len(p.State.PeerCertificates) > 0 {
		p.Leaf = p.State.PeerCertificates[0]
		for _, e := range p.Leaf.Extensions {
			if e.Id.Equal(oidSCTList) {
				p.SCTsInCert = true
			}
		}
	}
	p.SCTsInTLS = len(p.State.SignedCertificateTimestamps)
	return p
}

// probes connects to every distinct host of keys; unreachable hosts are
// reported as failures and skipped.
func probes(t *suite.T, keys []string) []*tlsProbe {
	var out []*tlsProbe
	for _, addr := range vauAddrs(t, keys) {
		p := probeTLS(t, addr)
		if !t.Must(afo("A_22250"), p.DialErr == nil && p.Leaf != nil, "TLS connection to %s succeeds with a certificate (%v)", addr, p.DialErr) {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		t.Stop()
	}
	return out
}

// lookupCAA returns the CAA records relevant for host (RFC 8659: the
// closest name up the tree that has CAA records).
var lookupCAA = dnsLookupCAA

func dnsLookupCAA(host string, timeout time.Duration) (string, []*dns.CAA, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		conf = &dns.ClientConfig{Servers: []string{"1.1.1.1"}, Port: "53"}
	}
	c := &dns.Client{Timeout: timeout}
	labels := dns.SplitDomainName(host)
	for i := 0; i < len(labels)-1; i++ {
		name := dns.Fqdn(strings.Join(labels[i:], "."))
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeCAA)
		m.RecursionDesired = true
		var r *dns.Msg
		for _, srv := range conf.Servers {
			r, _, err = c.Exchange(m, net.JoinHostPort(srv, conf.Port))
			if err == nil {
				break
			}
		}
		if err != nil {
			return "", nil, err
		}
		var out []*dns.CAA
		for _, rr := range r.Answer {
			if caa, ok := rr.(*dns.CAA); ok {
				out = append(out, caa)
			}
		}
		if len(out) > 0 {
			return name, out, nil
		}
	}
	return "", nil, nil
}

func infraTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GTL-01", Spec: spec, Section: "A_22943", Title: "VAU TLS certificates are from a publicly trusted (CAB Forum) CA",
			Expect: "The VAU must authenticate to clients with a TLS certificate from an issuer according to the CAB Forum, so that clients can verify it with standard TLS libraries (A_22943). Verification against the operating system's root store must succeed for every VAU host (authorization, PAR and token endpoints).",
			Run: func(t *suite.T) {
				for _, p := range probes(t, vauEndpoints) {
					t.Must(afo("A_22943"), p.VerifyErr == nil, "certificate of %s verifies against the system roots (%v)", p.Host, p.VerifyErr)
					t.Logf("%s: subject %s, issuer %s", p.Host, p.Leaf.Subject, p.Leaf.Issuer)
				}
			},
		},
		{
			ID: "GTL-02", Spec: spec, Section: "A_23006", Title: "VAU endpoints are on dedicated, non-wildcard subdomains",
			Expect: "The authorization, PAR and token endpoints run in the VAU and MUST be offered under a dedicated subdomain that is not a wildcard domain (A_23006), so that Certificate Transparency monitoring by the Federation Master is effective. No VAU host may be served with a wildcard certificate. (Separate hosts for the browser-facing authorization endpoint and the mTLS endpoints are fine; gematik's reference IdP does this.)",
			Run: func(t *suite.T) {
				t.Logf("VAU hosts: %v", vauAddrs(t, vauEndpoints))
				for _, p := range probes(t, vauEndpoints) {
					var wild []string
					for _, n := range p.Leaf.DNSNames {
						if strings.HasPrefix(n, "*.") {
							wild = append(wild, n)
						}
					}
					t.Must(afo("A_23006"), len(wild) == 0, "certificate of %s contains no wildcard names (found %v)", p.Host, wild)
				}
			},
		},
		{
			ID: "GTL-03", Spec: spec, Section: "A_22980", Title: "VAU certificates carry Certificate Transparency SCTs",
			Expect: "VAU TLS certificates MUST come from a CA that supports Certificate Transparency (RFC 6962/9162) (A_22980). Such certificates carry Signed Certificate Timestamps, embedded in the certificate or delivered in the TLS handshake.",
			Run: func(t *suite.T) {
				for _, p := range probes(t, vauEndpoints) {
					t.Must(afo("A_22980"), p.SCTsInCert || p.SCTsInTLS > 0,
						"certificate of %s has SCTs (embedded: %v, in TLS handshake: %d)", p.Host, p.SCTsInCert, p.SCTsInTLS)
				}
			},
		},
		{
			ID: "GTL-04", Spec: spec, Section: "A_22981", Title: "CAA DNS records restrict the issuing CA",
			Expect: "The IdP provider MUST publish Certification Authority Authorization (CAA) DNS records (RFC 6844/8659) for the VAU domains, so that only the intended CA may issue certificates for them (A_22981).",
			Run: func(t *suite.T) {
				var hosts []string
				for _, a := range vauAddrs(t, vauEndpoints) {
					h, _, _ := net.SplitHostPort(a)
					if !slices.Contains(hosts, h) {
						hosts = append(hosts, h)
					}
				}
				for _, host := range hosts {
					name, recs, err := lookupCAA(host, gcfg(t).Timeout.Duration)
					if err != nil {
						t.Fatalf("CAA lookup for %s failed: %v", host, err)
					}
					var issue []string
					for _, r := range recs {
						if r.Tag == "issue" || r.Tag == "issuewild" {
							issue = append(issue, r.Tag+" "+r.Value)
						}
					}
					t.Must(afo("A_22981"), len(issue) > 0, "CAA issue records exist for %s (found at %q: %v)", host, name, issue)
				}
			},
		},
		{
			ID: "GTL-05", Spec: spec, Section: "A_23192", Title: "VAU certificate lifetime is at most 398 days; keys are strong enough",
			Expect: "TLS key pairs MUST be replaced after at most 398 days (A_23192, consistent with CAB Forum rules), so a certificate's validity period may not exceed 398 days. Keys MUST reach a 120-bit security level (P-256/P-384, or RSA >= 3072) (A_23337-01).",
			Run: func(t *suite.T) {
				for _, p := range probes(t, vauEndpoints) {
					life := p.Leaf.NotAfter.Sub(p.Leaf.NotBefore)
					t.Must(afo("A_23192"), life <= 398*24*time.Hour, "certificate of %s is valid for at most 398 days (got %d days)", p.Host, int(life.Hours()/24))
					t.Must(afo("A_23192"), time.Now().Before(p.Leaf.NotAfter), "certificate of %s has not expired (notAfter %s)", p.Host, p.Leaf.NotAfter.UTC())
					desc, ok := keyStrength(p.Leaf.PublicKey)
					t.Must(afo("A_23337-01"), ok, "TLS key of %s (%s) reaches a 120-bit security level", p.Host, desc)
					t.Should(afo("A_22943"), p.State.Version >= tls.VersionTLS12, "%s negotiates TLS 1.2 or later (got %s)", p.Host, tls.VersionName(p.State.Version))
				}
			},
		},
		{
			ID: "GTL-06", Spec: spec, Section: "A_22864", Title: "PAR and token endpoints request a TLS client certificate (mTLS)",
			Expect: "HTTP connections between Fachdienste and the IdP MUST be mTLS connections terminating inside the VAU (A_22864); the VAU communicates with Fachdienste only via mTLS (A_22844). The TLS servers of the Fachdienst-facing endpoints (PAR, token) must therefore ask for a client certificate during the handshake.",
			Run: func(t *suite.T) {
				for _, p := range probes(t, mtlsEndpoints) {
					t.Must(afo("A_22864"), p.CertRequested, "TLS server of %s sends a CertificateRequest", p.Host)
				}
			},
		},
		{
			ID: "GAP-01", Spec: spec, Section: "A_22661", Title: "App Links and Universal Links files are served",
			Expect: "For App2App communication the provider MUST fulfil the OS prerequisites (A_22661): Android App Links (/.well-known/assetlinks.json) and Apple Universal Links (/.well-known/apple-app-site-association) must be served as JSON over https on the domain the Authenticator app is linked to.",
			Run: func(t *suite.T) {
				host := gcfg(t).IDP.AppLinkHost
				if host == "" {
					u, _ := url.Parse(endpoint(t, "authorization_endpoint"))
					host = u.Host
				}
				for _, p := range []string{"/.well-known/assetlinks.json", "/.well-known/apple-app-site-association"} {
					u := "https://" + host + p
					req, _ := http.NewRequestWithContext(t.Ctx, http.MethodGet, u, nil)
					resp, err := t.HTTPClient().Do(req)
					if err != nil {
						t.Must(afo("A_22661"), false, "%s is reachable (%v)", u, err)
						continue
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					resp.Body.Close()
					if !t.Must(afo("A_22661"), resp.StatusCode == 200, "%s is served with HTTP 200 (got HTTP %d)", u, resp.StatusCode) {
						continue
					}
					var v any
					jsonErr := json.Unmarshal(body, &v)
					t.Must(afo("A_22661"), jsonErr == nil, "%s is valid JSON (%v)", u, errOrNil(jsonErr))
				}
			},
		},
	}
}

func errOrNil(err error) string {
	if err == nil {
		return "valid JSON"
	}
	return fmt.Sprintf("invalid JSON: %v", err)
}
