package gematik

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"sekidp-ctk/internal/suite"
)

// Scopes and claims an IdP for insured persons must support (A_22989-02).
var scopeClaims = map[string][]string{
	"urn:telematik:geburtsdatum": {"birthdate"},
	"urn:telematik:alter":        {"urn:telematik:claims:alter"},
	"urn:telematik:display_name": {"urn:telematik:claims:display_name"},
	"urn:telematik:family_name":  {"urn:telematik:claims:family_name"},
	"urn:telematik:given_name":   {"urn:telematik:claims:given_name"},
	"urn:telematik:geschlecht":   {"urn:telematik:claims:geschlecht"},
	"urn:telematik:email":        {"urn:telematik:claims:email"},
	"urn:telematik:versicherter": {"urn:telematik:claims:profession", "urn:telematik:claims:id", "urn:telematik:claims:organization"},
}

var orgNameRe = regexp.MustCompile(`^[à-üÀ-Üß\w\ \-\.\+\*\/]{1,128}$`)

const clockSkew = 2 * time.Minute

// exactly reports whether list consists of exactly the allowed values.
func exactly(list []string, allowed ...string) bool {
	if len(list) == 0 {
		return false
	}
	for _, v := range list {
		if !slices.Contains(allowed, v) {
			return false
		}
	}
	return true
}

func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && u.Host != ""
}

func entityStatementTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GES-01", Spec: spec, Section: "A_22643-02", Title: "Self-signed entity statement is published",
			Expect: "The sector IdP MUST publish a self-signed entity statement per OpenID Federation 1.1 at <entity_id>/.well-known/openid-federation, served over https as application/entity-statement+jwt.",
			Run: func(t *suite.T) {
				es := fetchStatement(t, gcfg(t).IDP.EntityStatementURL)
				if !t.Must(afo("A_22643-02"), es.Err == nil, "entity statement %s is retrievable and a JWT (%v)", es.URL, es.Err) {
					return
				}
				t.Must(afo("A_22250"), strings.HasPrefix(es.URL, "https://"), "entity statement is served over https")
				mt := strings.TrimSpace(strings.Split(es.ContentType, ";")[0])
				t.Must(fed+"/9", mt == ctEntityStatement, "Content-Type is %s (got %q)", ctEntityStatement, es.ContentType)
			},
		},
		{
			ID: "GES-02", Spec: spec, Section: "A_22643-02", Title: "Entity statement header: ES256, entity-statement+jwt, UUID7 kid",
			Expect: "Table 2 fixes the JWS header of the entity statement: alg MUST be ES256, typ MUST be entity-statement+jwt and kid MUST be a UUIDv7 (RFC 9562) identifying the signing key.",
			Run: func(t *suite.T) {
				h := idpStatement(t).Header
				t.Must(afo("A_22643-02"), hstr(h, "alg") == "ES256", "alg is ES256 (got %q)", hstr(h, "alg"))
				t.Must(afo("A_22643-02"), hstr(h, "typ") == typEntityStatement, "typ is %s (got %q)", typEntityStatement, hstr(h, "typ"))
				_, ok := uuid7Time(hstr(h, "kid"))
				t.Must(afo("A_28195"), ok, "kid %q is a UUIDv7", hstr(h, "kid"))
			},
		},
		{
			ID: "GES-03", Spec: spec, Section: "A_22643-02", Title: "Entity statement signature verifies with its own jwks",
			Expect: "An entity configuration is self-signed: its signature MUST verify with the key identified by kid in its own top-level jwks (OpenID Federation 1.1). Otherwise relying parties cannot trust any of its metadata.",
			Run: func(t *suite.T) {
				es := idpStatement(t)
				key, err := verifyJWS(es.Raw, es.JWKS)
				if t.Must(fed+"/3", err == nil, "signature verifies with the entity statement's jwks (%v)", err) {
					t.Logf("signed with kid %s", key.KeyID)
				}
			},
		},
		{
			ID: "GES-04", Spec: spec, Section: "A_22643-02", Title: "iss and sub equal the entity identifier; iat and exp are valid",
			Expect: "In an entity configuration, iss and sub MUST both be the entity identifier (an https URL), and iat/exp MUST be numeric timestamps (seconds since 1970) with the current time between them.",
			Run: func(t *suite.T) {
				c := idpStatement(t).Claims
				want := gcfg(t).IDP.EntityID
				iss, _ := c["iss"].(string)
				sub, _ := c["sub"].(string)
				t.Must(afo("A_22643-02"), iss == want, "iss %q equals entity_id %q", iss, want)
				t.Must(afo("A_22643-02"), sub == iss, "sub %q equals iss", sub)
				iat, okI := numClaim(c, "iat")
				exp, okE := numClaim(c, "exp")
				if t.Must(afo("A_22643-02"), okI && okE, "iat and exp are numbers") {
					now := time.Now()
					t.Must(afo("A_22643-02"), !time.Unix(iat, 0).After(now.Add(clockSkew)), "iat %s is not in the future", time.Unix(iat, 0).UTC())
					t.Must(afo("A_22643-02"), time.Unix(exp, 0).After(now), "entity statement has not expired (exp %s)", time.Unix(exp, 0).UTC())
				}
			},
		},
		{
			ID: "GES-05", Spec: spec, Section: "A_23010", Title: "Entity statement is valid for at most 24 hours and reissued daily",
			Expect: "The validity of the IdP's entity statement (exp - iat) MUST NOT exceed 24 hours (A_23010), and it MUST be reissued every day (A_22711), so iat may be at most 24 hours old.",
			Run: func(t *suite.T) {
				c := idpStatement(t).Claims
				iat, okI := numClaim(c, "iat")
				exp, okE := numClaim(c, "exp")
				if !okI || !okE {
					t.Fatalf("iat/exp missing")
				}
				t.Must(afo("A_23010"), exp-iat <= 24*3600, "exp - iat is at most 24h (got %s)", time.Duration(exp-iat)*time.Second)
				age := time.Since(time.Unix(iat, 0))
				t.Must(afo("A_22711"), age <= 24*time.Hour+clockSkew, "entity statement was issued within the last 24h (iat is %s old)", age.Round(time.Minute))
			},
		},
		{
			ID: "GES-06", Spec: spec, Section: "A_28195", Title: "All keys have UUIDv7 key IDs reflecting their creation time",
			Expect: "Every key the IdP publishes in JWKS format MUST have a kid in UUIDv7 format (RFC 9562) that encodes the key's creation time (A_28195). This applies to the entity jwks and to the ID token signing keys (openid_provider jwks or signed_jwks_uri).",
			Run: func(t *suite.T) {
				es := idpStatement(t)
				keys := append(es.JWKS.Keys, idpSigningKeys(t).Keys...)
				for _, k := range keys {
					ts, ok := uuid7Time(k.KeyID)
					if t.Must(afo("A_28195"), ok, "kid %q is a UUIDv7", k.KeyID) {
						t.Must(afo("A_28195"), ts.Before(time.Now().Add(clockSkew)), "kid %q encodes a creation time in the past (%s)", k.KeyID, ts.UTC())
					}
				}
			},
		},
		{
			ID: "GES-07", Spec: spec, Section: "A_23192", Title: "Signing keys are at most 398 days old",
			Expect: "Key pairs used to sign entity statements or ID tokens MUST be replaced after at most 398 days (A_23192). The key age is derived from the creation time encoded in the UUIDv7 kid (A_28195).",
			Run: func(t *suite.T) {
				es := idpStatement(t)
				for _, k := range append(es.JWKS.Keys, idpSigningKeys(t).Keys...) {
					ts, ok := uuid7Time(k.KeyID)
					if !ok {
						t.Logf("kid %q is not a UUIDv7; age unknown (see GES-06)", k.KeyID)
						continue
					}
					age := time.Since(ts)
					t.Must(afo("A_23192"), age <= 398*24*time.Hour, "key %s is %d days old (max 398)", k.KeyID, int(age.Hours()/24))
				}
			},
		},
		{
			ID: "GES-08", Spec: spec, Section: "A_23337-01", Title: "Keys use P-256/P-384 or reach a 120-bit security level",
			Expect: "All keys of the sector IdP MUST provide a 120-bit security level, and ECC keys MUST use the curves P-256 or P-384 (A_23337-01). ID token signatures MUST use ECDSA on P-256 (A_22983).",
			Run: func(t *suite.T) {
				es := idpStatement(t)
				for _, k := range append(es.JWKS.Keys, idpSigningKeys(t).Keys...) {
					desc, ok := keyStrength(k.Key)
					t.Must(afo("A_23337-01"), ok, "key %s (%s) is P-256/P-384 or at least 120-bit strength", k.KeyID, desc)
				}
			},
		},
		{
			ID: "GES-09", Spec: spec, Section: "A_22643-02", Title: "authority_hints and metadata.openid_provider are present",
			Expect: "The entity statement MUST contain authority_hints (the superior entities, i.e. the Federation Master) and a metadata block of type openid_provider whose issuer equals iss (Tables 3 and 4).",
			Run: func(t *suite.T) {
				c := idpStatement(t).Claims
				hints := strList(c["authority_hints"])
				t.Must(afo("A_22643-02"), len(hints) > 0, "authority_hints is a non-empty list (got %v)", c["authority_hints"])
				for _, h := range hints {
					t.Must(afo("A_22643-02"), isURL(h), "authority hint %q is a URL", h)
				}
				m := idpStatement(t).metadata("openid_provider")
				if !t.Must(afo("A_22643-02"), m != nil, "metadata.openid_provider is present") {
					return
				}
				issuer, _ := m["issuer"].(string)
				t.Must(afo("A_22643-02"), issuer == c["iss"], "openid_provider.issuer %q equals iss %v", issuer, c["iss"])
			},
		},
		{
			ID: "GES-10", Spec: spec, Section: "A_22643-02", Title: "Exactly one of jwks or signed_jwks_uri, and it is valid",
			Expect: "metadata.openid_provider MUST contain either jwks or signed_jwks_uri, not both (Table 4, OpenID Federation 1.1). A signed_jwks_uri must serve a JWS signed with the entity keys whose key set is usable for ID token verification.",
			Run: func(t *suite.T) {
				m := op(t)
				_, hasJWKS := m["jwks"]
				uri, hasURI := m["signed_jwks_uri"].(string)
				t.Must(afo("A_22643-02"), hasJWKS != hasURI, "exactly one of jwks / signed_jwks_uri is present (jwks: %v, signed_jwks_uri: %v)", hasJWKS, hasURI)
				if hasURI {
					sj := fetchSignedJWKS(t, uri)
					if t.Must(fed+"/5.2.1", sj.Err == nil, "signed_jwks_uri %s returns a JWS signed by the entity keys (%v)", uri, sj.Err) {
						t.Must(fed+"/5.2.1", len(sj.Set.Keys) > 0, "signed JWK set contains keys")
						typ := hstr(sj.Header, "typ")
						// gemSpec_IDP_Sek 3.2.0 Table 29 uses jwk-set+json and asks receivers
						// to accept jwk-set+jwt (current OpenID Federation) as well.
						t.Should(fed+"/5.2.1", typ == "jwk-set+json" || typ == "jwk-set+jwt", "signed JWK set has typ jwk-set+json or jwk-set+jwt (got %q)", typ)
						t.Should(fed+"/5.2.1", sj.Claims["iss"] == gcfg(t).IDP.EntityID, "signed JWK set iss is the entity identifier (got %v)", sj.Claims["iss"])
					}
				}
				if hasJWKS {
					set, err := parseJWKS(m["jwks"])
					t.Must(afo("A_22643-02"), err == nil && len(set.Keys) > 0, "openid_provider.jwks is a non-empty JWK set (%v)", err)
				}
			},
		},
		{
			ID: "GES-11", Spec: spec, Section: "A_22643-02", Title: "Endpoint URLs are present and use https",
			Expect: "authorization_endpoint, token_endpoint and pushed_authorization_request_endpoint MUST be published in openid_provider metadata (Table 4, A_22651) as https URLs, since all interfaces must be protected against eavesdropping and manipulation (A_22250).",
			Run: func(t *suite.T) {
				m := op(t)
				for _, k := range []string{"authorization_endpoint", "token_endpoint", "pushed_authorization_request_endpoint"} {
					v, _ := m[k].(string)
					if t.Must(afo("A_22643-02"), isURL(v), "%s is a URL (got %q)", k, v) {
						t.Must(afo("A_22250"), strings.HasPrefix(v, "https://"), "%s uses https", k)
					}
				}
			},
		},
		{
			ID: "GES-12", Spec: spec, Section: "A_22643-02", Title: "Informational metadata: organization_name, keywords, contacts, logo_uri",
			Expect: "Table 4 requires organization_name matching ^[à-üÀ-Üß\\w\\ \\-\\.\\+\\*\\/]{1,128}$, keywords containing \"product_type_version:<version>\" and \"product_type:<type>\", contacts containing a support e-mail address and a logo_uri pointing to a .png file.",
			Run: func(t *suite.T) {
				m := op(t)
				name, _ := m["organization_name"].(string)
				t.Must(afo("A_22643-02"), orgNameRe.MatchString(name), "organization_name %q matches the allowed pattern", name)
				kw := strList(m["keywords"])
				hasPrefix := func(p string) bool {
					return slices.ContainsFunc(kw, func(s string) bool { return strings.HasPrefix(s, p) && len(s) > len(p) })
				}
				t.Must(afo("A_22643-02"), hasPrefix("product_type_version:"), "keywords contain product_type_version:<version> (got %v)", kw)
				t.Must(afo("A_22643-02"), hasPrefix("product_type:"), "keywords contain product_type:<type> (got %v)", kw)
				contacts := strList(m["contacts"])
				t.Must(afo("A_22643-02"), slices.ContainsFunc(contacts, func(s string) bool { return strings.Contains(s, "@") }),
					"contacts contain a support e-mail address (got %v)", contacts)
				logo, _ := m["logo_uri"].(string)
				u, err := url.Parse(logo)
				t.Must(afo("A_22643-02"), isURL(logo) && err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".png"), "logo_uri %q is a URL of a .png file", logo)
			},
		},
		{
			ID: "GES-13", Spec: spec, Section: "A_22643-02", Title: "Protocol metadata has exactly the allowed values",
			Expect: "Table 4 allows only these values: client_registration_types_supported [\"automatic\"], subject_types_supported [\"pairwise\"], response_types_supported [\"code\"], response_modes_supported [\"query\"], grant_types_supported [\"authorization_code\"], require_pushed_authorization_requests true, user_type_supported [\"IP\"].",
			Run: func(t *suite.T) {
				m := op(t)
				for key, allowed := range map[string]string{
					"client_registration_types_supported": "automatic",
					"subject_types_supported":             "pairwise",
					"response_types_supported":            "code",
					"response_modes_supported":            "query",
					"grant_types_supported":               "authorization_code",
					"user_type_supported":                 "IP",
				} {
					got := strList(m[key])
					t.Must(afo("A_22643-02"), exactly(got, allowed), "%s is [%q] (got %v)", key, allowed, m[key])
				}
				req, _ := m["require_pushed_authorization_requests"].(bool)
				t.Must(afo("A_22643-02"), req, "require_pushed_authorization_requests is true (got %v)", m["require_pushed_authorization_requests"])
			},
		},
		{
			ID: "GES-14", Spec: spec, Section: "A_22643-02", Title: "Client auth and ID token crypto metadata",
			Expect: "Table 4 requires token_endpoint_auth_methods_supported to contain self_signed_tls_client_auth, id_token_signing_alg_values_supported ES256, id_token_encryption_alg_values_supported ECDH-ES and id_token_encryption_enc_values_supported A256GCM.",
			Run: func(t *suite.T) {
				m := op(t)
				for key, want := range map[string]string{
					"token_endpoint_auth_methods_supported":    "self_signed_tls_client_auth",
					"id_token_signing_alg_values_supported":    "ES256",
					"id_token_encryption_alg_values_supported": "ECDH-ES",
					"id_token_encryption_enc_values_supported": "A256GCM",
				} {
					got := strList(m[key])
					t.Must(afo("A_22643-02"), slices.Contains(got, want), "%s contains %q (got %v)", key, want, m[key])
				}
			},
		},
		{
			ID: "GES-15", Spec: spec, Section: "A_22989-02", Title: "Scopes and claims for insured persons are advertised",
			Expect: "An IdP for insured persons MUST support the scopes and claims of Table 6 (A_22989-02) and signal them: scopes_supported contains openid and the urn:telematik scopes, claims_supported lists the supported claims (A_24403), and claims_parameter_supported is true because the claims parameter MUST be processed (A_24404).",
			Run: func(t *suite.T) {
				m := op(t)
				scopes := strList(m["scopes_supported"])
				t.Must(afo("A_22643-02"), slices.Contains(scopes, "openid"), "scopes_supported contains openid")
				claims := strList(m["claims_supported"])
				for scope, cl := range scopeClaims {
					t.Must(afo("A_22989-02"), slices.Contains(scopes, scope), "scopes_supported contains %s", scope)
					for _, c := range cl {
						t.Must(afo("A_24403"), slices.Contains(claims, c), "claims_supported contains %s", c)
					}
				}
				cps, _ := m["claims_parameter_supported"].(bool)
				t.Must(afo("A_24404"), cps, "claims_parameter_supported is true (got %v)", m["claims_parameter_supported"])
			},
		},
		{
			ID: "GES-16", Spec: spec, Section: "A_27506", Title: "ti_features_supported signals both ID token versions",
			Expect: "The IdP MUST signal the supported TI federation features in openid_provider.ti_features_supported (A_27506). During the transition it must support ID token versions 1.0.0 and 2.0.0, so id_token_version_supported lists exactly those (Table 5).",
			Run: func(t *suite.T) {
				tf := obj(op(t)["ti_features_supported"])
				if !t.Must(afo("A_27506"), tf != nil, "openid_provider.ti_features_supported is present") {
					return
				}
				v := strList(tf["id_token_version_supported"])
				t.Must(afo("A_27506"), exactly(v, "1.0.0", "2.0.0"), "id_token_version_supported only contains 1.0.0/2.0.0 (got %v)", tf["id_token_version_supported"])
				t.Must(afo("A_27506"), slices.Contains(v, "1.0.0") && slices.Contains(v, "2.0.0"), "both 1.0.0 and 2.0.0 are supported (got %v)", v)
			},
		},
		{
			ID: "GES-17", Spec: spec, Section: "A_22644", Title: "URLs offered in the entity statement are reachable",
			Expect: "The IdP MUST check hourly that every URL it offers in its entity statement is reachable (A_22644). From outside this means each advertised URL (endpoints, signed_jwks_uri, logo_uri) answers over HTTP; any status other than a 5xx error or connection failure counts as reachable.",
			Run: func(t *suite.T) {
				m := op(t)
				for _, k := range []string{"authorization_endpoint", "token_endpoint", "pushed_authorization_request_endpoint", "signed_jwks_uri", "logo_uri"} {
					u, _ := m[k].(string)
					if u == "" {
						continue
					}
					req, _ := http.NewRequestWithContext(t.Ctx, http.MethodGet, u, nil)
					resp, err := mtlsClient(t, fdCert(t)).Do(req)
					if err != nil {
						t.Should(afo("A_22644"), false, "%s %s is reachable (%v)", k, u, err)
						continue
					}
					resp.Body.Close()
					t.Should(afo("A_22644"), resp.StatusCode < 500, "%s %s is reachable (HTTP %d)", k, u, resp.StatusCode)
				}
			},
		},
	}
}
