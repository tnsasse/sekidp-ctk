package gematik

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"sekidp-ctk/internal/suite"
)

func fedMaster(t *suite.T) *FederationMaster {
	fm := gcfg(t).FederationMaster
	if fm == nil {
		t.SkipFixture("federation_master.entity_id not configured")
	}
	return fm
}

func fedMasterStatement(t *suite.T) *entityStatement {
	fm := fedMaster(t)
	es := fetchStatement(t, strings.TrimSuffix(fm.EntityID, "/")+"/.well-known/openid-federation")
	if es.Err != nil {
		t.Fatalf("Federation Master entity statement %s could not be loaded: %v", es.URL, es.Err)
	}
	return es
}

// subordinateStatement fetches the Federation Master's statement about the IdP.
func subordinateStatement(t *suite.T) (raw string, claims map[string]any) {
	fm := fedMasterStatement(t)
	ep, _ := fm.metadata("federation_entity")["federation_fetch_endpoint"].(string)
	if ep == "" {
		t.Fatalf("Federation Master metadata has no federation_entity.federation_fetch_endpoint")
	}
	u := ep + "?" + url.Values{"sub": {gcfg(t).IDP.EntityID}}.Encode()
	if strings.Contains(ep, "?") {
		u = ep + "&" + url.Values{"sub": {gcfg(t).IDP.EntityID}}.Encode()
	}
	req, _ := http.NewRequestWithContext(t.Ctx, http.MethodGet, u, nil)
	resp, err := t.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("fetch %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if !t.Must(fed+"/8.1", resp.StatusCode == 200, "Federation Master returns a subordinate statement about the IdP (HTTP %d)", resp.StatusCode) {
		t.Stop()
	}
	raw = strings.TrimSpace(string(body))
	claims, err = jwtPayload(raw)
	if err != nil {
		t.Fatalf("subordinate statement is not a JWT: %v", err)
	}
	return raw, claims
}

func sameKey(a, b jose.JSONWebKey) bool {
	ta, err1 := a.Thumbprint(cryptoSHA256)
	tb, err2 := b.Thumbprint(cryptoSHA256)
	return err1 == nil && err2 == nil && string(ta) == string(tb)
}

func federationTests() []*suite.Test {
	return []*suite.Test{
		{
			ID: "GFM-01", Spec: spec, Section: "A_22643-02", Title: "authority_hints point to the Federation Master",
			Expect: "The IdP is a participant of the TI federation, so its entity statement's authority_hints MUST name the Federation Master of the environment as superior (OpenID Federation 1.1, Table 3).",
			Run: func(t *suite.T) {
				fm := fedMaster(t)
				hints := strList(idpStatement(t).Claims["authority_hints"])
				t.Must(afo("A_22643-02"), slices.Contains(hints, fm.EntityID), "authority_hints %v contain %s", hints, fm.EntityID)
			},
		},
		{
			ID: "GFM-02", Spec: spec, Section: "A_22643-02", Title: "Federation Master lists the IdP in a valid subordinate statement",
			Expect: "The trust chain must resolve: the Federation Master's fetch endpoint returns a subordinate statement with iss = Federation Master and sub = IdP, signed with a key from the Federation Master's own entity statement (OpenID Federation 1.1 §8.1).",
			Run: func(t *suite.T) {
				fm := fedMasterStatement(t)
				raw, c := subordinateStatement(t)
				t.Must(fed+"/8.1", c["iss"] == fedMaster(t).EntityID, "subordinate statement iss %v is the Federation Master", c["iss"])
				t.Must(fed+"/8.1", c["sub"] == gcfg(t).IDP.EntityID, "subordinate statement sub %v is the IdP", c["sub"])
				_, err := verifyJWS(raw, fm.JWKS)
				t.Must(fed+"/8.1", err == nil, "subordinate statement is signed by the Federation Master (%v)", err)
				if h, err := joseHeader(raw); err == nil {
					t.Must(fed+"/3", hstr(h, "typ") == typEntityStatement, "subordinate statement typ is %s (got %q)", typEntityStatement, hstr(h, "typ"))
				}
			},
		},
		{
			ID: "GFM-04", Spec: specFD, Section: "AF_10116", Title: "IdP appears in the Federation Master's signed IDP list",
			Expect: "Fachdienste offer users the list of registered sector IdPs, which they MUST obtain from the Federation Master (gemSpec_IDP_FD AF_10116). The list is a JWS signed by the Federation Master (A_23033) and each entry carries at least the IdP's issuer, a readable name and the logo. An IdP missing from it cannot be selected by users.",
			Run: func(t *suite.T) {
				fm := fedMasterStatement(t)
				ep, _ := fm.metadata("federation_entity")["idp_list_endpoint"].(string)
				if ep == "" {
					t.Skipf("the Federation Master does not publish idp_list_endpoint")
				}
				req, _ := http.NewRequestWithContext(t.Ctx, http.MethodGet, ep, nil)
				resp, err := t.HTTPClient().Do(req)
				if err != nil {
					t.Fatalf("GET %s: %v", ep, err)
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
				resp.Body.Close()
				if !t.Must(specFD+"/AF_10116", resp.StatusCode == 200, "IDP list is served (HTTP %d)", resp.StatusCode) {
					return
				}
				raw := strings.TrimSpace(string(body))
				_, err = verifyJWS(raw, fm.JWKS)
				t.Must(specFD+"/A_23033", err == nil, "IDP list is signed by the Federation Master (%v)", err)
				if h, err := joseHeader(raw); err == nil {
					// gemSpec_IDP_Sek 3.2.0 Table 25.
					t.Should(specFD+"/AF_10116", hstr(h, "alg") == "ES256" && hstr(h, "typ") == "idp-list+jwt",
						"IDP list header has alg ES256 and typ idp-list+jwt (got %q, %q)", hstr(h, "alg"), hstr(h, "typ"))
				}
				claims, err := jwtPayload(raw)
				if err != nil {
					t.Fatalf("IDP list is not a JWT: %v", err)
				}
				var entry map[string]any
				for _, v := range claims {
					for _, e := range anyList(v) {
						if m := obj(e); m != nil && (m["iss"] == gcfg(t).IDP.EntityID || m["issuer"] == gcfg(t).IDP.EntityID) {
							entry = m
						}
					}
				}
				if !t.Must(specFD+"/AF_10116", entry != nil, "the IDP list contains an entry for %s", gcfg(t).IDP.EntityID) {
					return
				}
				name, _ := entry["organization_name"].(string)
				t.Should(specFD+"/AF_10116", name != "", "the entry has a readable name (organization_name)")
				// gemSpec_IDP_Sek 3.2.0 Table 24: entries mirror the IdP's metadata.
				t.Should(specFD+"/AF_10116", exactly(strList(entry["user_type_supported"]), "IP"), "the entry has user_type_supported [\"IP\"] (got %v)", entry["user_type_supported"])
				if logo, ok := op(t)["logo_uri"].(string); ok && entry["logo_uri"] != nil {
					t.Should(specFD+"/AF_10116", entry["logo_uri"] == logo, "the entry's logo_uri matches the IdP metadata")
				}
				t.Logf("IDP list entry: %v", entry)
			},
		},
		{
			ID: "GFM-03", Spec: spec, Section: "A_22643-02", Title: "Federation Master vouches for the IdP's entity signing key",
			Expect: "The jwks in the Federation Master's subordinate statement must contain the key that signed the IdP's entity statement; otherwise the IdP's self-signed statement cannot be anchored in the federation trust chain.",
			Run: func(t *suite.T) {
				es := idpStatement(t)
				_, c := subordinateStatement(t)
				set, err := parseJWKS(c["jwks"])
				if !t.Must(fed+"/8.1", err == nil && len(set.Keys) > 0, "subordinate statement contains a jwks (%v)", err) {
					return
				}
				kid := hstr(es.Header, "kid")
				own := es.JWKS.Key(kid)
				if len(own) == 0 {
					t.Fatalf("entity statement kid %q not in its own jwks", kid)
				}
				found := slices.ContainsFunc(set.Keys, func(k jose.JSONWebKey) bool { return sameKey(k, own[0]) })
				t.Must(fed+"/10", found, "the IdP's entity signing key %s is contained in the Federation Master's jwks for the IdP", kid)
			},
		},
	}
}

// keysJSON renders a key set for log output.
func keysJSON(set jose.JSONWebKeySet) string {
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	b, _ := json.Marshal(kids)
	return string(b)
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}
