package gematik

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"sekidp-ctk/internal/suite"
)

// runAll runs the whole catalog against the fake and returns status per ID.
func runAll(t *testing.T, d defects, filter func(id string) bool) map[string]suite.Result {
	t.Helper()
	_, cfg := startFake(t, d)
	env := &suite.Env{Data: cfg, Transport: NewTransport(cfg), Artifacts: &suite.Artifacts{},
		Enabled: map[string]bool{}, RequireFixtures: true}
	out := map[string]suite.Result{}
	for _, tc := range Registry().Tests() {
		if filter != nil && !filter(tc.ID) {
			continue
		}
		r := suite.RunTest(context.Background(), env, tc)
		out[r.ID] = r
	}
	return out
}

func describe(r suite.Result) string {
	var b strings.Builder
	b.WriteString(string(r.Status) + " " + r.Reason)
	for _, a := range r.Assertions {
		if !a.OK {
			b.WriteString("\n    " + a.Level.String() + " " + a.Section + ": " + a.Message)
		}
	}
	return b.String()
}

// TestCompliantFakePasses: against a conformant fake every check passes,
// except those that cannot apply (slow ones are disabled here).
func TestCompliantFakePasses(t *testing.T) {
	res := runAll(t, defects{}, nil)
	var ids []string
	for id := range res {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := res[id]
		switch {
		case r.Status == suite.Pass:
		case r.Status == suite.Skip && suite.IsOptInSkip(r.Reason):
		default:
			t.Errorf("%s: %s", id, describe(r))
		}
	}
	if len(res) < 65 {
		t.Fatalf("only %d tests ran", len(res))
	}
}

// TestDefectsAreDetected: each injected violation fails its check.
func TestDefectsAreDetected(t *testing.T) {
	cases := []struct {
		name string
		d    defects
		want []string // test IDs that must fail (MUST) or warn
	}{
		{"plain PKCE accepted", defects{allowPlainPKCE: true}, []string{"GPR-08"}},
		{"code reusable", defects{reusableCode: true}, []string{"GTK-11"}},
		{"request_uri lives 300s", defects{longRequestURI: true}, []string{"GPR-02"}},
		{"ID token lives 1h", defects{longIDToken: true}, []string{"GTK-05"}},
		{"wildcard VAU cert", defects{wildcardCert: true}, []string{"GTL-02"}},
		{"no version header", defects{noVersionHeader: true}, []string{"GTK-03"}},
		{"unrequested claim", defects{extraClaim: true}, []string{"GTK-08"}},
		{"any client cert accepted", defects{acceptAnyCert: true}, []string{"GPR-04", "GTK-13"}},
		{"sub not pairwise", defects{plainSub: true}, []string{"GTK-10"}},
		{"entity statement typ", defects{esTypWrong: true}, []string{"GES-02"}},
		{"no ti_features", defects{noTiFeatures: true}, []string{"GES-16"}},
		{"code without login", defects{redirectNoAuth: true}, []string{"GAZ-04"}},
		{"no app links", defects{noAppLinks: true}, []string{"GAP-01"}},
		{"amr not allowed for acr", defects{acrMismatch: true}, []string{"GTK-06"}},
		{"no client certificate request", defects{noCertRequest: true}, []string{"GTL-06"}},
		{"server error on malformed input", defects{crashOnInput: true}, []string{"GPR-14"}},
		{"deprecated amr in 2.0.0 token", defects{deprecatedAmrV2: true}, []string{"GTK-16"}},
		{"IdP missing from IDP list", defects{notInIDPList: true}, []string{"GFM-04"}},
		{"ID token JWS without typ", defects{jwsNoTyp: true}, []string{"GTK-04"}},
		{"essential acr ignored", defects{ignoreEssentialACR: true}, []string{"GTK-17"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := map[string]bool{}
			for _, id := range tc.want {
				want[id] = true
			}
			res := runAll(t, tc.d, func(id string) bool { return want[id] })
			for _, id := range tc.want {
				r := res[id]
				if r.Status != suite.Fail && r.Status != suite.Warn {
					t.Errorf("%s should detect %q but got %s", id, tc.name, describe(r))
				}
			}
		})
	}
}

var _ = http.StatusOK
