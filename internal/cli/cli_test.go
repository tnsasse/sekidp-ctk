package cli

import "testing"

func TestDefaultHTMLPath(t *testing.T) {
	for in, want := range map[string]string{
		"sector idp (ru)":            "sector-idp-ru-report.html",
		"https://idp.example/entity": "sekidp-ctk-report.html",
		"":                           "sekidp-ctk-report.html",
	} {
		if got := DefaultHTMLPath(in, "sekidp-ctk"); got != want {
			t.Errorf("DefaultHTMLPath(%q) = %q, want %q", in, got, want)
		}
	}
}
