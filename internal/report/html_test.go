package report

import (
	"strings"
	"testing"
	"time"

	"sekidp-ctk/internal/suite"
)

func TestHTMLSelfContainedAndEscaped(t *testing.T) {
	results := []suite.Result{{ID: "X-01", Spec: "6749", Title: "t", Section: "5.2", Status: suite.Fail,
		Expect: "expect", Assertions: []suite.Assertion{{Level: suite.Must, Section: "5.2", Message: "</script><img src=x onerror=alert(1)>"}}}}
	var b strings.Builder
	if err := HTML(&b, NewSummary("t", time.Now(), false, results)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "</script><img") {
		t.Fatal("untrusted message was not escaped inside the JSON data block")
	}
	for _, bad := range []string{"http://", "https://"} {
		if strings.Contains(out, "src=\""+bad) || strings.Contains(out, "href=\""+bad) {
			t.Fatalf("report references an external resource (%s)", bad)
		}
	}
	if !strings.Contains(out, "X-01") {
		t.Fatal("result data missing")
	}
}
