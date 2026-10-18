package report

import (
	"strings"
	"testing"
	"time"

	"sekidp-ctk/internal/suite"
)

func TestSummaryTable(t *testing.T) {
	results := []suite.Result{
		{ID: "A", Spec: "6749", Status: suite.Pass},
		{ID: "B", Spec: "6749", Status: suite.Fail},
		{ID: "C", Spec: "9700", Status: suite.Warn},
		{ID: "D", Spec: "9700", Status: suite.Skip},
	}
	s := NewSummary("t", time.Now(), false, results)
	var b strings.Builder
	SummaryTable(&b, s)
	out := b.String()
	for _, want := range []string{
		"RFC 6749              2         1         0         1         0         0",
		"RFC 9700              2         0         1         0         0         1",
		"total                 4         1         1         1         0         1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing row %q:\n%s", want, out)
		}
	}
	if !s.Failed() {
		t.Error("a failed test must fail the run")
	}
}
