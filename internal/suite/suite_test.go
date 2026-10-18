package suite

import (
	"context"
	"testing"
)

func TestSkipFixture(t *testing.T) {
	tc := &Test{ID: "X", Section: "1", Run: func(t *T) { t.SkipFixture("clients.secondary not configured") }}
	for _, full := range []bool{false, true} {
		env := &Env{RequireFixtures: full}
		r := RunTest(context.Background(), env, tc)
		want := Skip
		if full {
			want = Error
		}
		if r.Status != want {
			t.Errorf("full=%v: status %s, want %s (%s)", full, r.Status, want, r.Reason)
		}
	}
}

func TestOptInTags(t *testing.T) {
	tc := &Test{ID: "X", Section: "1", Tags: []string{TagSlow}, Run: func(t *T) { t.Must("", true, "ran") }}
	r := RunTest(context.Background(), &Env{}, tc)
	if r.Status != Skip || !IsOptInSkip(r.Reason) {
		t.Fatalf("slow test without opt-in: %s %q", r.Status, r.Reason)
	}
	r = RunTest(context.Background(), &Env{Enabled: map[string]bool{TagSlow: true}}, tc)
	if r.Status != Pass {
		t.Fatalf("slow test with opt-in: %s %q", r.Status, r.Reason)
	}
}
