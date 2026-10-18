// Package suite is a small conformance test framework: tests make assertions
// tagged with an RFC section and a requirement level, and the runner derives
// a status per test from them.
package suite

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"
)

// Level is the RFC 2119 requirement level of an assertion.
type Level int

const (
	Must Level = iota
	Should
)

func (l Level) String() string {
	if l == Must {
		return "MUST"
	}
	return "SHOULD"
}

func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

type Status string

const (
	Pass  Status = "pass"
	Warn  Status = "warn"  // only SHOULD-level assertions failed
	Fail  Status = "fail"  // at least one MUST-level assertion failed
	Skip  Status = "skip"  // not applicable to this target configuration
	Error Status = "error" // could not be evaluated (setup failed)
)

// Tags.
const (
	TagSlow        = "slow"        // waits for timeouts; opt-in via --slow
	TagDestructive = "destructive" // may lock accounts; runs only with its fixture configured
)

// OptInTags maps tags whose tests are skipped unless enabled to the CLI flag
// that enables them. --full enables every tag listed here.
var OptInTags = map[string]string{
	TagSlow: "--slow",
}

type Test struct {
	ID string
	// Spec is the RFC number the test belongs to; defaults to DefaultSpec.
	Spec    string
	Title   string
	Section string
	// Expect explains, for developers, what the RFC requires here and why.
	// It is shown with every failed, warned or errored result.
	Expect string
	Tags   []string
	Run    func(t *T)
}

// DefaultSpec is the RFC that bare section references refer to.
const DefaultSpec = "6749"

func (tc *Test) SpecOrDefault() string {
	if tc.Spec == "" {
		return DefaultSpec
	}
	return tc.Spec
}

// FormatSection renders a section reference as "RFC NNNN §x.y". References
// to other RFCs are written "RFCNUM/section" (e.g. "7636/4.6"); bare
// references belong to spec ("" meaning DefaultSpec). Assertion sections are
// always formatted with spec "", so shared validators can cite RFC 6749
// sections unqualified.
func FormatSection(spec, section string) string {
	if s, sec, ok := strings.Cut(section, "/"); ok {
		spec, section = s, sec
	}
	if spec == "" {
		spec = DefaultSpec
	}
	if !IsRFC(spec) {
		// gematik specs (e.g. gemSpec_IDP_Sek) use requirement IDs.
		return spec + " " + section
	}
	return "RFC " + spec + " §" + section
}

// IsRFC reports whether spec is an RFC number.
func IsRFC(spec string) bool {
	for _, r := range spec {
		if r < '0' || r > '9' {
			return false
		}
	}
	return spec != ""
}

// SpecLabel names a spec for summaries: "RFC 6749" or "gemSpec_IDP_Sek".
func SpecLabel(spec string) string {
	if IsRFC(spec) {
		return "RFC " + spec
	}
	return spec
}

func (tc *Test) HasTag(tag string) bool {
	for _, x := range tc.Tags {
		if x == tag {
			return true
		}
	}
	return false
}

type Assertion struct {
	Level   Level  `json:"level"`
	Section string `json:"section"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// Exchange is a recorded HTTP request/response pair with secrets redacted.
type Exchange struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type Result struct {
	ID         string        `json:"id"`
	Spec       string        `json:"spec"`
	Title      string        `json:"title"`
	Section    string        `json:"section"`
	Expect     string        `json:"expect"`
	Status     Status        `json:"status"`
	Reason     string        `json:"reason,omitempty"` // skip/error reason
	Assertions []Assertion   `json:"assertions"`
	Logs       []string      `json:"logs,omitempty"`
	Exchanges  []Exchange    `json:"exchanges,omitempty"`
	Duration   time.Duration `json:"duration_ns"`
}

// Env is shared across all tests of a run.
type Env struct {
	// Data holds the test kit configuration.
	Data      any
	Transport http.RoundTripper
	// Enabled holds the opt-in tags (see OptInTags) enabled for this run.
	Enabled map[string]bool
	// RequireFixtures turns skips caused by missing fixtures (SkipFixture)
	// into errors, so a full run cannot silently drop multi-client checks.
	RequireFixtures bool
	// Artifacts collects issued codes and tokens for cross-test checks.
	Artifacts *Artifacts
	// Cache holds values computed once per run (e.g. server metadata).
	Cache sync.Map
}

type Artifacts struct {
	mu            sync.Mutex
	Codes         []string
	AccessTokens  []string
	RefreshTokens []string
}

func (a *Artifacts) Add(list *[]string, v string) {
	if v == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	*list = append(*list, v)
}

// T is passed to each test.
type T struct {
	Ctx context.Context
	Env *Env

	test       *Test
	assertions []Assertion
	logs       []string
	exchanges  []Exchange
	reason     string
	status     Status
	mu         sync.Mutex
}

type stopTest struct{}

// Assert records an assertion and returns ok.
func (t *T) Assert(level Level, section string, ok bool, format string, args ...any) bool {
	if section == "" {
		section = t.test.Section
		if sp := t.test.SpecOrDefault(); sp != DefaultSpec {
			section = sp + "/" + section
		}
	}
	t.mu.Lock()
	t.assertions = append(t.assertions, Assertion{Level: level, Section: section, OK: ok, Message: fmt.Sprintf(format, args...)})
	t.mu.Unlock()
	return ok
}

func (t *T) Must(section string, ok bool, format string, args ...any) bool {
	return t.Assert(Must, section, ok, format, args...)
}

func (t *T) Should(section string, ok bool, format string, args ...any) bool {
	return t.Assert(Should, section, ok, format, args...)
}

func (t *T) Logf(format string, args ...any) {
	t.mu.Lock()
	t.logs = append(t.logs, fmt.Sprintf(format, args...))
	t.mu.Unlock()
}

// IsOptInSkip reports whether a skip reason came from an opt-in tag gate
// rather than from the target configuration.
func IsOptInSkip(reason string) bool { return strings.HasSuffix(reason, " or --full") }

// Skipf ends the test as not applicable.
func (t *T) Skipf(format string, args ...any) {
	t.status, t.reason = Skip, fmt.Sprintf(format, args...)
	panic(stopTest{})
}

// SkipFixture ends the test because a fixture (extra client, deny steps,
// issuer, ...) is not configured. In full runs this is an error.
func (t *T) SkipFixture(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if t.Env.RequireFixtures {
		t.status, t.reason = Error, "full run requires this fixture: "+msg
		panic(stopTest{})
	}
	t.Skipf("%s", msg)
}

// Fatalf ends the test because a precondition could not be established.
func (t *T) Fatalf(format string, args ...any) {
	t.status, t.reason = Error, fmt.Sprintf(format, args...)
	panic(stopTest{})
}

// Stop ends the test, keeping the assertions made so far. Use it after a
// failed assertion that makes the remaining steps meaningless.
func (t *T) Stop() { panic(stopTest{}) }

func (t *T) record(e Exchange) {
	t.mu.Lock()
	t.exchanges = append(t.exchanges, e)
	t.mu.Unlock()
}

// Transport returns a round tripper that records exchanges into this test.
func (t *T) Transport() http.RoundTripper {
	return &recorder{base: t.Env.Transport, t: t}
}

// Record wraps base so that its exchanges are recorded into this test (for
// transports with their own TLS settings, e.g. client certificates).
func (t *T) Record(base http.RoundTripper) http.RoundTripper {
	return &recorder{base: base, t: t}
}

// HTTPClient returns a client that does not follow redirects.
func (t *T) HTTPClient() *http.Client {
	return &http.Client{
		Transport:     t.Transport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Registry holds the test catalog in registration order.
type Registry struct{ tests []*Test }

func (r *Registry) Add(tests ...*Test) { r.tests = append(r.tests, tests...) }
func (r *Registry) Tests() []*Test     { return r.tests }

type Options struct {
	// Specs limits the run to tests of these RFCs (all if empty).
	Specs   []string
	Include *regexp.Regexp
	Exclude *regexp.Regexp
	// OnResult is called after every test (for progress output).
	OnResult func(Result)
}

// Run executes matching tests sequentially; ordering matters because some
// tests consume artifacts collected by earlier ones.
func Run(ctx context.Context, env *Env, reg *Registry, opts Options) []Result {
	var results []Result
	for _, tc := range reg.tests {
		if len(opts.Specs) > 0 && !slices.ContainsFunc(opts.Specs, func(sp string) bool { return strings.EqualFold(sp, tc.SpecOrDefault()) }) {
			continue
		}
		if opts.Include != nil && !opts.Include.MatchString(tc.ID) {
			continue
		}
		if opts.Exclude != nil && opts.Exclude.MatchString(tc.ID) {
			continue
		}
		r := runOne(ctx, env, tc)
		if opts.OnResult != nil {
			opts.OnResult(r)
		}
		results = append(results, r)
	}
	return results
}

// RunTest executes a single test.
func RunTest(ctx context.Context, env *Env, tc *Test) Result { return runOne(ctx, env, tc) }

func runOne(ctx context.Context, env *Env, tc *Test) Result {
	t := &T{Ctx: ctx, Env: env, test: tc}
	start := time.Now()
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, ok := v.(stopTest); !ok {
					t.status, t.reason = Error, fmt.Sprintf("panic: %v\n%s", v, debug.Stack())
				}
			}
		}()
		for tag, flag := range OptInTags {
			if tc.HasTag(tag) && !env.Enabled[tag] {
				t.Skipf("%s test; enable with %s or --full", tag, flag)
			}
		}
		tc.Run(t)
	}()
	res := Result{
		ID: tc.ID, Spec: tc.SpecOrDefault(), Title: tc.Title, Section: tc.Section, Expect: tc.Expect,
		Assertions: t.assertions, Logs: t.logs, Exchanges: t.exchanges,
		Reason: t.reason, Duration: time.Since(start),
	}
	res.Status = t.status
	if res.Status == "" || (res.Status == Error && hasFailure(t.assertions, Must)) {
		res.Status = derive(t.assertions)
	}
	if res.Status == Pass && len(t.assertions) == 0 {
		res.Status, res.Reason = Error, "test made no assertions"
	}
	return res
}

func hasFailure(as []Assertion, l Level) bool {
	for _, a := range as {
		if !a.OK && a.Level == l {
			return true
		}
	}
	return false
}

func derive(as []Assertion) Status {
	switch {
	case hasFailure(as, Must):
		return Fail
	case hasFailure(as, Should):
		return Warn
	}
	return Pass
}
