// Package report renders run results as text, JSON or JUnit XML.
package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"sekidp-ctk/internal/suite"
)

type Summary struct {
	// Title is the report heading, e.g. "OAuth 2.0 conformance report".
	Title    string         `json:"title,omitempty"`
	Target   string         `json:"target"`
	Started  time.Time      `json:"started"`
	Duration time.Duration  `json:"duration_ns"`
	Strict   bool           `json:"strict"`
	Counts   map[string]int `json:"counts"`
	// CountsBySpec breaks Counts down per RFC ("6749", "9700", ...).
	CountsBySpec map[string]map[string]int `json:"counts_by_spec"`
	Results      []suite.Result            `json:"results"`
}

func NewSummary(target string, started time.Time, strict bool, results []suite.Result) *Summary {
	s := &Summary{Target: target, Started: started, Duration: time.Since(started), Strict: strict,
		Counts: map[string]int{}, CountsBySpec: map[string]map[string]int{}, Results: results}
	for _, r := range results {
		s.Counts[string(r.Status)]++
		if s.CountsBySpec[r.Spec] == nil {
			s.CountsBySpec[r.Spec] = map[string]int{}
		}
		s.CountsBySpec[r.Spec][string(r.Status)]++
	}
	return s
}

// Failed reports whether the run should exit non-zero.
func (s *Summary) Failed() bool {
	return s.Counts[string(suite.Fail)] > 0 || s.Counts[string(suite.Error)] > 0 ||
		(s.Strict && s.Counts[string(suite.Warn)] > 0)
}

var labels = map[suite.Status]string{
	suite.Pass: "PASS ", suite.Warn: "WARN ", suite.Fail: "FAIL ", suite.Skip: "SKIP ", suite.Error: "ERROR",
}

// Line formats a single result for progress output.
func Line(r suite.Result) string {
	return fmt.Sprintf("%s %-7s %-21s %s", labels[r.Status], r.ID, "["+suite.FormatSection(r.Spec, r.Section)+"]", r.Title)
}

// Text writes a human-readable report: result lines, optional evidence
// (verbose >= 1: logs and HTTP exchanges of non-passing tests; 2: all tests
// and all assertions), the summary table and the findings.
func Text(w io.Writer, s *Summary, verbose int, progressShown bool) {
	for _, r := range s.Results {
		if !progressShown {
			fmt.Fprintln(w, Line(r))
		}
	}
	evidence := false
	for _, r := range s.Results {
		if verbose < 1 {
			break
		}
		if !needsAttention(r) && verbose < 2 {
			continue
		}
		if len(r.Logs) == 0 && len(r.Exchanges) == 0 && verbose < 2 {
			continue
		}
		if !evidence {
			fmt.Fprintln(w, "\n─── evidence (logs and HTTP exchanges) ───")
			evidence = true
		}
		fmt.Fprintf(w, "\n%s %s — %s\n", labels[r.Status], r.ID, r.Title)
		if verbose > 1 {
			for _, a := range r.Assertions {
				mark := "✓"
				if !a.OK {
					mark = "✗"
				}
				fmt.Fprintf(w, "    %s %-6s %-18s %s\n", mark, a.Level, suite.FormatSection("", a.Section), a.Message)
			}
		}
		for _, l := range r.Logs {
			fmt.Fprintf(w, "    · %s\n", l)
		}
		for i, e := range r.Exchanges {
			fmt.Fprintf(w, "    ── exchange %d ──\n%s\n%s\n", i+1, indent(e.Request, "      > "), indent(e.Response, "      < "))
		}
	}
	SummaryTable(w, s)
	Findings(w, s)
	if s.Failed() {
		fmt.Fprintln(w, "\nRESULT: NOT CONFORMANT")
	} else {
		fmt.Fprintln(w, "\nRESULT: CONFORMANT (for the tests that ran)")
	}
}

func needsAttention(r suite.Result) bool {
	return r.Status == suite.Fail || r.Status == suite.Warn || r.Status == suite.Error
}

// Findings explains every failed, errored and warned test for developers:
// what the RFC expects and what the implementation did.
func Findings(w io.Writer, s *Summary) {
	order := []suite.Status{suite.Fail, suite.Error, suite.Warn}
	if s.Counts["fail"]+s.Counts["error"]+s.Counts["warn"] == 0 {
		return
	}
	fmt.Fprintf(w, "\nFindings: %d failed (MUST), %d errors, %d warnings (SHOULD)\n",
		s.Counts["fail"], s.Counts["error"], s.Counts["warn"])
	for _, st := range order {
		for _, r := range s.Results {
			if r.Status != st {
				continue
			}
			fmt.Fprintf(w, "\n%s %s  %s  [%s]\n", labels[r.Status], r.ID, r.Title, suite.FormatSection(r.Spec, r.Section))
			if r.Expect != "" {
				writeWrapped(w, "      Expected  ", "                ", r.Expect, 100)
			}
			prefix := "      Observed  "
			if r.Status == suite.Error {
				writeWrapped(w, prefix, "                ", "could not be evaluated: "+r.Reason, 100)
				continue
			}
			for _, a := range r.Assertions {
				if a.OK {
					continue
				}
				writeWrapped(w, prefix, "                ",
					fmt.Sprintf("%s %s: %s", a.Level, suite.FormatSection("", a.Section), a.Message), 100)
				prefix = "                "
			}
		}
	}
}

// writeWrapped writes text word-wrapped to width, with first/rest prefixes.
func writeWrapped(w io.Writer, first, rest, text string, width int) {
	line, prefix := "", first
	for _, word := range strings.Fields(text) {
		if line != "" && len(prefix)+len(line)+1+len(word) > width {
			fmt.Fprintln(w, prefix+line)
			line, prefix = "", rest
		}
		if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		fmt.Fprintln(w, prefix+line)
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func JSON(w io.Writer, s *Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     float64     `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Error     *junitMessage `xml:"error,omitempty"`
	Skipped   *junitMessage `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// JUnit writes JUnit XML. Warnings are failures in strict mode and passing
// cases with system-out otherwise.
func JUnit(w io.Writer, s *Summary) error {
	js := junitSuite{Name: "sekidp-ctk " + s.Target, Time: s.Duration.Seconds()}
	for _, r := range s.Results {
		c := junitCase{Name: r.ID + " " + r.Title, Classname: junitClass(r.Spec, r.Section),
			Time: r.Duration.Seconds()}
		msg := failedAssertions(r)
		var body strings.Builder
		for _, l := range r.Logs {
			body.WriteString(l + "\n")
		}
		for _, e := range r.Exchanges {
			body.WriteString(e.Request + "\n" + e.Response + "\n\n")
		}
		switch {
		case r.Status == suite.Fail || (r.Status == suite.Warn && s.Strict):
			js.Failures++
			c.Failure = &junitMessage{Message: msg, Body: "Expected: " + r.Expect + "\n\nObserved:\n" + msg + "\n\n" + body.String()}
		case r.Status == suite.Error:
			js.Errors++
			c.Error = &junitMessage{Message: r.Reason, Body: body.String()}
		case r.Status == suite.Skip:
			js.Skipped++
			c.Skipped = &junitMessage{Message: r.Reason}
		case r.Status == suite.Warn:
			c.SystemOut = "WARNING:\n" + msg
		}
		js.Tests++
		js.Cases = append(js.Cases, c)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(junitSuites{Suites: []junitSuite{js}})
}

func failedAssertions(r suite.Result) string {
	var parts []string
	for _, a := range r.Assertions {
		if !a.OK {
			parts = append(parts, fmt.Sprintf("%s %s: %s", a.Level, suite.FormatSection("", a.Section), a.Message))
		}
	}
	return strings.Join(parts, "\n")
}

// ConfigSkips lists the tests a full run still skipped. These are not
// applicable to the server (unsupported grant or auth method, waived TLS,
// nothing issued); missing fixtures are already reported as errors.
func ConfigSkips(w io.Writer, s *Summary) {
	var reasons []string
	ids := map[string][]string{}
	for _, r := range s.Results {
		if r.Status == suite.Skip && !suite.IsOptInSkip(r.Reason) {
			if _, ok := ids[r.Reason]; !ok {
				reasons = append(reasons, r.Reason)
			}
			ids[r.Reason] = append(ids[r.Reason], r.ID)
		}
	}
	if len(reasons) == 0 {
		fmt.Fprintln(w, "\nfull run: every test was executed")
		return
	}
	n := 0
	for _, l := range ids {
		n += len(l)
	}
	fmt.Fprintf(w, "\nfull run: %d tests not applicable to this server:\n", n)
	for _, reason := range reasons {
		writeWrapped(w, "  "+strings.Join(ids[reason], ", ")+": ", "      ", reason, 100)
	}
}

var summaryCols = []struct {
	status suite.Status
	head   string
}{
	{suite.Pass, "passed"}, {suite.Warn, "warnings"}, {suite.Fail, "failed"},
	{suite.Error, "errors"}, {suite.Skip, "skipped"},
}

// SummaryTable writes per-RFC and total counts of test results.
func SummaryTable(w io.Writer, s *Summary) {
	specs := make([]string, 0, len(s.CountsBySpec))
	for sp := range s.CountsBySpec {
		specs = append(specs, sp)
	}
	sort.Strings(specs)

	fmt.Fprintf(w, "\nSummary: %s (%s)\n", s.Target, s.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "  %-16s %6s", "", "tests")
	for _, c := range summaryCols {
		fmt.Fprintf(w, " %9s", c.head)
	}
	fmt.Fprintln(w)
	row := func(label string, counts map[string]int) {
		total := 0
		for _, n := range counts {
			total += n
		}
		fmt.Fprintf(w, "  %-16s %6d", label, total)
		for _, c := range summaryCols {
			fmt.Fprintf(w, " %9d", counts[string(c.status)])
		}
		fmt.Fprintln(w)
	}
	for _, sp := range specs {
		row(suite.SpecLabel(sp), s.CountsBySpec[sp])
	}
	if len(specs) > 1 {
		row("total", s.Counts)
	}
	if s.Strict && s.Counts[string(suite.Warn)] > 0 {
		fmt.Fprintln(w, "  (strict: warnings count as failures)")
	}
}

// junitClass builds a JUnit classname such as "rfc6749.s4_1_2" or
// "gemSpec_IDP_Sek.A_22643_02".
func junitClass(spec, section string) string {
	clean := strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(section)
	if suite.IsRFC(spec) {
		return "rfc" + spec + ".s" + clean
	}
	return spec + "." + clean
}
