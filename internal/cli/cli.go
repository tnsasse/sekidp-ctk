// Package cli implements the sekidp-ctk command line: run/list commands,
// flags, progress output and report files.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"sekidp-ctk/internal/report"
	"sekidp-ctk/internal/suite"
)

// Tool describes one test kit binary.
type Tool struct {
	// Name is the binary name, e.g. "sekidp-ctk".
	Name string
	// Description is the one-line description printed in the usage text.
	Description string
	// ReportTitle is the heading of the HTML report.
	ReportTitle string
	// SpecHelp describes the values accepted by -spec.
	SpecHelp string
	// Registry returns the test catalog.
	Registry func() *suite.Registry
	// Load reads a config file and returns the target name and an
	// environment with Data and Transport set.
	Load func(path string) (target string, env *suite.Env, err error)
}

func (t Tool) usage() string {
	return fmt.Sprintf(`%s — %s

Usage:
  %s run  -config target.yaml [flags]
  %s list

Run '%s run -h' for flags.
Exit status: 0 conformant, 1 failures/errors (or warnings with --strict), 2 usage/config error.
`, t.Name, t.Description, t.Name, t.Name, t.Name)
}

// Main runs the tool with os.Args and exits.
func (t Tool) Main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, t.usage())
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(t.run(os.Args[2:]))
	case "list":
		os.Exit(t.list())
	case "-h", "--help", "help":
		fmt.Print(t.usage())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], t.usage())
		os.Exit(2)
	}
}

func (t Tool) list() int {
	for _, tc := range t.Registry().Tests() {
		tags := ""
		if len(tc.Tags) > 0 {
			tags = " (" + strings.Join(tc.Tags, ",") + ")"
		}
		fmt.Printf("%-7s %-30s %s%s\n", tc.ID, "["+suite.FormatSection(tc.SpecOrDefault(), tc.Section)+"]", tc.Title, tags)
	}
	return 0
}

func (t Tool) run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "target config file (YAML); ${VAR} references are expanded from the environment")
	format := fs.String("format", "text", "report format written to -o: text, json, junit or html")
	out := fs.String("o", "", "write the report to this file instead of stdout")
	junit := fs.String("junit", "", "additionally write a JUnit XML report to this file")
	jsonOut := fs.String("json", "", "additionally write a JSON report to this file")
	htmlOut := fs.String("html", "", "additionally write a self-contained HTML report to this file (automatic with --full; 'none' disables)")
	strict := fs.Bool("strict", false, "treat SHOULD-level warnings as failures")
	slow := fs.Bool("slow", false, "include slow tests (e.g. waiting for code expiry)")
	full := fs.Bool("full", false, "run everything: every opt-in test (implies --slow), and missing fixtures are errors instead of skips")
	specs := fs.String("spec", "", "comma-separated specs to test: "+t.SpecHelp+" (default: all)")
	include := fs.String("run", "", "only run tests whose ID matches this regexp")
	exclude := fs.String("skip", "", "skip tests whose ID matches this regexp")
	verbose := fs.Int("v", 1, "verbosity: 0 results, summary and findings (default with --full), 1 + logs/HTTP exchanges for findings, 2 + every assertion of every test")
	quiet := fs.Bool("q", false, "no progress output")
	_ = fs.Parse(args)
	vSet := false
	fs.Visit(func(f *flag.Flag) { vSet = vSet || f.Name == "v" })
	if *full && !vSet {
		*verbose = 0 // full runs print results, summary and findings unless -v is given
	}

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		return 2
	}
	name, env, err := t.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	opts := suite.Options{}
	if *specs != "" {
		for _, sp := range strings.Split(*specs, ",") {
			sp = strings.TrimSpace(sp)
			if len(sp) > 3 && strings.EqualFold(sp[:3], "rfc") {
				sp = strings.TrimSpace(sp[3:])
			}
			opts.Specs = append(opts.Specs, sp)
		}
	}
	if opts.Include, err = compile(*include); err != nil {
		fmt.Fprintln(os.Stderr, "-run:", err)
		return 2
	}
	if opts.Exclude, err = compile(*exclude); err != nil {
		fmt.Fprintln(os.Stderr, "-skip:", err)
		return 2
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		defer f.Close()
		w = f
	}
	// Progress goes to stderr unless the text report itself goes to stdout.
	progress := io.Writer(os.Stderr)
	progressShown := !*quiet
	if *format == "text" && *out == "" {
		progress = os.Stdout
	} else {
		progressShown = false
	}
	if !*quiet {
		opts.OnResult = func(r suite.Result) { fmt.Fprintln(progress, report.Line(r)) }
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	enabled := map[string]bool{suite.TagSlow: *slow}
	if *full {
		for tag := range suite.OptInTags {
			enabled[tag] = true
		}
	}
	env.Enabled, env.RequireFixtures, env.Artifacts = enabled, *full, &suite.Artifacts{}
	started := time.Now()
	results := suite.Run(ctx, env, t.Registry(), opts)
	sum := report.NewSummary(name, started, *strict, results)
	sum.Title = t.ReportTitle

	switch *format {
	case "text":
		report.Text(w, sum, *verbose, progressShown && *out == "")
		if *full {
			report.ConfigSkips(w, sum)
		}
	case "json":
		err = report.JSON(w, sum)
	case "junit":
		err = report.JUnit(w, sum)
	case "html":
		err = report.HTML(w, sum)
	default:
		fmt.Fprintf(os.Stderr, "unknown -format %q\n", *format)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	htmlPath := *htmlOut
	if *full && htmlPath == "" {
		htmlPath = DefaultHTMLPath(name, t.Name)
	}
	if htmlPath == "none" {
		htmlPath = ""
	}
	for path, fn := range map[string]func(io.Writer, *report.Summary) error{*junit: report.JUnit, *jsonOut: report.JSON, htmlPath: report.HTML} {
		if path == "" {
			continue
		}
		if err := writeFile(path, sum, fn); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if htmlPath != "" {
		fmt.Fprintf(os.Stderr, "HTML report: %s\n", htmlPath)
	}
	if sum.Failed() {
		return 1
	}
	return 0
}

// DefaultHTMLPath derives a report file name from the target name, e.g.
// "sector idp (ru)" -> "sector-idp-ru-report.html". fallback is used when
// the name is empty or a URL.
func DefaultHTMLPath(target, fallback string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(target) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" || strings.Contains(target, "://") {
		slug = fallback
	}
	return slug + "-report.html"
}

func writeFile(path string, s *report.Summary, fn func(io.Writer, *report.Summary) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f, s)
}

func compile(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	return regexp.Compile(expr)
}
