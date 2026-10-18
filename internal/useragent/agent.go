// Package useragent plays the resource owner's browser at the authorization
// endpoint without a human: it follows redirects, fills in configured HTML
// forms (login, consent, ...) and stops as soon as the server redirects to a
// client origin. Nothing needs to listen on the client's redirect URI.
package useragent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const maxHops = 25

// Outcome describes where the flow ended.
type Outcome struct {
	// Redirect is set when the server redirected the user agent to one of the
	// watched client origins.
	Redirect *url.URL
	// Otherwise the flow ended on a page that no step matched (typically an
	// error page) or a non-redirect, non-HTML response.
	PageURL    *url.URL
	PageStatus int
	PageBody   string
	// Locations lists every redirect target seen, in order.
	Locations []string
	// Hops lists every HTTP exchange, in order.
	Hops []Hop
	// Pages lists every HTML page received (login, consent, error pages).
	Pages []Page
	// StepsUsed lists the names of submitted steps, in order.
	StepsUsed []string
}

// Hop is one request/response of the flow.
type Hop struct {
	Method   string
	URL      string
	Status   int
	Location string
	// Credentials is true if the request was a form submission carrying a
	// configured credential field (a filled-in step field).
	Credentials bool
}

// Page is an HTML response the user agent rendered.
type Page struct {
	URL    *url.URL
	Status int
	Header http.Header
	Body   string
}

func (o *Outcome) String() string {
	if o.Redirect != nil {
		return "redirected to " + o.Redirect.String()
	}
	return fmt.Sprintf("stopped at page %s (HTTP %d): %s", o.PageURL, o.PageStatus, Snippet(o.PageBody, 200))
}

// RedirectedTo reports whether any redirect seen during the flow pointed at
// the given origin (scheme://host[:port]).
func (o *Outcome) RedirectedTo(origin string) bool {
	for _, l := range o.Locations {
		if u, err := url.Parse(l); err == nil && Origin(u) == origin {
			return true
		}
	}
	return false
}

// Step describes how to fill in and submit one HTML form. On every page the
// user agent submits the first step whose Form selector matches.
type Step struct {
	Name string `yaml:"name"`
	// Form is a CSS selector identifying the form element.
	Form string `yaml:"form"`
	// Fields maps input names to values. "{{username}}" and "{{password}}" are
	// replaced with the user's credentials.
	Fields map[string]string `yaml:"fields"`
	// Submit optionally names the submit button to "click".
	Submit      string `yaml:"submit"`
	SubmitValue string `yaml:"submit_value"`
	// Check lists checkbox names to tick (every checkbox with that name),
	// e.g. checkboxes on a consent screen that start unchecked.
	Check []string `yaml:"check"`
}

type Agent struct {
	// Jar, if set, is used instead of a fresh cookie jar, so that several runs
	// share one browser session.
	Jar http.CookieJar
	// Transport is the base round tripper (TLS config, recording, ...).
	Transport http.RoundTripper
	Steps     []Step
	Vars      map[string]string
	// StopOrigins are client origins; a redirect to any of them ends the flow.
	StopOrigins []string
}

// Run starts at the authorization request URL and drives the flow. Unless
// Jar is set, each Run uses a fresh cookie jar and starts unauthenticated.
func (a *Agent) Run(ctx context.Context, start string) (*Outcome, error) {
	var jar http.CookieJar = a.Jar
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	hc := &http.Client{
		Transport: a.Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	out := &Outcome{}
	uses := map[int]int{}
	sentCredentials := false

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, start, nil)
	if err != nil {
		return nil, err
	}
	for hop := 0; hop < maxHops; hop++ {
		resp, err := hc.Do(req)
		if err != nil {
			return out, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		out.Hops = append(out.Hops, Hop{Method: req.Method, URL: req.URL.String(), Status: resp.StatusCode,
			Location: resp.Header.Get("Location"), Credentials: sentCredentials})
		sentCredentials = false

		if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			next, err := req.URL.Parse(loc)
			if err != nil {
				return out, fmt.Errorf("bad Location %q: %w", loc, err)
			}
			out.Locations = append(out.Locations, next.String())
			if a.isStop(next) {
				out.Redirect = next
				return out, nil
			}
			method := http.MethodGet
			if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
				method = req.Method // body re-sending is not supported; forms are re-posted rarely
			}
			req, err = http.NewRequestWithContext(ctx, method, next.String(), nil)
			if err != nil {
				return out, err
			}
			continue
		}

		out.PageURL, out.PageStatus, out.PageBody = resp.Request.URL, resp.StatusCode, string(body)
		if !strings.Contains(resp.Header.Get("Content-Type"), "html") && !strings.Contains(strings.ToLower(out.PageBody), "<form") {
			return out, nil
		}
		out.Pages = append(out.Pages, Page{URL: resp.Request.URL, Status: resp.StatusCode, Header: resp.Header, Body: string(body)})
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			return out, nil
		}
		idx, form := a.matchStep(doc)
		if idx < 0 {
			return out, nil
		}
		uses[idx]++
		if uses[idx] > 3 {
			return out, fmt.Errorf("step %q matched %d times; credentials rejected or selectors wrong (page %s: %s)",
				a.Steps[idx].Name, uses[idx], out.PageURL, Snippet(out.PageBody, 300))
		}
		out.StepsUsed = append(out.StepsUsed, a.Steps[idx].Name)
		sentCredentials = len(a.Steps[idx].Fields) > 0
		req, err = a.submit(ctx, resp.Request.URL, form, a.Steps[idx])
		if err != nil {
			return out, err
		}
	}
	return out, errors.New("too many redirects / form submissions")
}

func (a *Agent) isStop(u *url.URL) bool {
	o := Origin(u)
	for _, s := range a.StopOrigins {
		if s == o {
			return true
		}
	}
	return false
}

func (a *Agent) matchStep(doc *goquery.Document) (int, *goquery.Selection) {
	for i, s := range a.Steps {
		if sel := doc.Find(s.Form).First(); sel.Length() > 0 {
			if !sel.Is("form") {
				sel = sel.Closest("form")
			}
			if sel.Length() > 0 {
				return i, sel
			}
		}
	}
	return -1, nil
}

func (a *Agent) submit(ctx context.Context, page *url.URL, form *goquery.Selection, step Step) (*http.Request, error) {
	values := url.Values{}
	form.Find("input, select, textarea").Each(func(_ int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok || name == "" {
			return
		}
		_, disabled := s.Attr("disabled")
		if disabled {
			return
		}
		switch goquery.NodeName(s) {
		case "input":
			typ := strings.ToLower(s.AttrOr("type", "text"))
			switch typ {
			case "submit", "button", "image", "reset", "file":
				return
			case "checkbox", "radio":
				if _, checked := s.Attr("checked"); !checked && !(typ == "checkbox" && contains(step.Check, name)) {
					return
				}
				values.Add(name, s.AttrOr("value", "on"))
			default:
				values.Add(name, s.AttrOr("value", ""))
			}
		case "select":
			opt := s.Find("option[selected]").First()
			if opt.Length() == 0 {
				opt = s.Find("option").First()
			}
			if opt.Length() > 0 {
				values.Add(name, opt.AttrOr("value", strings.TrimSpace(opt.Text())))
			}
		case "textarea":
			values.Add(name, s.Text())
		}
	})
	for k, v := range step.Fields {
		values.Set(k, a.expand(v))
	}
	if step.Submit != "" {
		val := step.SubmitValue
		if val == "" {
			btn := form.Find(fmt.Sprintf(`[name=%q]`, step.Submit)).First()
			val = btn.AttrOr("value", "")
		}
		values.Set(step.Submit, val)
	}

	action, err := page.Parse(form.AttrOr("action", ""))
	if err != nil {
		return nil, fmt.Errorf("step %q: bad form action: %w", step.Name, err)
	}
	if strings.EqualFold(form.AttrOr("method", "get"), "post") {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, action.String(), strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	}
	action.RawQuery = values.Encode()
	return http.NewRequestWithContext(ctx, http.MethodGet, action.String(), nil)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (a *Agent) expand(v string) string {
	for k, val := range a.Vars {
		v = strings.ReplaceAll(v, "{{"+k+"}}", val)
	}
	return v
}

// Origin returns scheme://host[:port] in lower case.
func Origin(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// Snippet returns a whitespace-collapsed prefix of an HTML/text body with tags
// stripped, for error messages.
func Snippet(body string, n int) string {
	if doc, err := goquery.NewDocumentFromReader(strings.NewReader(body)); err == nil {
		doc.Find("script, style").Remove()
		if t := doc.Text(); strings.TrimSpace(t) != "" {
			body = t
		}
	}
	body = strings.Join(strings.Fields(body), " ")
	if len(body) > n {
		body = body[:n] + "…"
	}
	return body
}
