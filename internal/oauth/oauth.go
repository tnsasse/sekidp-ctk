// Package oauth implements the client side of the RFC 6749 token endpoint
// with enough knobs to send deliberately malformed requests.
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AuthMethod selects how client credentials are presented (Section 2.3.1).
type AuthMethod int

const (
	// AuthNone sends no secret; client_id is placed in the body if set.
	AuthNone AuthMethod = iota
	// AuthBasic uses the HTTP Basic scheme with form-urlencoded id and secret.
	AuthBasic
	// AuthBody sends client_id and client_secret as body parameters.
	AuthBody
	// AuthBoth uses Basic and body parameters at once (forbidden by Section 2.3).
	AuthBoth
)

func (m AuthMethod) String() string {
	return [...]string{"none", "basic", "body", "basic+body"}[m]
}

type Credentials struct {
	ID     string
	Secret string
}

// TokenRequest describes a single POST to the token endpoint.
type TokenRequest struct {
	Endpoint string
	Form     url.Values
	// RawBody, if non-empty, is sent verbatim instead of Form.Encode(); used to
	// send repeated parameters in a controlled order.
	RawBody string
	Auth    AuthMethod
	Client  Credentials
	// Authorization overrides the Authorization header when non-empty.
	Authorization string
	// Query is appended to the endpoint URL.
	Query url.Values
	// Method defaults to POST.
	Method string
}

// Response is a parsed token endpoint response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	// JSON holds the top-level object if the body was a JSON object.
	JSON    map[string]any
	JSONErr error
}

// Str returns a top-level string member.
func (r *Response) Str(key string) (string, bool) {
	v, ok := r.JSON[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Has reports whether the top-level member exists (of any type).
func (r *Response) Has(key string) bool {
	_, ok := r.JSON[key]
	return ok
}

func (r *Response) ErrorCode() string {
	s, _ := r.Str("error")
	return s
}

func (r *Response) Summary() string {
	if code := r.ErrorCode(); code != "" {
		desc, _ := r.Str("error_description")
		if desc != "" {
			return fmt.Sprintf("HTTP %d error=%s (%s)", r.Status, code, desc)
		}
		return fmt.Sprintf("HTTP %d error=%s", r.Status, code)
	}
	if r.Has("access_token") {
		return fmt.Sprintf("HTTP %d with access_token", r.Status)
	}
	body := string(r.Body)
	if len(body) > 120 {
		body = body[:120] + "…"
	}
	return fmt.Sprintf("HTTP %d %s", r.Status, body)
}

// BasicAuth builds an Authorization header value per Section 2.3.1: the client
// identifier and password are encoded with application/x-www-form-urlencoded
// (Appendix B) before being joined and base64-encoded.
func BasicAuth(c Credentials) string {
	raw := url.QueryEscape(c.ID) + ":" + url.QueryEscape(c.Secret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// Do sends the token request.
func Do(ctx context.Context, hc *http.Client, tr TokenRequest) (*Response, error) {
	form := url.Values{}
	for k, v := range tr.Form {
		form[k] = append([]string(nil), v...)
	}
	header := http.Header{}
	switch tr.Auth {
	case AuthNone:
		if tr.Client.ID != "" && form.Get("client_id") == "" {
			form.Set("client_id", tr.Client.ID)
		}
	case AuthBasic:
		header.Set("Authorization", BasicAuth(tr.Client))
	case AuthBody:
		form.Set("client_id", tr.Client.ID)
		form.Set("client_secret", tr.Client.Secret)
	case AuthBoth:
		header.Set("Authorization", BasicAuth(tr.Client))
		form.Set("client_id", tr.Client.ID)
		form.Set("client_secret", tr.Client.Secret)
	}
	if tr.Authorization != "" {
		header.Set("Authorization", tr.Authorization)
	}
	body := tr.RawBody
	if body == "" {
		body = form.Encode()
	} else if extra := authFormParams(tr, form); extra != "" {
		body += "&" + extra
	}

	endpoint := tr.Endpoint
	if len(tr.Query) > 0 {
		endpoint = AppendQuery(endpoint, tr.Query)
	}
	method := tr.Method
	if method == "" {
		method = http.MethodPost
	}
	var rdr io.Reader
	if method == http.MethodGet {
		endpoint = AppendQuery(endpoint, mustParseQuery(body))
	} else {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return nil, err
	}
	req.Header = header
	if rdr != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	out := &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		out.JSONErr = err
	} else {
		out.JSON = obj
	}
	return out, nil
}

// authFormParams returns the client authentication body parameters that must
// be appended to a RawBody request.
func authFormParams(tr TokenRequest, form url.Values) string {
	v := url.Values{}
	for _, k := range []string{"client_id", "client_secret"} {
		if form.Get(k) != "" && !strings.Contains(tr.RawBody, k+"=") {
			v.Set(k, form.Get(k))
		}
	}
	return v.Encode()
}

func mustParseQuery(s string) url.Values {
	v, _ := url.ParseQuery(s)
	return v
}

// AppendQuery adds parameters to a URL while retaining any existing query
// component (Sections 3.1 and 3.2 require this).
func AppendQuery(raw string, params url.Values) string {
	if len(params) == 0 {
		return raw
	}
	sep := "?"
	if strings.Contains(raw, "?") {
		sep = "&"
		if strings.HasSuffix(raw, "?") || strings.HasSuffix(raw, "&") {
			sep = ""
		}
	}
	return raw + sep + params.Encode()
}
