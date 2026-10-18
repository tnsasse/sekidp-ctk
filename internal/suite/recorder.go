package suite

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const maxRecordedBody = 2048

// sensitive parameters whose values are redacted from recorded exchanges.
var sensitiveParams = map[string]bool{
	"password": true, "client_secret": true,
}

type recorder struct {
	base http.RoundTripper
	t    *T
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	resp, err := r.base.RoundTrip(req)
	ex := Exchange{Request: formatRequest(req, reqBody)}
	if err != nil {
		ex.Response = "transport error: " + err.Error()
		r.t.record(ex)
		return nil, err
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	ex.Response = formatResponse(resp, respBody)
	r.t.record(ex)
	return resp, nil
}

func formatRequest(req *http.Request, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", req.Method, redactURL(req.URL))
	writeHeaders(&b, req.Header)
	if len(body) > 0 {
		b.WriteString("\n")
		b.WriteString(truncate(redactForm(string(body))))
	}
	return b.String()
}

func formatResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d\n", resp.StatusCode)
	writeHeaders(&b, resp.Header)
	if len(body) > 0 {
		b.WriteString("\n")
		b.WriteString(truncate(string(body)))
	}
	return b.String()
}

func writeHeaders(b *strings.Builder, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			switch strings.ToLower(k) {
			case "authorization":
				if i := strings.IndexByte(v, ' '); i > 0 {
					v = v[:i] + " <redacted>"
				}
			case "cookie", "set-cookie":
				v = "<redacted>"
			}
			fmt.Fprintf(b, "%s: %s\n", k, v)
		}
	}
}

func redactURL(u *url.URL) string {
	c := *u
	if c.RawQuery != "" {
		c.RawQuery = redactForm(c.RawQuery)
	}
	return c.String()
}

// redactForm masks sensitive values in a form-encoded string, preserving
// parameter order and repetition.
func redactForm(s string) string {
	parts := strings.Split(s, "&")
	for i, p := range parts {
		k, _, found := strings.Cut(p, "=")
		if name, err := url.QueryUnescape(k); err == nil && found && sensitiveParams[name] {
			parts[i] = k + "=***"
		}
	}
	return strings.Join(parts, "&")
}

func truncate(s string) string {
	if len(s) > maxRecordedBody {
		return s[:maxRecordedBody] + fmt.Sprintf("… (%d bytes truncated)", len(s)-maxRecordedBody)
	}
	return s
}
