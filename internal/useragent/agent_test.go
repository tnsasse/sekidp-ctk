package useragent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// loginServer serves a two-step login + consent UI and then redirects to the
// client callback, the way typical authorization servers do.
func loginServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s1", Path: "/"})
		fmt.Fprintf(w, `<html><form id="login" method="post" action="/login?state=%s">
			<input type="hidden" name="csrf" value="tok">
			<input name="user"><input type="password" name="pass">
			<input type="checkbox" name="remember" value="yes">
			<button name="go" value="1">Sign in</button></form></html>`, r.URL.Query().Get("state"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "s1" {
			http.Error(w, "no session", 400)
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("csrf") != "tok" || r.PostForm.Get("go") != "1" || r.PostForm.Has("remember") {
			http.Error(w, "bad form: "+r.PostForm.Encode(), 400)
			return
		}
		if r.PostForm.Get("user") != "alice" || r.PostForm.Get("pass") != "pw" {
			fmt.Fprint(w, `<form id="login" method="post" action="/login"><input type="hidden" name="csrf" value="tok">
				<input name="user"><input name="pass"><button name="go" value="1">Retry</button></form>`)
			return
		}
		http.Redirect(w, r, "/consent?state="+r.URL.Query().Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/consent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprintf(w, `<form method="post"><input type="hidden" name="state" value="%s">
				<input type="checkbox" name="grant_scope" value="a"><input type="checkbox" name="grant_scope" value="b">
				<button name="accept">Yes</button><button name="deny">No</button></form>`, r.URL.Query().Get("state"))
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Has("deny") {
			http.Redirect(w, r, "https://client.test/cb?error=access_denied&state="+r.PostForm.Get("state"), http.StatusFound)
			return
		}
		code := "abc"
		if g := r.PostForm["grant_scope"]; len(g) > 0 {
			code = "scoped-" + fmt.Sprint(len(g))
		}
		http.Redirect(w, r, "https://client.test/cb?code="+code+"&state="+r.PostForm.Get("state"), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func agent(steps []Step, password string) *Agent {
	return &Agent{
		Transport:   http.DefaultTransport,
		Steps:       steps,
		Vars:        map[string]string{"username": "alice", "password": password},
		StopOrigins: []string{"https://client.test"},
	}
}

var loginStep = Step{Name: "login", Form: "form#login",
	Fields: map[string]string{"user": "{{username}}", "pass": "{{password}}"}, Submit: "go"}

func TestAgentApproves(t *testing.T) {
	srv := loginServer(t)
	steps := []Step{loginStep, {Name: "consent", Form: "form:has(button[name=accept])", Submit: "accept"}}
	out, err := agent(steps, "pw").Run(context.Background(), srv.URL+"/authorize?state=xyz")
	if err != nil {
		t.Fatal(err)
	}
	if out.Redirect == nil || out.Redirect.Query().Get("code") != "abc" || out.Redirect.Query().Get("state") != "xyz" {
		t.Fatalf("unexpected outcome: %s", out)
	}
	if fmt.Sprint(out.StepsUsed) != "[login consent]" {
		t.Fatalf("steps used: %v", out.StepsUsed)
	}
}

func TestAgentDenies(t *testing.T) {
	srv := loginServer(t)
	steps := []Step{loginStep, {Name: "deny", Form: "form:has(button[name=deny])", Submit: "deny"}}
	out, err := agent(steps, "pw").Run(context.Background(), srv.URL+"/authorize?state=s")
	if err != nil {
		t.Fatal(err)
	}
	if out.Redirect == nil || out.Redirect.Query().Get("error") != "access_denied" {
		t.Fatalf("unexpected outcome: %s", out)
	}
}

func TestAgentDetectsLoginLoop(t *testing.T) {
	srv := loginServer(t)
	_, err := agent([]Step{loginStep}, "wrong").Run(context.Background(), srv.URL+"/authorize")
	if err == nil {
		t.Fatal("expected an error for rejected credentials")
	}
}

func TestAgentStopsAtUnmatchedPage(t *testing.T) {
	srv := loginServer(t)
	out, err := agent(nil, "pw").Run(context.Background(), srv.URL+"/authorize")
	if err != nil {
		t.Fatal(err)
	}
	if out.Redirect != nil || out.PageStatus != 200 {
		t.Fatalf("expected to stop at the login page: %s", out)
	}
}

func TestAgentTicksCheckboxes(t *testing.T) {
	srv := loginServer(t)
	steps := []Step{loginStep, {Name: "consent", Form: "form:has(button[name=accept])", Submit: "accept", Check: []string{"grant_scope"}}}
	out, err := agent(steps, "pw").Run(context.Background(), srv.URL+"/authorize?state=s")
	if err != nil {
		t.Fatal(err)
	}
	if out.Redirect == nil || out.Redirect.Query().Get("code") != "scoped-2" {
		t.Fatalf("expected both checkboxes to be submitted: %s", out)
	}
}
