// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadEmbedded(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(tpls) < 10 {
		t.Fatalf("embedded templates = %d, want at least 10", len(tpls))
	}
	ids := map[string]bool{}
	for _, tplt := range tpls {
		if ids[tplt.ID] {
			t.Errorf("duplicate template id %s", tplt.ID)
		}
		ids[tplt.ID] = true
		if len(tplt.Nerva) == 0 || !strings.HasPrefix(tplt.Path, "/") {
			t.Errorf("%s missing nerva name or path", tplt.ID)
		}
	}
	for _, id := range []string{"tomcat-manager", "grafana-login", "phpmyadmin", "adminer", "fortigate", "gitlab", "pgadmin", "watchguard"} {
		if !ids[id] {
			t.Errorf("missing embedded template %s", id)
		}
	}
}

func TestMatchRequiresTechnology(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if got := Match(tpls, nil); len(got) != 0 {
		t.Fatalf("empty technologies matched %d templates", len(got))
	}
	got := Match(tpls, []string{"Adminer"})
	if len(got) != 1 || got[0].ID != "adminer" {
		t.Fatalf("adminer match = %+v", got)
	}
	if len(Match(tpls, []string{"nginx"})) != 0 {
		t.Fatal("unrelated technology must not select a template")
	}
}

func TestRunBasicHitAndOpenSkip(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manager/html" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="tomcat"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sawAuth = user + ":" + pass
		if user == "tomcat" && pass == "tomcat" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Tomcat Web Application Manager"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits, err := Run(context.Background(), srv.URL, Match(tpls, []string{"tomcat"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "tomcat" || hits[0].Password != "tomcat" {
		t.Fatalf("hits = %+v, last auth %q", hits, sawAuth)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, Match(tpls, []string{"tomcat"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open path reported hits: %+v", hits)
	}
}

func TestRunFormUsesPrefetchAndRejectsWeakMatcher(t *testing.T) {
	var postedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="token" value="abc123">`))
			return
		}
		_ = r.ParseForm()
		postedToken = r.Form.Get("token")
		if r.Form.Get("pma_password") == "root" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("server databases"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Access denied"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits, err := Run(context.Background(), srv.URL, Match(tpls, []string{"phpmyadmin"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedToken != "abc123" {
		t.Fatalf("prefetch token = %q", postedToken)
	}
	if len(hits) != 1 || hits[0].Password != "root" {
		t.Fatalf("hits = %+v", hits)
	}

	weak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("always ok"))
	}))
	defer weak.Close()
	hits, err = Run(context.Background(), weak.URL, Match(tpls, []string{"phpmyadmin"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("weak matcher reported hits: %+v", hits)
	}
}

func TestRunJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 256)
		n, _ := r.Body.Read(body)
		raw := string(body[:n])
		if strings.Contains(raw, `"password":"admin"`) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"Logged in"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid username or password"}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	hits, err := Run(context.Background(), srv.URL, Match(tpls, []string{"grafana"}), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].TemplateID != "grafana-login" {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestParseNerva(t *testing.T) {
	in := strings.NewReader(`{"ip":"10.0.0.5","port":443,"protocol":"https","tls":true,"metadata":{"technologies":["fortinet-fortigate"]}}
{"ip":"10.0.0.6","port":22,"protocol":"ssh","metadata":{"technologies":["openssh"]}}
{"url":"http://panel.example","technologies":["adminer"]}
{"ip":"10.0.0.7","port":80,"protocol":"http"}
`)
	got, err := ParseNerva(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("targets = %+v", got)
	}
	if got[0].BaseURL != "https://10.0.0.5:443" || got[0].Technologies[0] != "fortinet-fortigate" {
		t.Fatalf("first target = %+v", got[0])
	}
	if got[1].BaseURL != "http://panel.example" {
		t.Fatalf("second target = %+v", got[1])
	}
}

func TestRunPgAdmin(t *testing.T) {
	var postedToken, postedEmail string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form><input name="csrf_token" value="pga-token"><title>pgAdmin 4</title></form>`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedToken = r.Form.Get("csrf_token")
		postedEmail = r.Form.Get("email")
		if r.Form.Get("email") == "admin@example.com" && r.Form.Get("password") == "secret" {
			w.Header().Set("Location", "/browser/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login?error=1")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("invalid login"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"pgadmin-login"})
	if len(selected) != 1 || selected[0].ID != "pgadmin" {
		t.Fatalf("pgadmin-login match = %+v", selected)
	}
	creds := []Pair{{Username: "admin@example.com", Password: "secret"}}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second, Creds: creds})
	if err != nil {
		t.Fatal(err)
	}
	if postedToken != "pga-token" || postedEmail != "admin@example.com" {
		t.Fatalf("posted token=%q email=%q", postedToken, postedEmail)
	}
	if len(hits) != 1 || hits[0].Username != "admin@example.com" || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin@example.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunWatchGuard(t *testing.T) {
	var postedUser, postedDomain string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("user")
		postedDomain = r.Form.Get("domain")
		if r.Form.Get("user") == "admin" && r.Form.Get("password") == "secret" && r.Form.Get("domain") == "Firebox-DB" {
			w.Header().Set("Location", "/auth/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/auth/login?failed=1")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"watchguard-firebox"})
	if len(selected) != 1 || selected[0].ID != "watchguard" {
		t.Fatalf("watchguard match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedDomain != "Firebox-DB" {
		t.Fatalf("posted user=%q domain=%q", postedUser, postedDomain)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
