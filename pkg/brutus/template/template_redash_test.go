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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedRedash(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "redash" {
			if tpl.Path != "/login" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template redash")
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

func TestRunRedash(t *testing.T) {
	var postedEmail, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="email"><input name="password"><input name="csrf_token" value="redash-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedEmail = r.Form.Get("email")
		postedCSRF = r.Form.Get("csrf_token")
		if postedEmail == "analyst@example.com" && r.Form.Get("password") == "secret" && postedCSRF == "redash-token" {
			w.Header().Set("Location", "/queries")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"redash"})
	if len(selected) != 1 || selected[0].ID != "redash" {
		t.Fatalf("redash match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "analyst@example.com", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedEmail != "analyst@example.com" || postedCSRF != "redash-token" {
		t.Fatalf("posted email=%q csrf=%q", postedEmail, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "analyst@example.com", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}

func TestRunGrafana(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		raw := string(body)
		if !strings.Contains(raw, `"user":`) || strings.Contains(r.Header.Get("Authorization"), "Basic") {
			http.Error(w, "expected JSON user field, not Basic Auth", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(raw, `"user":"admin"`) && strings.Contains(raw, `"password":"admin"`) {
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
	selected := Match(tpls, []string{"grafana"})
	if len(selected) != 1 || selected[0].ID != "grafana-login" || selected[0].Method != "json" {
		t.Fatalf("grafana match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "admin" {
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
