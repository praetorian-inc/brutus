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
	"testing"
	"time"
)

func TestEmbeddedSuperset(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "superset" {
			if tpl.Path != "/login/" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template superset")
}

func TestRunSuperset(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="username"><input name="password"><input name="csrf_token" value="superset-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedCSRF = r.Form.Get("csrf_token")
		if postedUser == "admin" && r.Form.Get("password") == "secret" && postedCSRF == "superset-token" {
			w.Header().Set("Location", "/superset/welcome/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"superset"})
	if len(selected) != 1 || selected[0].ID != "superset" {
		t.Fatalf("superset match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "admin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedCSRF != "superset-token" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
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

func TestRunAirflow(t *testing.T) {
	var postedUser, postedCSRF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="username"><input name="password"><input name="csrf_token" value="airflow-token">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedCSRF = r.Form.Get("csrf_token")
		if postedUser == "airflow" && r.Form.Get("password") == "secret" && postedCSRF == "airflow-token" {
			w.Header().Set("Location", "/home")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"airflow"})
	if len(selected) != 1 || selected[0].ID != "airflow" {
		t.Fatalf("airflow match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "airflow", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "airflow" || postedCSRF != "airflow-token" {
		t.Fatalf("posted user=%q csrf=%q", postedUser, postedCSRF)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "airflow", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
