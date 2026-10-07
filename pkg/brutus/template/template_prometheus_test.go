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

func TestEmbeddedPrometheus(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "prometheus" {
			if tpl.Path != "/api/v1/status/buildinfo" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template prometheus")
}

func TestRunPrometheus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status/buildinfo" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="prometheus"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if user == "prom" && pass == "secret" {
			_, _ = w.Write([]byte(`{"status":"success","data":{"version":"2.51.0"}}`))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"prometheus"})
	if len(selected) != 1 || selected[0].ID != "prometheus" {
		t.Fatalf("prometheus match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "prom", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer open.Close()
	hits, err = Run(context.Background(), open.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "prom", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("open Prometheus buildinfo reported a credential hit: %+v", hits)
	}
}
