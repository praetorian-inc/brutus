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

func TestEmbeddedManageengine(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "manageengine" {
			if tpl.Path != "/j_security_check" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template manageengine")
}

func TestRunManageEngine(t *testing.T) {
	var postedUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/j_security_check" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("j_username")
		if postedUser == "admin" && r.Form.Get("j_password") == "admin" {
			w.Header().Set("Location", "/HomePage.do")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/showlogin.cc?error=invalid")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"manageengine"})
	if len(selected) != 1 || selected[0].ID != "manageengine" {
		t.Fatalf("manageengine match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" {
		t.Fatalf("posted user=%q", postedUser)
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
