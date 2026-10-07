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

func TestEmbeddedSitecore(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "sitecore" {
			if tpl.Path != "/sitecore/login" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template sitecore")
}

func TestRunSitecore(t *testing.T) {
	var postedUser, postedView string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sitecore/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="UserName"><input name="Password"><input name="__VIEWSTATE" value="vs123">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("UserName")
		postedView = r.Form.Get("__VIEWSTATE")
		if postedUser == "admin" && r.Form.Get("Password") == "b" && postedView == "vs123" {
			w.Header().Set("Location", "/sitecore/shell")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/sitecore/login")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("Login failed"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"sitecore"})
	if len(selected) != 1 || selected[0].ID != "sitecore" {
		t.Fatalf("sitecore match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedView != "vs123" {
		t.Fatalf("posted user=%q viewstate=%q", postedUser, postedView)
	}
	if len(hits) != 1 || hits[0].Username != "admin" || hits[0].Password != "b" {
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
