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

func TestEmbeddedKentico(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "kentico" {
			if tpl.Path != "/CMSPages/logon.aspx" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template kentico")
}

func TestRunKentico(t *testing.T) {
	var postedUser, postedView string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/CMSPages/logon.aspx" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="Login1$UserName"><input name="Login1$Password"><input name="__VIEWSTATE" value="kvs">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("Login1$UserName")
		postedView = r.Form.Get("__VIEWSTATE")
		if postedUser == "administrator" && r.Form.Get("Login1$Password") == "secret" && postedView == "kvs" {
			w.Header().Set("Location", "/Admin/CMSAdministration.aspx")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/CMSPages/logon.aspx")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"kentico-cms"})
	if len(selected) != 1 || selected[0].ID != "kentico" {
		t.Fatalf("kentico match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "administrator", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "administrator" || postedView != "kvs" {
		t.Fatalf("posted user=%q viewstate=%q", postedUser, postedView)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "administrator", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
