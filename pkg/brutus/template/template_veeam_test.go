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

func TestEmbeddedVeeam(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "veeam" {
			if tpl.Path != "/login.aspx" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template veeam")
}

func TestRunVeeam(t *testing.T) {
	var postedUser, postedView string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login.aspx" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="txtLogin"><input name="txtPassword"><input name="__VIEWSTATE" value="veeam-vs">`))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("txtLogin")
		postedView = r.Form.Get("__VIEWSTATE")
		if postedUser == "veeamadmin" && r.Form.Get("txtPassword") == "secret" && postedView == "veeam-vs" {
			w.Header().Set("Location", "/default.aspx")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/login.aspx")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"veeam_backup_enterprise_manager_web"})
	if len(selected) != 1 || selected[0].ID != "veeam" {
		t.Fatalf("veeam match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "veeamadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "veeamadmin" || postedView != "veeam-vs" {
		t.Fatalf("posted user=%q viewstate=%q", postedUser, postedView)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "veeamadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
