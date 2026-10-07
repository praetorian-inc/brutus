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

func TestEmbeddedIvanti(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "ivanti" {
			if tpl.Path != "/dana-na/auth/url_default/login.cgi" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template ivanti")
}

func TestRunIvanti(t *testing.T) {
	var postedUser, postedRealm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dana-na/auth/url_default/login.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedRealm = r.Form.Get("realm")
		if postedUser == "vpnuser" && r.Form.Get("password") == "secret" && postedRealm == "Users" {
			w.Header().Set("Location", "/dana/home/index.cgi")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "/dana-na/auth/url_default/welcome.cgi?p=failed")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"ivanti-connect-secure"})
	if len(selected) != 1 || selected[0].ID != "ivanti" {
		t.Fatalf("ivanti match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "vpnuser", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "vpnuser" || postedRealm != "Users" {
		t.Fatalf("posted user=%q realm=%q", postedUser, postedRealm)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "vpnuser", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
