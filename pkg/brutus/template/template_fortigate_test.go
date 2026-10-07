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

func TestEmbeddedFortigate(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "fortigate" {
			if tpl.Path != "/remote/logincheck" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template fortigate")
}

func TestRunFortiGate(t *testing.T) {
	var postedUser, postedAjax string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/remote/logincheck" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedUser = r.Form.Get("username")
		postedAjax = r.Form.Get("ajax")
		if postedUser == "admin" && r.Form.Get("credential") == "admin" && postedAjax == "1" {
			_, _ = w.Write([]byte("ret=1,redir=/remote/hostcheck"))
			return
		}
		_, _ = w.Write([]byte("ret=0"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"fortinet-fortigate"})
	if len(selected) != 1 || selected[0].ID != "fortigate" || selected[0].Path != "/remote/logincheck" {
		t.Fatalf("fortigate match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if postedUser != "admin" || postedAjax != "1" {
		t.Fatalf("posted user=%q ajax=%q", postedUser, postedAjax)
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
