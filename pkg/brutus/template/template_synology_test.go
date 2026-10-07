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

func TestEmbeddedSynology(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "synology" {
			if tpl.Path != "/webapi/auth.cgi" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template synology")
}

func TestRunSynology(t *testing.T) {
	var postedAccount, postedAPI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/auth.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		postedAccount = r.Form.Get("account")
		postedAPI = r.Form.Get("api")
		w.Header().Set("Content-Type", "application/json")
		if postedAccount == "nasadmin" && r.Form.Get("passwd") == "secret" && postedAPI == "SYNO.API.Auth" {
			_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"abc"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":400}}`))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"synology-dsm"})
	if len(selected) != 1 || selected[0].ID != "synology" {
		t.Fatalf("synology match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "nasadmin", Password: "secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postedAccount != "nasadmin" || postedAPI != "SYNO.API.Auth" {
		t.Fatalf("posted account=%q api=%q", postedAccount, postedAPI)
	}
	if len(hits) != 1 || hits[0].Password != "secret" {
		t.Fatalf("hits = %+v", hits)
	}

	miss, err := Run(context.Background(), srv.URL, selected, Options{
		Timeout: 2 * time.Second,
		Creds:   []Pair{{Username: "nasadmin", Password: "wrong"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 {
		t.Fatalf("wrong password reported a hit: %+v", miss)
	}
}
