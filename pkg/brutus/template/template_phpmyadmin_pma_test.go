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

func TestEmbeddedPhpmyadminPma(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "phpmyadmin-pma" {
			if tpl.Path != "/pma/index.php" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template phpmyadmin-pma")
}

func TestRunPhpMyAdminPMAPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pma/index.php" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<input name="token" value="pma-token">`))
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("pma_password") == "root" && r.Form.Get("token") == "pma-token" {
			_, _ = w.Write([]byte("server databases"))
			return
		}
		_, _ = w.Write([]byte("Access denied"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"phpmyadmin-pma"})
	if len(selected) != 1 || selected[0].Path != "/pma/index.php" {
		t.Fatalf("pma match = %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, selected, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].TemplateID != "phpmyadmin-pma" || hits[0].Password != "root" {
		t.Fatalf("hits = %+v", hits)
	}
}
