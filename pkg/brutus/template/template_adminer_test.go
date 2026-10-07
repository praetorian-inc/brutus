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

func TestEmbeddedAdminer(t *testing.T) {
	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		if tpl.ID == "adminer" {
			if tpl.Path != "/" {
				t.Fatalf("path = %q", tpl.Path)
			}
			return
		}
	}
	t.Fatal("missing embedded template adminer")
}

func TestRunAdminerPHP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adminer.php" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("auth[username]") == "root" && r.Form.Get("auth[password]") == "" && r.Form.Get("auth[driver]") == "server" {
			_, _ = w.Write([]byte("Logout"))
			return
		}
		_, _ = w.Write([]byte("Login - Adminer"))
	}))
	defer srv.Close()

	tpls, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	selected := Match(tpls, []string{"adminer"})
	var php Template
	for _, tplt := range selected {
		if tplt.ID == "adminer-php" {
			php = tplt
		}
	}
	if php.Path != "/adminer.php" {
		t.Fatalf("adminer-php missing from %+v", selected)
	}
	hits, err := Run(context.Background(), srv.URL, []Template{php}, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Password != "" {
		t.Fatalf("hits = %+v", hits)
	}
}
