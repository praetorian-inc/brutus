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

// Package template runs product-specific default-credential checks.
//
// A template names the Nerva technology it applies to, the login request, and
// how a success response differs from a failure. Generic HTTP Basic Auth
// against "/" is not a template.
package template

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed templates/*.yaml
var embedded embed.FS

// Method is the login request shape.
const (
	MethodBasic = "basic"
	MethodForm  = "form"
	MethodJSON  = "json"
)

// Template is one product login check.
type Template struct {
	ID            string            `yaml:"id"`
	Name          string            `yaml:"name"`
	Nerva         []string          `yaml:"nerva"`
	Method        string            `yaml:"method"`
	Path          string            `yaml:"path"`
	UsernameField string            `yaml:"username_field"`
	PasswordField string            `yaml:"password_field"`
	Extra         map[string]string `yaml:"extra,omitempty"`
	Prefetch      *Prefetch         `yaml:"prefetch,omitempty"`
	Success       Matchers          `yaml:"success"`
	Creds         []string          `yaml:"creds,omitempty"`
}

// Prefetch is an unauthenticated GET whose body supplies {{name}} values.
type Prefetch struct {
	Path    string            `yaml:"path"`
	Extract map[string]string `yaml:"extract"`
}

// Matchers are AND conditions. Empty Status on a basic template means 2xx.
type Matchers struct {
	Status       []int    `yaml:"status,omitempty"`
	Body         []string `yaml:"body,omitempty"`
	BodyAbsent   []string `yaml:"body_absent,omitempty"`
	Header       string   `yaml:"header,omitempty"`
	HeaderHas    string   `yaml:"header_has,omitempty"`
	HeaderAbsent string   `yaml:"header_absent,omitempty"`
}

// LoadEmbedded returns the templates compiled into the binary.
func LoadEmbedded() ([]Template, error) {
	return loadFS(embedded, "templates")
}

// LoadDir reads *.yaml templates from dir. Files that fail to parse are errors.
func LoadDir(dir string) ([]Template, error) {
	return loadFS(os.DirFS(dir), ".")
}

func loadFS(fsys fs.FS, dir string) ([]Template, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading templates: %w", err)
	}
	var out []Template
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := name
		if dir != "." {
			path = dir + "/" + name
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		t, err := Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no templates in %s", dir)
	}
	return out, nil
}

// Parse decodes and validates one template document.
func Parse(raw []byte) (Template, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var t Template
	if err := dec.Decode(&t); err != nil {
		return Template{}, fmt.Errorf("parse yaml: %w", err)
	}
	if err := t.validate(); err != nil {
		return Template{}, err
	}
	return t, nil
}

func (t Template) validate() error {
	if t.ID == "" {
		return fmt.Errorf("template id is required")
	}
	switch t.Method {
	case MethodBasic, MethodForm, MethodJSON:
	default:
		return fmt.Errorf("%s: method %q must be basic, form, or json", t.ID, t.Method)
	}
	if !strings.HasPrefix(t.Path, "/") {
		return fmt.Errorf("%s: path %q must start with /", t.ID, t.Path)
	}
	if len(t.Nerva) == 0 {
		return fmt.Errorf("%s: nerva technology names are required", t.ID)
	}
	if t.Method != MethodBasic {
		if t.UsernameField == "" || t.PasswordField == "" {
			return fmt.Errorf("%s: username_field and password_field are required", t.ID)
		}
		if len(t.Success.Status) == 0 && len(t.Success.Body) == 0 && t.Success.Header == "" {
			return fmt.Errorf("%s: success matchers are required for %s", t.ID, t.Method)
		}
	}
	for _, c := range t.Creds {
		if _, _, ok := splitCred(c); !ok {
			return fmt.Errorf("%s: cred %q is not user:pass", t.ID, c)
		}
	}
	if t.Prefetch != nil {
		if t.Prefetch.Path == "" || len(t.Prefetch.Extract) == 0 {
			return fmt.Errorf("%s: prefetch needs a path and extract rules", t.ID)
		}
	}
	return nil
}

// Pair is one username and password.
type Pair struct {
	Username string
	Password string
}

// Pairs returns embedded credentials. An empty password is allowed.
func (t Template) Pairs() []Pair {
	var out []Pair
	for _, c := range t.Creds {
		user, pass, ok := splitCred(c)
		if ok {
			out = append(out, Pair{Username: user, Password: pass})
		}
	}
	return out
}

func splitCred(c string) (string, string, bool) {
	user, pass, ok := strings.Cut(c, ":")
	if !ok || user == "" {
		return "", "", false
	}
	return user, pass, true
}

// Match returns templates whose nerva names intersect techs.
// Comparison is case-insensitive. An empty techs list returns nothing:
// a URL alone is not a reason to try every product.
func Match(tpls []Template, techs []string) []Template {
	if len(techs) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, tech := range techs {
		want[strings.ToLower(strings.TrimSpace(tech))] = true
	}
	var out []Template
	for _, t := range tpls {
		for _, name := range t.Nerva {
			if want[strings.ToLower(name)] {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// LoadExtra merges a directory of operator templates onto embedded ones.
// Operator ids replace embedded ids.
func LoadExtra(dir string) ([]Template, error) {
	base, err := LoadEmbedded()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return base, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("template dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("template dir %s is not a directory", dir)
	}
	extra, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}
	byID := map[string]Template{}
	var order []string
	for _, t := range base {
		byID[t.ID] = t
		order = append(order, t.ID)
	}
	for _, t := range extra {
		if _, ok := byID[t.ID]; !ok {
			order = append(order, t.ID)
		}
		byID[t.ID] = t
	}
	out := make([]Template, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}
