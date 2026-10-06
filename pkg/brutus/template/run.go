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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

const (
	maxBody       = 8192
	invalidSecret = "__brutus_invalid__"
)

// Options controls one run.
type Options struct {
	Timeout  time.Duration
	TLSMode  string
	ProxyURL string
	// Creds, when set, replace each template's embedded pairs.
	Creds []Pair
}

// Hit is a credential the success matchers accepted and the negative control rejected.
type Hit struct {
	TemplateID string
	Name       string
	URL        string
	Username   string
	Password   string
}

// Run tries each template against baseURL. baseURL is scheme://host[:port].
// Templates whose negative control already looks successful are skipped.
func Run(ctx context.Context, baseURL string, tpls []Template, opt Options) ([]Hit, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("base URL must be scheme://host[:port]")
	}
	client, err := newClient(opt)
	if err != nil {
		return nil, err
	}
	var hits []Hit
	for _, t := range tpls {
		if err := ctx.Err(); err != nil {
			return hits, err
		}
		pairs := t.Pairs()
		if len(opt.Creds) > 0 {
			pairs = opt.Creds
		}
		if len(pairs) == 0 {
			continue
		}
		found, err := runOne(ctx, client, base, t, pairs)
		if err != nil {
			return hits, fmt.Errorf("%s: %w", t.ID, err)
		}
		hits = append(hits, found...)
	}
	return hits, nil
}

func newClient(opt Options) (*http.Client, error) {
	var tlsCfg *tls.Config
	if opt.TLSMode != "" && opt.TLSMode != "disable" {
		tlsCfg = brutus.BuildTLSConfig(opt.TLSMode)
	}
	c, err := brutus.NewHTTPClientWithProxy(opt.Timeout, tlsCfg, opt.ProxyURL)
	if err != nil {
		return nil, err
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c, nil
}

func runOne(ctx context.Context, client *http.Client, base *url.URL, t Template, pairs []Pair) ([]Hit, error) {
	vars, err := prefetch(ctx, client, base, t)
	if err != nil {
		return nil, err
	}
	if t.Method == MethodBasic {
		anon, err := doLogin(ctx, client, base, t, Pair{}, vars, true)
		if err != nil {
			return nil, err
		}
		if anon.Status >= 200 && anon.Status < 300 {
			return nil, nil
		}
	} else {
		neg := pairs[0]
		neg.Password = invalidSecret
		negResp, err := doLogin(ctx, client, base, t, neg, vars, false)
		if err != nil {
			return nil, err
		}
		if match(t.Success, negResp) {
			return nil, nil
		}
	}
	var hits []Hit
	for _, pair := range pairs {
		resp, err := doLogin(ctx, client, base, t, pair, vars, false)
		if err != nil {
			return hits, err
		}
		if !success(t, resp) {
			continue
		}
		hits = append(hits, Hit{
			TemplateID: t.ID,
			Name:       t.Name,
			URL:        resolve(base, substitute(t.Path, vars)),
			Username:   pair.Username,
			Password:   pair.Password,
		})
	}
	return hits, nil
}

type response struct {
	Status int
	Header http.Header
	Body   string
}

func success(t Template, resp response) bool {
	if t.Method == MethodBasic && len(t.Success.Status) == 0 && len(t.Success.Body) == 0 && t.Success.Header == "" {
		return resp.Status >= 200 && resp.Status < 300
	}
	return match(t.Success, resp)
}

func match(m Matchers, resp response) bool {
	if len(m.Status) > 0 && !containsInt(m.Status, resp.Status) {
		return false
	}
	body := strings.ToLower(resp.Body)
	for _, want := range m.Body {
		if !strings.Contains(body, strings.ToLower(want)) {
			return false
		}
	}
	for _, ban := range m.BodyAbsent {
		if strings.Contains(body, strings.ToLower(ban)) {
			return false
		}
	}
	if m.Header != "" {
		got := strings.ToLower(resp.Header.Get(m.Header))
		if m.HeaderHas != "" && !strings.Contains(got, strings.ToLower(m.HeaderHas)) {
			return false
		}
		if m.HeaderAbsent != "" && strings.Contains(got, strings.ToLower(m.HeaderAbsent)) {
			return false
		}
	}
	return true
}

func prefetch(ctx context.Context, client *http.Client, base *url.URL, t Template) (map[string]string, error) {
	vars := map[string]string{}
	if t.Prefetch == nil {
		return vars, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolve(base, t.Prefetch.Path), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	for name, expr := range t.Prefetch.Extract {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("extract %s: %w", name, err)
		}
		found := re.FindStringSubmatch(body.Body)
		if len(found) < 2 {
			continue
		}
		vars[name] = found[1]
	}
	return vars, nil
}

func doLogin(ctx context.Context, client *http.Client, base *url.URL, t Template, pair Pair, vars map[string]string, anonymous bool) (response, error) {
	endpoint := resolve(base, substitute(t.Path, vars))
	var req *http.Request
	var err error
	switch t.Method {
	case MethodBasic:
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return response{}, err
		}
		if !anonymous {
			req.SetBasicAuth(pair.Username, pair.Password)
		}
	case MethodForm:
		form := url.Values{}
		form.Set(t.UsernameField, pair.Username)
		form.Set(t.PasswordField, pair.Password)
		for k, v := range t.Extra {
			v = substitute(v, vars)
			if v == "" {
				continue
			}
			form.Set(k, v)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return response{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case MethodJSON:
		payload := fmt.Sprintf(`{%q:%q,%q:%q}`, t.UsernameField, pair.Username, t.PasswordField, pair.Password)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
		if err != nil {
			return response{}, err
		}
		req.Header.Set("Content-Type", "application/json")
	default:
		return response{}, fmt.Errorf("unknown method %s", t.Method)
	}
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	return readBody(resp)
}

func readBody(resp *http.Response) (response, error) {
	defer func() { _ = resp.Body.Close() }()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return response{}, err
	}
	return response{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: string(buf)}, nil
}

func resolve(base *url.URL, path string) string {
	ref, err := url.Parse(path)
	if err != nil {
		return base.String() + path
	}
	return base.ResolveReference(ref).String()
}

func substitute(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
