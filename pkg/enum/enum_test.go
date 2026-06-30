// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enum

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// TestHTTPClientContext — Section E: WithHTTPClient / HTTPClientFromContext
// ---------------------------------------------------------------------------

func TestHTTPClientContext_RoundTrip(t *testing.T) {
	client := &http.Client{}
	ctx := WithHTTPClient(context.Background(), client)
	got := HTTPClientFromContext(ctx)
	assert.Same(t, client, got, "HTTPClientFromContext must return the same *http.Client stored by WithHTTPClient")
}

func TestHTTPClientContext_Default(t *testing.T) {
	got := HTTPClientFromContext(context.Background())
	assert.Nil(t, got, "HTTPClientFromContext on a plain Background context must return nil")
}

// ---------------------------------------------------------------------------
// TestProxyURLContext — Section E: WithProxyURL / ProxyURLFromContext
// ---------------------------------------------------------------------------

func TestProxyURLContext_RoundTrip(t *testing.T) {
	const wantURL = "http://proxy.example:8080"
	ctx := WithProxyURL(context.Background(), wantURL)
	got := ProxyURLFromContext(ctx)
	assert.Equal(t, wantURL, got, "ProxyURLFromContext must return the URL stored by WithProxyURL")
}

func TestProxyURLContext_Default(t *testing.T) {
	got := ProxyURLFromContext(context.Background())
	assert.Equal(t, "", got, "ProxyURLFromContext on a plain Background context must return empty string")
}
