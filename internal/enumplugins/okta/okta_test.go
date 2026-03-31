package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, "okta", p.Name())
}

func TestPlugin_Check_Exists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"E0000004","errorSummary":"Authentication failed"}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "user@company.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, "okta", result.Service)
}

func TestPlugin_Check_NotExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "unknown@company.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.False(t, result.Exists)
}

func TestPlugin_Check_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "user@company.com", 5*time.Second)

	assert.NotNil(t, result.Error)
	assert.False(t, result.Exists)
}
