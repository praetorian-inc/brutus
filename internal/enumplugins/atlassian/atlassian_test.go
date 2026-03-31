package atlassian

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
	assert.Equal(t, "atlassian", p.Name())
}

func TestPlugin_Check_Exists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"login"}`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "user@company.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, "atlassian", result.Service)
	assert.Equal(t, "user@company.com", result.Email)
}

func TestPlugin_Check_NotExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"signup"}`))
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
