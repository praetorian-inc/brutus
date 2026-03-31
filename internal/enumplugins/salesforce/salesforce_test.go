package salesforce

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
	assert.Equal(t, "salesforce", p.Name())
}

func TestPlugin_Check_Exists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Please check your username and password. If you still can't log in, contact your administrator.</body></html>`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "valid@company.com", 5*time.Second)

	require.Nil(t, result.Error)
	assert.True(t, result.Exists)
	assert.Equal(t, "salesforce", result.Service)
	assert.Equal(t, "valid@company.com", result.Email)
}

func TestPlugin_Check_NotExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Username not found. Please try again.</body></html>`))
	}))
	defer srv.Close()

	p := &Plugin{baseURL: srv.URL}
	result := p.Check(context.Background(), "invalid@company.com", 5*time.Second)

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
