package winrm

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// Integration tests require a live WinRM server.
// Set environment variables to run:
//
//	WINRM_HOST=10.10.1.154
//	WINRM_USER=Administrator
//	WINRM_PASS=password
func skipIfNoServer(t *testing.T) (host, user, pass string) {
	t.Helper()
	host = os.Getenv("WINRM_HOST")
	user = os.Getenv("WINRM_USER")
	pass = os.Getenv("WINRM_PASS")
	if host == "" || user == "" || pass == "" {
		t.Skip("Skipping: set WINRM_HOST, WINRM_USER, WINRM_PASS to run integration tests")
	}
	return host, user, pass
}

func TestIntegration_ValidCredentials(t *testing.T) {
	host, user, pass := skipIfNoServer(t)

	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	result := p.Test(ctx, host, user, pass, 10*time.Second, brutus.PluginConfig{})

	assert.True(t, result.Success, "expected valid credentials to succeed")
	assert.Nil(t, result.Error, "expected no error for valid credentials")
}

func TestIntegration_InvalidCredentials(t *testing.T) {
	host, user, _ := skipIfNoServer(t)

	p := &Plugin{UseHTTPS: false}
	ctx := context.Background()
	result := p.Test(ctx, host, user, "definitely-wrong-password", 10*time.Second, brutus.PluginConfig{})

	assert.False(t, result.Success, "expected invalid credentials to fail")
	assert.Nil(t, result.Error, "expected nil error for auth failure (not connection error)")
}
