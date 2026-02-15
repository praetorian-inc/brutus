package brutus

import (
	"testing"
)

func TestDefaultCredentials_LoadsWordlists(t *testing.T) {
	protocols := []string{"ssh", "mysql", "ftp", "redis", "postgresql", "vnc", "rdp", "smb", "mongodb", "snmp"}
	for _, proto := range protocols {
		creds := DefaultCredentials(proto)
		if len(creds) == 0 {
			t.Errorf("DefaultCredentials(%q) returned no credentials", proto)
		}
	}
}

func TestDefaultCredentials_UnknownProtocol(t *testing.T) {
	creds := DefaultCredentials("nonexistent")
	if creds != nil {
		t.Errorf("expected nil for unknown protocol, got %d credentials", len(creds))
	}
}

func TestApplyDefaults_SSH_LoadsBadkeysAndWordlist(t *testing.T) {
	cfg := &Config{Target: "x:22", Protocol: "ssh", UseDefaults: true}
	cfg.applyDefaults()

	if len(cfg.Credentials) == 0 {
		t.Fatal("expected badkeys + wordlist credentials, got none")
	}

	// Should have key-based credentials (badkeys)
	hasKey := false
	for _, c := range cfg.Credentials {
		if len(c.Key) > 0 {
			hasKey = true
			break
		}
	}
	if !hasKey {
		t.Error("expected SSH badkeys (key-based credentials) to be loaded")
	}

	// Should also have password-based credentials (from wordlist)
	hasPassword := false
	for _, c := range cfg.Credentials {
		if c.Password != "" && len(c.Key) == 0 {
			hasPassword = true
			break
		}
	}
	if !hasPassword {
		t.Error("expected SSH wordlist (password-based credentials) to be loaded")
	}
}

func TestApplyDefaults_SSH_NoBadkeys(t *testing.T) {
	cfg := &Config{Target: "x:22", Protocol: "ssh", UseDefaults: true, NoBadkeys: true}
	cfg.applyDefaults()

	for _, c := range cfg.Credentials {
		if len(c.Key) > 0 {
			t.Fatal("NoBadkeys is set but got key-based credential")
		}
	}
	if len(cfg.Credentials) == 0 {
		t.Fatal("expected wordlist password credentials even with NoBadkeys")
	}
}

func TestApplyDefaults_SSH_ExplicitCredsSkipsDefaults(t *testing.T) {
	cfg := &Config{
		Target:      "x:22",
		Protocol:    "ssh",
		UseDefaults: true,
		Credentials: []Credential{{Username: "custom", Password: "custom"}},
	}
	cfg.applyDefaults()

	// Should not load badkeys because hasCreds was true
	for _, c := range cfg.Credentials {
		if len(c.Key) > 0 {
			t.Error("should not load badkeys when explicit credentials provided")
		}
	}
	if len(cfg.Credentials) != 1 {
		t.Errorf("expected 1 credential (the explicit one), got %d", len(cfg.Credentials))
	}
}

func TestApplyDefaults_MySQL(t *testing.T) {
	cfg := &Config{Target: "x:3306", Protocol: "mysql", UseDefaults: true}
	cfg.applyDefaults()

	if len(cfg.Credentials) == 0 {
		t.Fatal("expected mysql default credentials")
	}

	hasRoot := false
	for _, c := range cfg.Credentials {
		if c.Username == "root" {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		t.Error("expected 'root' in mysql default credentials")
	}
}

func TestApplyDefaults_Redis(t *testing.T) {
	cfg := &Config{Target: "x:6379", Protocol: "redis", UseDefaults: true}
	cfg.applyDefaults()

	if len(cfg.Credentials) == 0 {
		t.Fatal("expected redis default credentials")
	}
}

func TestApplyDefaults_FTP(t *testing.T) {
	cfg := &Config{Target: "x:21", Protocol: "ftp", UseDefaults: true}
	cfg.applyDefaults()

	if len(cfg.Credentials) == 0 {
		t.Fatal("expected ftp default credentials")
	}

	hasAnon := false
	for _, c := range cfg.Credentials {
		if c.Username == "anonymous" {
			hasAnon = true
			break
		}
	}
	if !hasAnon {
		t.Error("expected 'anonymous' in ftp default credentials")
	}
}

func TestApplyDefaults_Disabled(t *testing.T) {
	cfg := &Config{Target: "x:22", Protocol: "ssh", UseDefaults: false}
	cfg.applyDefaults()

	if len(cfg.Credentials) > 0 || len(cfg.Passwords) > 0 {
		t.Error("applyDefaults should be a no-op when UseDefaults is false")
	}
}

func TestValidate_UseDefaults_PassesWithoutExplicitCreds(t *testing.T) {
	protocols := []string{"ssh", "mysql", "ftp", "redis", "postgresql"}
	for _, proto := range protocols {
		cfg := &Config{Target: "x:1234", Protocol: proto, UseDefaults: true}
		if err := cfg.validate(); err != nil {
			t.Errorf("validate() for %s with UseDefaults should pass, got: %v", proto, err)
		}
	}
}

func TestValidate_NoDefaults_FailsWithoutCreds(t *testing.T) {
	cfg := &Config{Target: "x:22", Protocol: "ssh"}
	if err := cfg.validate(); err == nil {
		t.Error("validate() without UseDefaults and no creds should fail")
	}
}
