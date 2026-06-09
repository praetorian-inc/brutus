package brutus

import (
	"testing"
)

func TestDefaultCredentials_LoadsWordlists(t *testing.T) {
	protocols := []string{"ssh", "mysql", "ftp", "redis", "postgresql", "vnc", "rdp", "smb", "mongodb", "snmp", "http", "https", "browser", "elasticsearch"}
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

func TestApplyDefaults_SSH_BadkeysOnly(t *testing.T) {
	cfg := &Config{Target: "x:22", Protocol: "ssh", UseDefaults: true, BadkeysOnly: true}
	cfg.applyDefaults()

	if len(cfg.Credentials) == 0 {
		t.Fatal("expected badkeys credentials, got none")
	}

	// Should have ONLY key-based credentials (no password wordlist)
	for _, c := range cfg.Credentials {
		if len(c.Key) == 0 {
			t.Errorf("BadkeysOnly should only load key-based credentials, got password credential: %s:%s", c.Username, c.Password)
		}
	}
}

func TestApplyDefaults_NonSSH_BadkeysOnly(t *testing.T) {
	for _, proto := range []string{"mysql", "ftp", "redis", "postgresql"} {
		cfg := &Config{Target: "x:1234", Protocol: proto, UseDefaults: true, BadkeysOnly: true}
		cfg.applyDefaults()

		if len(cfg.Credentials) > 0 {
			t.Errorf("BadkeysOnly with protocol %q should load no credentials, got %d", proto, len(cfg.Credentials))
		}
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

func TestApplyDefaults_Browser(t *testing.T) {
	cfg := &Config{Target: "x:80", Protocol: "browser", UseDefaults: true}
	cfg.applyDefaults()

	if len(cfg.Credentials) == 0 {
		t.Fatal("expected browser default credentials")
	}

	hasAdmin := false
	for _, c := range cfg.Credentials {
		if c.Username == "admin" && c.Password == "admin" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		t.Error("expected 'admin:admin' in browser default credentials")
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
	protocols := []string{"ssh", "mysql", "ftp", "redis", "postgresql", "http", "https", "browser", "elasticsearch"}
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

func TestParseWordlist_LineWithoutColon_TreatedAsPasswordOnly(t *testing.T) {
	// Test for SNMP community strings (password-only lines without colons)
	input := "public\nprivate\nadmin:password\nguest"
	creds := parseWordlist(input)

	if len(creds) != 4 {
		t.Fatalf("expected 4 credentials, got %d", len(creds))
	}

	// First credential: "public" (no colon, should be password-only)
	if creds[0].Username != "" {
		t.Errorf("creds[0] expected empty username for password-only line, got %q", creds[0].Username)
	}
	if creds[0].Password != "public" {
		t.Errorf("creds[0] expected password %q, got %q", "public", creds[0].Password)
	}

	// Second credential: "private" (no colon, should be password-only)
	if creds[1].Username != "" {
		t.Errorf("creds[1] expected empty username for password-only line, got %q", creds[1].Username)
	}
	if creds[1].Password != "private" {
		t.Errorf("creds[1] expected password %q, got %q", "private", creds[1].Password)
	}

	// Third credential: "admin:password" (has colon, normal username:password)
	if creds[2].Username != "admin" {
		t.Errorf("creds[2] expected username %q, got %q", "admin", creds[2].Username)
	}
	if creds[2].Password != "password" {
		t.Errorf("creds[2] expected password %q, got %q", "password", creds[2].Password)
	}

	// Fourth credential: "guest" (no colon, should be password-only)
	if creds[3].Username != "" {
		t.Errorf("creds[3] expected empty username for password-only line, got %q", creds[3].Username)
	}
	if creds[3].Password != "guest" {
		t.Errorf("creds[3] expected password %q, got %q", "guest", creds[3].Password)
	}
}

// --- Tiered loading tests ---

func TestParseWordlistTiered_WithMarkers(t *testing.T) {
	content := `# Test wordlist
root:root
admin:admin
# --- cautious ---
root:password
root:toor
# --- aggressive ---
vendor:vendor123
obscure:cred`

	cautious := parseWordlistTiered(content, ModeCautious)
	if len(cautious) != 2 {
		t.Errorf("cautious: expected 2 credentials, got %d", len(cautious))
	}

	dflt := parseWordlistTiered(content, ModeDefault)
	if len(dflt) != 4 {
		t.Errorf("default: expected 4 credentials, got %d", len(dflt))
	}

	aggressive := parseWordlistTiered(content, ModeAggressive)
	if len(aggressive) != 6 {
		t.Errorf("aggressive: expected 6 credentials, got %d", len(aggressive))
	}
}

func TestParseWordlistTiered_NoMarkers_CautiousCapped(t *testing.T) {
	content := "root:root\nroot:password\nadmin:admin\nuser:user\ntest:test\nguest:guest\nfoo:bar"

	cautious := parseWordlistTiered(content, ModeCautious)
	if len(cautious) != maxCautiousFallback {
		t.Errorf("cautious without markers: expected %d credentials, got %d", maxCautiousFallback, len(cautious))
	}

	dflt := parseWordlistTiered(content, ModeDefault)
	if len(dflt) != 7 {
		t.Errorf("default without markers: expected 7 credentials, got %d", len(dflt))
	}

	aggressive := parseWordlistTiered(content, ModeAggressive)
	if len(aggressive) != 7 {
		t.Errorf("aggressive without markers: expected 7 credentials, got %d", len(aggressive))
	}
}

func TestParseWordlistTiered_NoMarkers_SmallFile(t *testing.T) {
	content := "root:root\nadmin:admin\nuser:user"

	// File has fewer than maxCautiousFallback entries — all returned.
	cautious := parseWordlistTiered(content, ModeCautious)
	if len(cautious) != 3 {
		t.Errorf("cautious small file: expected 3 credentials, got %d", len(cautious))
	}
}

func TestDefaultCredentialsForMode_BackwardCompat(t *testing.T) {
	// DefaultCredentials() should return same count as ModeDefault.
	protocols := []string{"ssh", "mysql", "ftp", "redis", "postgresql"}
	for _, proto := range protocols {
		old := DefaultCredentials(proto)
		dflt := DefaultCredentialsForMode(proto, ModeDefault)
		if len(old) != len(dflt) {
			t.Errorf("%s: DefaultCredentials returned %d, DefaultCredentialsForMode(ModeDefault) returned %d",
				proto, len(old), len(dflt))
		}
	}
}

func TestDefaultCredentialsForMode_CautiousSubsetOfDefault(t *testing.T) {
	protocols := []string{"ssh", "mysql", "rdp", "http", "ftp"}
	for _, proto := range protocols {
		cautious := DefaultCredentialsForMode(proto, ModeCautious)
		dflt := DefaultCredentialsForMode(proto, ModeDefault)
		if len(cautious) >= len(dflt) {
			t.Errorf("%s: cautious (%d) should be smaller than default (%d)",
				proto, len(cautious), len(dflt))
		}
	}
}

func TestDefaultCredentialsForMode_AggressiveSupersetOfDefault(t *testing.T) {
	protocols := []string{"ssh", "mysql", "rdp", "http", "ftp"}
	for _, proto := range protocols {
		dflt := DefaultCredentialsForMode(proto, ModeDefault)
		aggressive := DefaultCredentialsForMode(proto, ModeAggressive)
		if len(aggressive) < len(dflt) {
			t.Errorf("%s: aggressive (%d) should be >= default (%d)",
				proto, len(aggressive), len(dflt))
		}
	}
}

func TestApplyDefaults_WithMode(t *testing.T) {
	// Cautious mode should load fewer defaults than default mode.
	cautious := &Config{Target: "x:22", Protocol: "ssh", UseDefaults: true, Mode: ModeCautious, NoBadkeys: true}
	cautious.applyDefaults()

	dflt := &Config{Target: "x:22", Protocol: "ssh", UseDefaults: true, Mode: ModeDefault, NoBadkeys: true}
	dflt.applyDefaults()

	if len(cautious.Credentials) >= len(dflt.Credentials) {
		t.Errorf("cautious mode (%d creds) should have fewer than default mode (%d creds)",
			len(cautious.Credentials), len(dflt.Credentials))
	}
}

func TestDefaultCredentials_SNMP_CommunityStringsAsPasswords(t *testing.T) {
	// SNMP uses community strings which should be in the Password field
	creds := DefaultCredentials("snmp")

	if len(creds) == 0 {
		t.Fatal("expected SNMP default credentials, got none")
	}

	// All SNMP credentials should have empty username and non-empty password
	hasPublic := false
	hasPrivate := false
	for _, c := range creds {
		if c.Username != "" {
			t.Errorf("SNMP credential should have empty username, got %q", c.Username)
		}
		if c.Password == "" {
			t.Error("SNMP credential should have non-empty password")
		}
		if c.Password == "public" {
			hasPublic = true
		}
		if c.Password == "private" {
			hasPrivate = true
		}
	}

	if !hasPublic {
		t.Error("expected 'public' community string in SNMP defaults")
	}
	if !hasPrivate {
		t.Error("expected 'private' community string in SNMP defaults")
	}
}
