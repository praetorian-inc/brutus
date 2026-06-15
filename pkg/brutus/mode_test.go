package brutus

import "testing"

func TestNormalizeMode(t *testing.T) {
	tests := []struct {
		input string
		want  Mode
	}{
		{"cautious", ModeCautious},
		{"CAUTIOUS", ModeCautious},
		{"  Cautious  ", ModeCautious},
		{"default", ModeDefault},
		{"DEFAULT", ModeDefault},
		{"aggressive", ModeAggressive},
		{"AGGRESSIVE", ModeAggressive},
		{"unknown", ModeDefault},
		{"", ModeDefault},
	}
	for _, tt := range tests {
		got := NormalizeMode(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidMode(t *testing.T) {
	valid := []string{"cautious", "default", "aggressive", "CAUTIOUS", "DEFAULT", "AGGRESSIVE"}
	for _, s := range valid {
		if !ValidMode(s) {
			t.Errorf("ValidMode(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "fast", "unknown"}
	for _, s := range invalid {
		if ValidMode(s) {
			t.Errorf("ValidMode(%q) = true, want false", s)
		}
	}
}

func TestModePresets(t *testing.T) {
	// Cautious should have lower threads and non-zero rate limit.
	cp := ModeCautious.Presets()
	if cp.Threads >= ModeDefault.Presets().Threads {
		t.Errorf("cautious threads (%d) should be less than default (%d)", cp.Threads, ModeDefault.Presets().Threads)
	}
	if cp.RateLimit == 0 {
		t.Error("cautious should have a non-zero rate limit")
	}

	// Aggressive should have higher threads than default.
	ep := ModeAggressive.Presets()
	dp := ModeDefault.Presets()
	if ep.Threads <= dp.Threads {
		t.Errorf("aggressive threads (%d) should be greater than default (%d)", ep.Threads, dp.Threads)
	}
}
