package titleclass

import (
	_ "embed"
	"encoding/json"
	"math"
	"testing"
)

//go:embed testdata/parity.json
var parityBytes []byte

type paritySample struct {
	Raw           string             `json:"raw"`
	Normalized    string             `json:"normalized"`
	Argmax        string             `json:"argmax"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
}

// TestParityWithPython locks Go inference to the scikit-learn output. If the
// n-gram tokenization, TF-IDF math, or softmax drifts, this fails.
func TestParityWithPython(t *testing.T) {
	clf, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var fx struct {
		Samples []paritySample `json:"samples"`
	}
	if err := json.Unmarshal(parityBytes, &fx); err != nil {
		t.Fatalf("parse parity fixture: %v", err)
	}
	if len(fx.Samples) == 0 {
		t.Fatal("no parity samples")
	}

	const tol = 1e-4
	for _, s := range fx.Samples {
		if got := clf.Normalize(s.Raw); got != s.Normalized {
			t.Errorf("Normalize(%q) = %q, want %q", s.Raw, got, s.Normalized)
		}
		// threshold 0 => argmax is never masked to Unknown.
		res := clf.ClassifyWithThreshold(s.Raw, 0)
		if res.Argmax != s.Argmax {
			t.Errorf("%q argmax = %q, want %q", s.Raw, res.Argmax, s.Argmax)
		}
		if math.Abs(res.Confidence-s.Confidence) > tol {
			t.Errorf("%q confidence = %.6f, want %.6f", s.Raw, res.Confidence, s.Confidence)
		}
		for label, want := range s.Probabilities {
			if got := res.Probabilities[label]; math.Abs(got-want) > tol {
				t.Errorf("%q P(%s) = %.6f, want %.6f", s.Raw, label, got, want)
			}
		}
	}
}

// TestUnknownThreshold verifies the below-threshold fallback and that gibberish
// does not confidently land in a real department.
func TestUnknownThreshold(t *testing.T) {
	clf, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A clear title well above any sane threshold.
	res := clf.ClassifyWithThreshold("SOC Analyst II", 0.5)
	if res.Department == clf.UnknownLabel() {
		t.Errorf("expected a real department for a clear title, got Unknown (conf %.3f)", res.Confidence)
	}

	// An impossibly high threshold forces Unknown even for a clear title.
	res = clf.ClassifyWithThreshold("SOC Analyst II", 1.01)
	if res.Department != clf.UnknownLabel() {
		t.Errorf("expected Unknown at threshold 1.01, got %q", res.Department)
	}
	if res.Argmax == clf.UnknownLabel() {
		t.Error("Argmax should never be Unknown")
	}

	// Probabilities should form a distribution.
	var sum float64
	for _, p := range res.Probabilities {
		sum += p
	}
	if math.Abs(sum-1.0) > 1e-6 {
		t.Errorf("probabilities sum = %.6f, want ~1.0", sum)
	}
}
