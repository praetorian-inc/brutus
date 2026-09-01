package brutus

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCredentialConfigExposesNoLogonKnob pins the separation between credential
// testing and logon-screen backdoor detection at the one place a consumer can
// reach: the exported configuration surface.
//
// The two are different operations against different things. Credential testing
// authenticates; the sticky-keys/utilman check is pre-auth, needs no credentials
// at all, and physically triggers a backdoor on the target's logon screen. They
// live in separate packages for that reason -- pkg/brutus/logon owns the check,
// with its own admission control, NLA probing, cancellation, and structured
// Results carrying ScanType.
//
// Until this test landed, Config.StickyKeys let the credential path run the
// check inline and report it by APPENDING to the Banner of whichever credential
// attempt happened to be in flight. That produced a finding with no ScanType, no
// Result of its own, and -- because the check is pre-auth and the banner rides
// the attempt -- a CONFIRMED unauthenticated SYSTEM shell arriving on a Result
// with Success == false. Consumers filtering on Success dropped it silently
// (guard ENG-6865), and consumers matching the banner text inherited a control
// path steered by bytes the scanned host chooses.
//
// A knob here is what makes that reachable, so the knob is what this test
// forbids. Run the check through pkg/brutus/logon.DetectBackdoors instead: it
// returns findings as first-class Results and never touches a credential
// attempt.
func TestCredentialConfigExposesNoLogonKnob(t *testing.T) {
	// Substrings, not exact names, so a rename cannot slip a re-introduction
	// past this test.
	forbidden := []string{"stickykeys", "utilman", "logon", "backdoor"}

	for _, typ := range []reflect.Type{
		reflect.TypeOf(Config{}),
		reflect.TypeOf(PluginConfig{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i).Name
			lowered := strings.ToLower(field)
			for _, banned := range forbidden {
				assert.NotContains(t, lowered, banned,
					"%s.%s re-exposes the logon-screen check on the credential path; "+
						"that detection belongs to pkg/brutus/logon, which reports it as its "+
						"own Result instead of appending to a credential attempt's Banner",
					typ.Name(), field)
			}
		}
	}
}
