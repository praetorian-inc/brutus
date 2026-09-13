// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rdp

import (
	"errors"
	"strings"
	"testing"

	gconnector "github.com/UNC1739/gordp/pkg/connector"
	gcredssp "github.com/UNC1739/gordp/pkg/credssp"
	gpdu "github.com/UNC1739/gordp/pkg/pdu"
)

// TestClassifyGordpErrorVerdicts pins the three-way contract at the point it is
// decided. Each case names what the exchange actually established, because that
// -- not the wording of the message -- is what the verdict has to reflect.
func TestClassifyGordpErrorVerdicts(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want gordpVerdict
		why  string
	}{
		{
			name: "wrong password is a rejection",
			err:  &gcredssp.AuthError{Status: gcredssp.StatusLogonFailure},
			want: verdictRejected,
			why:  "the server evaluated the credential and refused it",
		},
		{
			name: "locked-out account proves the password",
			err:  &gcredssp.AuthError{Status: gcredssp.StatusAccountLockedOut},
			want: verdictProvenValid,
			why:  "CredSSP got far enough to say the password was right",
		},
		{
			name: "expired password proves the password",
			err:  &gcredssp.AuthError{Status: gcredssp.StatusPasswordExpired},
			want: verdictProvenValid,
			why:  "an expired password is still the correct password",
		},
		{
			name: "negotiation failure proves nothing",
			err:  &gconnector.NegotiationError{Code: gpdu.FailureHybridRequiredByServer},
			want: verdictUntestable,
			why:  "negotiation settles the security protocol before any credential is sent",
		},
		{
			name: "ssl-required negotiation failure proves nothing",
			err:  &gconnector.NegotiationError{Code: gpdu.FailureSSLRequiredByServer},
			want: verdictUntestable,
			why:  "same: the exchange ended before the password was offered",
		},
		{
			name: "unknown transport error is untestable",
			err:  errors.New("connection reset by peer"),
			want: verdictUntestable,
			why:  "a host that stopped answering has proven nothing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyGordpError(tc.err)
			if got.verdict != tc.want {
				t.Errorf("verdict = %v, want %v (%s)\nmessage: %s",
					got.verdict, tc.want, tc.why, got.detail)
			}
			if !errors.Is(got, tc.err) && got.cause != tc.err {
				t.Errorf("cause was not preserved; errors.As through the wrapper will break")
			}
		})
	}
}

// TestUntestableMessagesCarryNoVerdict is the regression test for the defect
// this design replaced.
//
// classifyGordpError used to return a plain string, which the caller re-parsed
// against rdpAuthIndicators to recover the verdict. Every message beginning
// "authentication failed" therefore read as a rejected password -- including a
// negotiation failure, which happens before a credential is ever sent.
//
// The verdict is now carried as data and testGordp reads it directly, so
// classifyError is out of this path entirely. What this test guards is the
// message: an untestable outcome must not *state* a credential verdict, so that
// reintroducing string classification here would fail loudly instead of quietly
// reporting unreachable hosts as wrong passwords.
//
// It checks the verdict phrases only, not all of rdpAuthIndicators. That list
// mixes verdicts ("authentication failed") with bare protocol names ("nla",
// "ntlm", "credssp"), and a diagnostic is allowed -- often obliged -- to name
// the protocol: "hybrid (NLA) required by server" is the most useful thing an
// operator can be told about such a host. The protocol-name entries make
// rdpAuthIndicators hazardous for any caller that does still match on it, which
// is a pre-existing wart in the WASM path and not something this path relies on.
func TestUntestableMessagesCarryNoVerdict(t *testing.T) {
	verdictPhrases := []string{
		"authentication failed",
		"logon failed",
		"login failed",
		"access denied",
		"wrong password",
		"invalid credentials",
		"sec_e_logon_denied",
	}

	untestable := []error{
		&gconnector.NegotiationError{Code: gpdu.FailureHybridRequiredByServer},
		&gconnector.NegotiationError{Code: gpdu.FailureSSLRequiredByServer},
		&gconnector.NegotiationError{Code: gpdu.FailureSSLNotAllowedByServer},
		&gconnector.NegotiationError{Code: gpdu.FailureInconsistentFlags},
		errors.New("i/o timeout"),
	}

	for _, err := range untestable {
		classified := classifyGordpError(err)
		if classified.verdict != verdictUntestable {
			t.Fatalf("test precondition failed: %v is not untestable", err)
		}
		lower := strings.ToLower(classified.detail)
		for _, phrase := range verdictPhrases {
			if strings.Contains(lower, phrase) {
				t.Errorf("untestable message %q states the credential verdict %q; "+
					"a host that was never interrogated must not read as one that "+
					"refused the credential", classified.detail, phrase)
			}
		}
	}
}

// TestProvenValidIsNotReportedAsRejection covers the other half of the original
// defect: the locked-out arm also began "authentication failed", so a valid
// password on a restricted account was reported as invalid despite the server
// having confirmed it.
func TestProvenValidIsNotReportedAsRejection(t *testing.T) {
	for _, status := range []gcredssp.NTStatus{
		gcredssp.StatusAccountLockedOut,
		gcredssp.StatusAccountRestriction,
		gcredssp.StatusPasswordExpired,
		gcredssp.StatusInvalidLogonHours,
		gcredssp.StatusLogonTypeNotGranted,
	} {
		classified := classifyGordpError(&gcredssp.AuthError{Status: status})
		if classified.verdict != verdictProvenValid {
			t.Errorf("status %v: verdict = %v, want verdictProvenValid",
				status, classified.verdict)
		}
	}
}
