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
	"context"
	"os"
	"testing"
	"time"

	"github.com/praetorian-inc/brutus/pkg/brutus"
)

// Environment for the credential tests. Without these they skip, so an ordinary
// run needs no server.
const (
	credHostEnv = "BRUTUS_RDP_CRED_HOST"
	credUserEnv = "BRUTUS_RDP_CRED_USER"
	credPassEnv = "BRUTUS_RDP_CRED_PASS"
)

// TestNativeCredentialContract checks the three-way outcome the plugin contract
// depends on, through the native backend.
//
// The contract is what makes a credential scan trustworthy:
//
//	Success=true,  Error=nil   the credentials are valid
//	Success=false, Error=nil   the credentials were rejected
//	Success=false, Error!=nil  the host could not be tested
//
// Confusing the last two is the damaging failure. An error means "retry this
// host"; a rejection means "this password is wrong". Reporting a protocol
// failure as a rejection makes a scan conclude that a working credential does
// not work, and nothing downstream can recover that.
func TestNativeCredentialContract(t *testing.T) {
	host, user, pass := requireCredHost(t)

	t.Run("valid password is accepted", func(t *testing.T) {
		result := runCredentialTest(t, BackendGordp, host, user, pass)
		t.Logf("success=%v error=%v banner=%q", result.Success, result.Error, result.Banner)

		if result.Error != nil {
			t.Fatalf("valid credentials produced a transport error: %v", result.Error)
		}
		if !result.Success {
			t.Fatal("valid credentials were reported as rejected")
		}
	})

	t.Run("wrong password is rejected, not errored", func(t *testing.T) {
		wrong := "definitely-not-the-password-" + time.Now().Format("150405")
		result := runCredentialTest(t, BackendGordp, host, user, wrong)
		t.Logf("success=%v error=%v", result.Success, result.Error)

		if result.Success {
			t.Fatal("a wrong password was accepted")
		}
		if result.Error != nil {
			t.Fatalf("a wrong password was reported as a transport error, which "+
				"would make the host look untestable rather than the password "+
				"wrong: %v", result.Error)
		}
	})
}

// TestWASMCredentialContractIsBrokenOnModernWindows documents a defect in the
// IronRDP WASM backend, in executable form.
//
// Against Windows Server 2022 the WASM connector's CredSSP exchange fails with
// "credssp: [TsRequest] custom error" for *any* password, valid or not. Because
// rdpAuthIndicators lists "credssp", that protocol failure is classified as a
// credential rejection, so the backend reports every password as invalid and can
// never discover a working RDP credential on such a host.
//
// Confirmed on two separate Windows Server 2022 instances, with an embedded
// module that is newer than its Rust sources and built against sspi 0.18.7 and
// ironrdp-connector 0.8.0, so it is not a stale artifact. The Rust side has not
// been root-caused; there is no Rust toolchain on the build host, which is part
// of why the native backend exists.
//
// This test asserts the broken behaviour deliberately. If IronRDP is upgraded
// and the exchange starts working, this test fails — which is the intended
// signal to delete it and fold the case back into the contract test above.
func TestWASMCredentialContractIsBrokenOnModernWindows(t *testing.T) {
	host, user, pass := requireCredHost(t)

	valid := runCredentialTest(t, BackendWASM, host, user, pass)
	t.Logf("valid password:  success=%v error=%v", valid.Success, valid.Error)

	if valid.Success {
		t.Fatal("the WASM backend now accepts valid credentials against modern " +
			"Windows. That is good news: delete this test and require the " +
			"contract of both backends instead.")
	}

	// The specific shape of the defect: indistinguishable from a real rejection,
	// which is exactly why it is dangerous rather than merely broken.
	if valid.Error != nil {
		t.Logf("note: the failure now surfaces as a transport error (%v) rather "+
			"than as a silent rejection. That is an improvement, and this test "+
			"should be revisited.", valid.Error)
	}
}

// runCredentialTest exercises Plugin.Test on the given backend.
//
// Nothing needs switching off any more: the credential path no longer runs the
// pre-authentication logon-backdoor checks, so it opens one connection per
// attempt and cannot exhaust a Windows Server's two-session limit by itself.
func runCredentialTest(t *testing.T, backend Backend, host, user, pass string) *brutus.Result {
	t.Helper()

	value := ""
	if backend == BackendGordp {
		value = "gordp"
	}
	t.Setenv(backendEnvVar, value)

	p := &Plugin{}
	return p.Test(context.Background(), host, user, pass, 30*time.Second,
		brutus.PluginConfig{})
}

func requireCredHost(t *testing.T) (host, user, pass string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping credential tests in short mode")
	}
	host = os.Getenv(credHostEnv)
	user = os.Getenv(credUserEnv)
	pass = os.Getenv(credPassEnv)
	if host == "" || user == "" || pass == "" {
		t.Skipf("%s, %s and %s must all be set; see GROK.md in the gordp repo",
			credHostEnv, credUserEnv, credPassEnv)
	}
	return host, user, pass
}
