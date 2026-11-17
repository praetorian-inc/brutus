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

// Package winlocal decides whether an NTLM attempt is a local SAM login or an
// explicit domain login.
//
// Unqualified names are local. Sending them with an empty domain is not: SMB
// libraries substitute the challenge TargetName, which on a domain member is
// the AD domain, and Windows will pass an empty or unknown domain through to
// a DC. Either path increments the domain account's bad-password count on
// every host in the spray.
package winlocal

import "strings"

// Identity is the NTLM account to authenticate.
//
// Local means the caller did not name a domain. The domain field sent on the
// wire must then be the target computer's NetBIOS name, never empty and never
// the AD domain from the challenge.
type Identity struct {
	User   string
	Domain string
	Local  bool
}

// Parse splits a username into an NTLM identity.
//
//	CORP\user     explicit domain CORP
//	user@corp     explicit domain corp (UPN)
//	.\user        local
//	user          local
//
// A backslash wins over '@'. Only the first separator is split.
func Parse(username string) Identity {
	if i := strings.Index(username, `\`); i >= 0 {
		domain, user := username[:i], username[i+1:]
		if domain == "" || domain == "." {
			return Identity{User: user, Local: true}
		}
		return Identity{User: user, Domain: domain, Local: false}
	}
	if i := strings.Index(username, "@"); i > 0 {
		return Identity{User: username[:i], Domain: username[i+1:], Local: false}
	}
	return Identity{User: username, Local: true}
}
