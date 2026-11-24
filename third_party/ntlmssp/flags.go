package ntlmssp

import "strings"

type negotiateFlag uint32

const (
	ntlmsspNegotiateUnicode negotiateFlag = 1 << iota
	ntlmNegotiateOEM
	ntlmsspRequestTarget
	_
	ntlmsspNegotiateSign
	ntlmsspNegotiateSeal
	ntlmsspNegotiateDatagram
	ntlmsspNegotiateLMKey
	_
	ntlmsspNegotiateNTLM
	_
	ntlmsspAnonymous
	ntlmsspNegotiateOEMDomainSupplied
	ntlmsspNegotiateOEMWorkstationSupplied
	_
	ntlmsspNegotiateAlwaysSign
	ntlmsspTargetTypeDomain
	ntlmsspTargetTypeServer
	_
	ntlmsspNegotiateExtendedSessionsecurity
	ntlmsspNegotiateIdentity
	_
	ntlmsspRequestNonNTSessionKey
	ntlmsspNegotiateTargetInfo
	_
	ntlmsspNegotiateVersion
	_
	_
	_
	ntlmsspNegotiate128
	ntlmsspNegotiateKeyExch
	ntlmsspNegotiate56
)

func (f negotiateFlag) Set(flags uint32) uint32 {
	return flags | uint32(f)
}

func (f negotiateFlag) IsSet(flags uint32) bool {
	return (flags & uint32(f)) != 0
}

func (f negotiateFlag) Unset(flags uint32) uint32 {
	return flags & ^uint32(f)
}

func (f negotiateFlag) String() string {
	strings := map[negotiateFlag]string{
		ntlmsspNegotiateUnicode:                 "NTLMSSP_NEGOTIATE_UNICODE",
		ntlmNegotiateOEM:                        "NTLM_NEGOTIATE_OEM",
		ntlmsspRequestTarget:                    "NTLMSSP_REQUEST_TARGET",
		ntlmsspNegotiateSign:                    "NTLMSSP_NEGOTIATE_SIGN",
		ntlmsspNegotiateSeal:                    "NTLMSSP_NEGOTIATE_SEAL",
		ntlmsspNegotiateDatagram:                "NTLMSSP_NEGOTIATE_DATAGRAM",
		ntlmsspNegotiateLMKey:                   "NTLMSSP_NEGOTIATE_LM_KEY",
		ntlmsspNegotiateNTLM:                    "NTLMSSP_NEGOTIATE_NTLM",
		ntlmsspAnonymous:                        "NTLMSSP_ANONYMOUS",
		ntlmsspNegotiateOEMDomainSupplied:       "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED",
		ntlmsspNegotiateOEMWorkstationSupplied:  "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED",
		ntlmsspNegotiateAlwaysSign:              "NTLMSSP_NEGOTIATE_ALWAYS_SIGN",
		ntlmsspTargetTypeDomain:                 "NTLMSSP_TARGET_TYPE_DOMAIN",
		ntlmsspTargetTypeServer:                 "NTLMSSP_TARGET_TYPE_SERVER",
		ntlmsspNegotiateExtendedSessionsecurity: "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY",
		ntlmsspNegotiateIdentity:                "NTLMSSP_NEGOTIATE_IDENTITY",
		ntlmsspRequestNonNTSessionKey:           "NTLMSSP_REQUEST_NON_NT_SESSION_KEY",
		ntlmsspNegotiateTargetInfo:              "NTLMSSP_NEGOTIATE_TARGET_INFO",
		ntlmsspNegotiateVersion:                 "NTLMSSP_NEGOTIATE_VERSION",
		ntlmsspNegotiate128:                     "NTLMSSP_NEGOTIATE_128",
		ntlmsspNegotiateKeyExch:                 "NTLMSSP_NEGOTIATE_KEY_EXCH",
		ntlmsspNegotiate56:                      "NTLMSSP_NEGOTIATE_56",
	}

	return strings[f]
}

func flagsToString(flags uint32) string {
	var set []string

	for _, f := range [...]negotiateFlag{
		ntlmsspNegotiateUnicode,
		ntlmNegotiateOEM,
		ntlmsspRequestTarget,
		ntlmsspNegotiateSign,
		ntlmsspNegotiateSeal,
		ntlmsspNegotiateDatagram,
		ntlmsspNegotiateLMKey,
		ntlmsspNegotiateNTLM,
		ntlmsspAnonymous,
		ntlmsspNegotiateOEMDomainSupplied,
		ntlmsspNegotiateOEMWorkstationSupplied,
		ntlmsspNegotiateAlwaysSign,
		ntlmsspTargetTypeDomain,
		ntlmsspTargetTypeServer,
		ntlmsspNegotiateExtendedSessionsecurity,
		ntlmsspNegotiateIdentity,
		ntlmsspRequestNonNTSessionKey,
		ntlmsspNegotiateTargetInfo,
		ntlmsspNegotiateVersion,
		ntlmsspNegotiate128,
		ntlmsspNegotiateKeyExch,
		ntlmsspNegotiate56,
	} {
		if f.IsSet(flags) {
			set = append(set, f.String())
		}
	}

	return strings.Join(set, " | ")
}
