package ntlmssp

import (
	"fmt"
	"strings"
)

type lmCompatibilityLevel int

const (
	DefaultClientCompatibilityLevel lmCompatibilityLevel = 3
)

type Client struct {
	compatibilityLevel lmCompatibilityLevel
	defaultFlags       uint32
	domain             string
	password           string
	username           string
	workstation        string
	version            *Version

	negotiatedFlags  uint32
	negotiateMessage []byte
	challengeMessage []byte
	complete         bool
	securitySession  *SecuritySession
}

func realClientChallenge() ([]byte, error) {
	return nonce(8)
}

func realExportedSessionKey() ([]byte, error) {
	return nonce(16)
}

var (
	generateClientChallenge    = realClientChallenge
	generateExportedSessionKey = realExportedSessionKey
)

func NewClient(options ...func(*Client) error) (*Client, error) {
	c := &Client{}

	// Set the defaults
	if err := c.SetOption(SetCompatibilityLevel(DefaultClientCompatibilityLevel)); err != nil {
		return nil, err
	}

	if err := c.SetOption(options...); err != nil {
		return nil, err
	}

	return c, nil
}

func defaultClientFlags() uint32 {
	flags := uint32(0)

	flags = ntlmsspNegotiateUnicode.Set(flags)
	flags = ntlmsspNegotiateSign.Set(flags)
	flags = ntlmsspNegotiateSeal.Set(flags)
	flags = ntlmsspNegotiateAlwaysSign.Set(flags)
	flags = ntlmsspNegotiateTargetInfo.Set(flags)
	flags = ntlmsspNegotiate128.Set(flags)
	flags = ntlmsspNegotiateKeyExch.Set(flags)
	flags = ntlmsspNegotiate56.Set(flags)

	return flags
}

func (c *Client) SetOption(options ...func(*Client) error) error {
	for _, option := range options {
		if err := option(c); err != nil {
			return err
		}
	}
	return nil
}

func SetCompatibilityLevel(level lmCompatibilityLevel) func(*Client) error {
	return func(c *Client) error {
		flags := defaultClientFlags()

		// Ideally these should be constants if there's official naming for them
		switch level {
		case 0: // LM Auth and NTLMv1 Auth
			flags = ntlmsspNegotiateLMKey.Set(flags)
			flags = ntlmsspNegotiateNTLM.Set(flags)
		case 1: // LM Auth and NTLMv1 Auth with Extended Session Security (NTLM2)
			flags = ntlmsspNegotiateNTLM.Set(flags)
			flags = ntlmsspNegotiateExtendedSessionsecurity.Set(flags)
		case 2: // NTLMv1 Auth with Extended Session Security (NTLM2)
			fallthrough
		case 3, 4, 5: // NTLMv2 Auth
			flags = ntlmsspNegotiateExtendedSessionsecurity.Set(flags)
		default:
			return fmt.Errorf("invalid compatibility level(0-5): %d", level)
		}

		c.compatibilityLevel = level
		c.defaultFlags = flags

		return nil
	}
}

func SetDomain(domain string) func(*Client) error {
	return func(c *Client) error {
		c.domain = strings.TrimSpace(domain)
		return nil
	}
}

func SetUserInfo(username, password string) func(*Client) error {
	return func(c *Client) error {
		c.username = username
		c.password = password
		return nil
	}
}

func SetWorkstation(workstation string) func(*Client) error {
	return func(c *Client) error {
		c.workstation = strings.TrimSpace(workstation)
		return nil
	}
}

func SetVersion(version *Version) func(*Client) error {
	return func(c *Client) error {
		c.version = version
		return nil
	}
}

func (c *Client) Authenticate(input []byte, bindings *ChannelBindings) ([]byte, error) {
	if input != nil {
		return c.processChallengeMessage(input, bindings)
	}
	return c.newNegotiateMessage()
}

func (c *Client) newNegotiateMessage() ([]byte, error) {
	m := &negotiateMessage{
		negotiateMessageFields: negotiateMessageFields{
			messageHeader:  newMessageHeader(ntLmNegotiate),
			NegotiateFlags: c.defaultFlags,
		},
		DomainName:  c.domain,
		Workstation: c.workstation,
		Version:     c.version,
	}

	b, err := m.Marshal()
	if err != nil {
		return nil, err
	}

	// Store the message bytes in case we need to generate a MIC
	c.negotiateMessage = b

	return b, nil
}

func (c *Client) processChallengeMessage(input []byte, bindings *ChannelBindings) ([]byte, error) {
	cm := &challengeMessage{}
	if err := cm.Unmarshal(input); err != nil {
		return nil, err
	}

	// Store the message bytes in case we need to generate a MIC
	c.challengeMessage = input

	c.negotiatedFlags = cm.NegotiateFlags
	if ntlmsspNegotiateUnicode.IsSet(c.negotiatedFlags) {
		c.negotiatedFlags = ntlmNegotiateOEM.Unset(c.negotiatedFlags)
	}

	// Set anonymous flag
	if c.username == "" && c.password == "" {
		c.negotiatedFlags = ntlmsspAnonymous.Set(c.negotiatedFlags)
	}

	clientChallenge, err := generateClientChallenge()
	if err != nil {
		return nil, err
	}

	lmChallengeResponse, err := lmChallengeResponse(c.negotiatedFlags, c.compatibilityLevel, clientChallenge, c.username, c.password, c.domain, cm)
	if err != nil {
		return nil, err
	}

	targetInfo, err := cm.TargetInfo.Clone()
	if err != nil {
		return nil, err
	}

	ntChallengeResponse, keyExchangeKey, err := ntChallengeResponse(c.negotiatedFlags, c.compatibilityLevel, clientChallenge, c.username, c.password, c.domain, cm, lmChallengeResponse, *targetInfo, bindings)
	if err != nil {
		return nil, err
	}

	var encryptedRandomSessionKey, exportedSessionKey []byte

	if ntlmsspNegotiateKeyExch.IsSet(c.negotiatedFlags) {
		exportedSessionKey, err = generateExportedSessionKey()
		if err != nil {
			return nil, err
		}

		encryptedRandomSessionKey, err = encryptRC4K(keyExchangeKey, exportedSessionKey)
		if err != nil {
			return nil, err
		}
	} else {
		exportedSessionKey = keyExchangeKey
	}

	if ntlmsspNegotiateSeal.IsSet(c.negotiatedFlags) || ntlmsspNegotiateSign.IsSet(c.negotiatedFlags) {
		c.securitySession, err = newSecuritySession(c.negotiatedFlags, exportedSessionKey, sourceClient)
		if err != nil {
			return nil, err
		}
	}

	am := &authenticateMessage{
		authenticateMessageFields: authenticateMessageFields{
			messageHeader:  newMessageHeader(ntLmAuthenticate),
			NegotiateFlags: c.negotiatedFlags,
		},
		LmChallengeResponse:       lmChallengeResponse,
		NtChallengeResponse:       ntChallengeResponse,
		DomainName:                c.domain,
		UserName:                  c.username,
		Workstation:               c.workstation,
		EncryptedRandomSessionKey: encryptedRandomSessionKey,
		Version:                   c.version,
		// Needed for computing the MIC
		ExportedSessionKey: exportedSessionKey,
		TargetInfo:         *targetInfo,
	}

	if err := am.UpdateMIC(concat(c.negotiateMessage, c.challengeMessage)); err != nil {
		return nil, err
	}

	b, err := am.Marshal()
	if err != nil {
		return nil, err
	}

	// Mark transaction as complete
	c.complete = true

	return b, nil
}

func (c *Client) Complete() bool {
	return c.complete
}

func (c *Client) SecuritySession() *SecuritySession {
	return c.securitySession
}
