package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"
)

var (
	errInvalidChallengeMessage = errors.New("invalid NTLM challenge message")
)

type challengeMessageFields struct {
	messageHeader
	TargetNameFields payload
	NegotiateFlags   uint32
	ServerChallenge  [8]uint8
	_                [8]uint8
	TargetInfoFields payload
}

func (m *challengeMessageFields) IsValid() bool {
	return m.messageHeader.IsValid() && m.MessageType == ntLmChallenge
}

type challengeMessage struct {
	challengeMessageFields
	TargetName string
	TargetInfo targetInfo
	Version    *Version
}

func (m *challengeMessage) Marshal() ([]byte, error) {
	offset := int(unsafe.Sizeof(m.challengeMessageFields) + unsafe.Sizeof(*m.Version))

	m.NegotiateFlags = ntlmsspRequestTarget.Unset(m.NegotiateFlags)
	if m.TargetName != "" {
		m.NegotiateFlags = ntlmsspRequestTarget.Set(m.NegotiateFlags)
	}

	m.NegotiateFlags = ntlmsspNegotiateTargetInfo.Unset(m.NegotiateFlags)
	if m.TargetInfo.Len() > 0 {
		m.NegotiateFlags = ntlmsspNegotiateTargetInfo.Set(m.NegotiateFlags)
	}

	var targetName []byte
	if ntlmsspNegotiateUnicode.IsSet(m.NegotiateFlags) {
		var err error
		targetName, err = utf16FromString(m.TargetName)
		if err != nil {
			return nil, err
		}
	} else {
		targetName = []byte(m.TargetName)
	}

	m.TargetNameFields = newPayload(len(targetName), &offset)

	targetInfo, err := m.TargetInfo.Marshal()
	if err != nil {
		return nil, err
	}

	m.TargetInfoFields = newPayload(len(targetInfo), &offset)

	var version = &Version{}

	m.NegotiateFlags = ntlmsspNegotiateVersion.Unset(m.NegotiateFlags)
	if m.Version != nil {
		m.NegotiateFlags = ntlmsspNegotiateVersion.Set(m.NegotiateFlags)
		version = m.Version
	}

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &m.challengeMessageFields); err != nil {
		return nil, err
	}

	v, err := version.marshal()
	if err != nil {
		return nil, err
	}
	b.Write(v)

	b.Write(targetName)
	b.Write(targetInfo)

	return b.Bytes(), nil
}

func (m *challengeMessage) Unmarshal(b []byte) error {
	reader := bytes.NewReader(b)

	err := binary.Read(reader, binary.LittleEndian, &m.challengeMessageFields)
	if err != nil {
		return err
	}

	if !m.challengeMessageFields.IsValid() {
		return errInvalidChallengeMessage
	}

	if ntlmsspRequestTarget.IsSet(m.NegotiateFlags) && m.TargetNameFields.Len > 0 {
		m.TargetName, err = m.TargetNameFields.ReadString(reader, ntlmsspNegotiateUnicode.IsSet(m.NegotiateFlags))
		if err != nil {
			return err
		}
	}

	m.TargetInfo = newTargetInfo()

	if ntlmsspNegotiateTargetInfo.IsSet(m.NegotiateFlags) && m.TargetInfoFields.Len > 0 {
		v, err := m.TargetInfoFields.ReadValue(reader)
		if err != nil {
			return err
		}

		if err := m.TargetInfo.Unmarshal(v); err != nil {
			return err
		}
	}

	if ntlmsspNegotiateVersion.IsSet(m.NegotiateFlags) {
		v := Version{}
		if err := v.unmarshal(reader); err != nil {
			return err
		}
		m.Version = &v
	}

	return nil
}
