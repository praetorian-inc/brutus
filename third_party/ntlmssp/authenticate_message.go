package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"unsafe"
)

var (
	errInvalidAuthenticateMessage = errors.New("invalid NTLM authenticate message")
)

type authenticateMessageFields struct {
	messageHeader
	LmChallengeResponseFields       payload
	NtChallengeResponseFields       payload
	DomainNameFields                payload
	UserNameFields                  payload
	WorkstationFields               payload
	EncryptedRandomSessionKeyFields payload
	NegotiateFlags                  uint32
}

func (m *authenticateMessageFields) IsValid() bool {
	return m.messageHeader.IsValid() && m.MessageType == ntLmAuthenticate
}

type authenticateMessage struct {
	authenticateMessageFields
	LmChallengeResponse       []uint8
	NtChallengeResponse       []uint8
	DomainName                string
	UserName                  string
	Workstation               string
	EncryptedRandomSessionKey []uint8
	Version                   *Version
	MIC                       []uint8

	// These aren't transmitted, but necessary in order to compute the MIC
	ExportedSessionKey []uint8
	TargetInfo         targetInfo
}

func (m *authenticateMessage) UpdateMIC(preamble []byte) error {
	if v, ok := m.TargetInfo.Get(msvAvFlags); ok {
		flags := binary.LittleEndian.Uint32(v)
		if flags&msvAvFlagMICProvided != 0 {
			// Add an all-zero MIC first
			m.MIC = zeroBytes(16)

			b, err := m.Marshal()
			if err != nil {
				return err
			}

			// Now compute the actual MIC
			m.MIC = hmacMD5(m.ExportedSessionKey, concat(preamble, b))
		}
	}

	return nil
}

func (m *authenticateMessage) Marshal() ([]byte, error) {
	offset := int(unsafe.Sizeof(m.authenticateMessageFields) + unsafe.Sizeof(*m.Version))
	if m.MIC != nil {
		offset += len(m.MIC)
	}

	var domainName, userName, workstation []byte
	if ntlmsspNegotiateUnicode.IsSet(m.NegotiateFlags) {
		var err error
		domainName, err = utf16FromString(m.DomainName)
		if err != nil {
			return nil, err
		}
		userName, err = utf16FromString(m.UserName)
		if err != nil {
			return nil, err
		}
		workstation, err = utf16FromString(m.Workstation)
		if err != nil {
			return nil, err
		}
	} else {
		domainName = []byte(m.DomainName)
		userName = []byte(m.UserName)
		workstation = []byte(m.Workstation)
	}

	// Microsoft MS-NLMP spec doesn't write out the payloads in the same
	// order as they are defined in the struct. Copy the behaviour just so
	// the various test values can be used

	m.DomainNameFields = newPayload(len(domainName), &offset)
	m.UserNameFields = newPayload(len(userName), &offset)
	m.WorkstationFields = newPayload(len(workstation), &offset)

	m.LmChallengeResponseFields = newPayload(len(m.LmChallengeResponse), &offset)
	m.NtChallengeResponseFields = newPayload(len(m.NtChallengeResponse), &offset)

	m.EncryptedRandomSessionKeyFields = newPayload(len(m.EncryptedRandomSessionKey), &offset)

	var version = &Version{}

	m.NegotiateFlags = ntlmsspNegotiateVersion.Unset(m.NegotiateFlags)
	if m.Version != nil {
		m.NegotiateFlags = ntlmsspNegotiateVersion.Set(m.NegotiateFlags)
		version = m.Version
	}

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &m.authenticateMessageFields); err != nil {
		return nil, err
	}

	v, err := version.marshal()
	if err != nil {
		return nil, err
	}
	b.Write(v)

	if m.MIC != nil {
		b.Write(m.MIC)
	}

	b.Write(domainName)
	b.Write(userName)
	b.Write(workstation)

	b.Write(m.LmChallengeResponse)
	b.Write(m.NtChallengeResponse)

	b.Write(m.EncryptedRandomSessionKey)

	return b.Bytes(), nil
}

func (m *authenticateMessage) Unmarshal(b []byte) error {
	reader := bytes.NewReader(b)

	err := binary.Read(reader, binary.LittleEndian, &m.authenticateMessageFields)
	if err != nil {
		return err
	}

	if !m.authenticateMessageFields.IsValid() {
		return errInvalidAuthenticateMessage
	}

	var offsets []int

	for _, x := range []struct {
		payload *payload
		bytes   *[]uint8
	}{
		{
			&m.LmChallengeResponseFields,
			&m.LmChallengeResponse,
		},
		{
			&m.NtChallengeResponseFields,
			&m.NtChallengeResponse,
		},
		{
			&m.EncryptedRandomSessionKeyFields,
			&m.EncryptedRandomSessionKey,
		},
	} {
		offsets = append(offsets, int(x.payload.Offset))

		if x.payload.Len > 0 {
			*x.bytes, err = x.payload.ReadValue(reader)
			if err != nil {
				return err
			}
		}
	}

	for _, x := range []struct {
		payload *payload
		string  *string
	}{
		{
			&m.DomainNameFields,
			&m.DomainName,
		},
		{
			&m.UserNameFields,
			&m.UserName,
		},
		{
			&m.WorkstationFields,
			&m.Workstation,
		},
	} {
		offsets = append(offsets, int(x.payload.Offset))

		if x.payload.Len > 0 {
			*x.string, err = x.payload.ReadString(reader, ntlmsspNegotiateUnicode.IsSet(m.NegotiateFlags))
			if err != nil {
				return err
			}
		}
	}

	if ntlmsspNegotiateVersion.IsSet(m.NegotiateFlags) {
		v := Version{}
		if err := v.unmarshal(reader); err != nil {
			return err
		}
		m.Version = &v
	} else {
		// Seek past the version
		if _, err := reader.Seek(int64(unsafe.Sizeof(*m.Version)), io.SeekCurrent); err != nil {
			return err
		}
	}

	pos, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	// Sort the offsets into ascending order
	sort.Ints(offsets)

	// If there's a gap between the end of the version where we are and
	// the first payload offset then treat the gap as a MIC
	if length := offsets[0] - int(pos); length > 0 {
		m.MIC = make([]byte, length)
		n, err := reader.Read(m.MIC)
		if err != nil {
			return err
		}
		if n != length {
			return fmt.Errorf("expected %d bytes, only read %d", length, n)
		}
	}

	return nil
}
