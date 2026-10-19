package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"
)

var (
	errInvalidNegotiateMessage = errors.New("invalid NTLM negotiate message")
)

type negotiateMessageFields struct {
	messageHeader
	NegotiateFlags    uint32
	DomainNameFields  payload
	WorkstationFields payload
}

func (m *negotiateMessageFields) IsValid() bool {
	return m.messageHeader.IsValid() && m.MessageType == ntLmNegotiate
}

type negotiateMessage struct {
	negotiateMessageFields
	DomainName  string
	Workstation string
	Version     *Version
}

func (m *negotiateMessage) Marshal() ([]byte, error) {
	offset := int(unsafe.Sizeof(m.negotiateMessageFields) + unsafe.Sizeof(*m.Version))

	m.NegotiateFlags = ntlmsspNegotiateOEMDomainSupplied.Unset(m.NegotiateFlags)
	if m.DomainName != "" {
		m.NegotiateFlags = ntlmsspNegotiateOEMDomainSupplied.Set(m.NegotiateFlags)
	}

	m.NegotiateFlags = ntlmsspNegotiateOEMWorkstationSupplied.Unset(m.NegotiateFlags)
	if m.Workstation != "" {
		m.NegotiateFlags = ntlmsspNegotiateOEMWorkstationSupplied.Set(m.NegotiateFlags)
	}

	// Always OEM
	m.DomainNameFields = newPayload(len(m.DomainName), &offset)
	m.WorkstationFields = newPayload(len(m.Workstation), &offset)

	var version = &Version{}

	m.NegotiateFlags = ntlmsspNegotiateVersion.Unset(m.NegotiateFlags)
	if m.Version != nil {
		m.NegotiateFlags = ntlmsspNegotiateVersion.Set(m.NegotiateFlags)
		version = m.Version
	}

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &m.negotiateMessageFields); err != nil {
		return nil, err
	}

	v, err := version.marshal()
	if err != nil {
		return nil, err
	}
	b.Write(v)

	// Always OEM
	// XXX Should they be forced uppercase?
	b.WriteString(m.DomainName + m.Workstation)

	return b.Bytes(), nil
}

func (m *negotiateMessage) Unmarshal(b []byte) error {
	reader := bytes.NewReader(b)

	err := binary.Read(reader, binary.LittleEndian, &m.negotiateMessageFields)
	if err != nil {
		return err
	}

	if !m.negotiateMessageFields.IsValid() {
		return errInvalidNegotiateMessage
	}

	if ntlmsspNegotiateOEMDomainSupplied.IsSet(m.NegotiateFlags) && m.DomainNameFields.Len > 0 {
		m.DomainName, err = m.DomainNameFields.ReadString(reader, false) // Always OEM
		if err != nil {
			return err
		}
	}

	if ntlmsspNegotiateOEMWorkstationSupplied.IsSet(m.NegotiateFlags) && m.WorkstationFields.Len > 0 {
		m.Workstation, err = m.WorkstationFields.ReadString(reader, false) // Always OEM
		if err != nil {
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
