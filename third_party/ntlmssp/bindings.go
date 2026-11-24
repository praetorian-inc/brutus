package ntlmssp

import (
	"bytes"
	"encoding/binary"
)

const (
	// TLSServerEndPoint is defined in RFC 5929 and stores the hash of the server certificate.
	TLSServerEndPoint string = "tls-server-end-point"
)

// ChannelBindings models the GSS-API channel bindings defined in RFC 2744.
type ChannelBindings struct {
	InitiatorAddrtype uint32
	InitiatorAddress  []uint8
	AcceptorAddrtype  uint32
	AcceptorAddress   []uint8
	ApplicationData   []uint8
}

func (c *ChannelBindings) marshal() ([]byte, error) {
	b := bytes.Buffer{}

	if err := binary.Write(&b, binary.LittleEndian, &c.InitiatorAddrtype); err != nil {
		return nil, err
	}

	length := uint32(len(c.InitiatorAddress))
	if err := binary.Write(&b, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	b.Write(c.InitiatorAddress)

	if err := binary.Write(&b, binary.LittleEndian, &c.AcceptorAddrtype); err != nil {
		return nil, err
	}

	length = uint32(len(c.AcceptorAddress))
	if err := binary.Write(&b, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	b.Write(c.AcceptorAddress)

	length = uint32(len(c.ApplicationData))
	if err := binary.Write(&b, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	b.Write(c.ApplicationData)

	return b.Bytes(), nil
}
