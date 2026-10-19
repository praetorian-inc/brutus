package ntlmssp

import (
	"bytes"
	"fmt"
	"io"
)

type payload struct {
	Len    uint16
	MaxLen uint16
	Offset uint32
}

func newPayload(length int, offset *int) payload {
	p := payload{
		Len:    uint16(length),
		MaxLen: uint16(length),
		Offset: uint32(*offset),
	}

	*offset += length

	return p
}

func (p *payload) ReadValue(reader *bytes.Reader) ([]byte, error) {
	// Remember where we are
	pos, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// Seek to where the payload is
	_, err = reader.Seek(int64(p.Offset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Read the value
	b := make([]byte, p.Len)
	n, err := reader.Read(b)
	if err != nil {
		return nil, err
	}
	if n != int(p.Len) {
		return nil, fmt.Errorf("expected %d bytes, only read %d", p.Len, n)
	}

	// Seek back to where we were
	_, err = reader.Seek(pos, io.SeekStart)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p *payload) ReadString(reader *bytes.Reader, utf16 bool) (string, error) {
	b, err := p.ReadValue(reader)
	if err != nil {
		return "", err
	}

	if utf16 {
		s, err := utf16ToString(b)
		if err != nil {
			return "", err
		}
		return s, nil
	}

	return string(b), nil
}
