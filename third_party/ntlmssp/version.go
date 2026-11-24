package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

const (
	// NTLMSSPRevisionW2K3 is the current revision of NTLM.
	NTLMSSPRevisionW2K3 uint8 = 0x0f
)

// Version models the NTLM version passed in the various messages.
type Version struct {
	ProductMajorVersion uint8
	ProductMinorVersion uint8
	ProductBuild        uint16
	_                   [3]uint8
	NTLMRevisionCurrent uint8
}

func (v *Version) marshal() ([]byte, error) {
	dest := make([]byte, 0, unsafe.Sizeof(Version{}))
	buffer := bytes.NewBuffer(dest)

	if err := binary.Write(buffer, binary.LittleEndian, v); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (v *Version) unmarshal(reader *bytes.Reader) error {
	if err := binary.Read(reader, binary.LittleEndian, v); err != nil {
		return err
	}

	return nil
}
