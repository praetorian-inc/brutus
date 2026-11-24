package ntlmssp

import "golang.org/x/text/encoding/unicode"

func utf16FromString(s string) ([]byte, error) {
	b, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes([]byte(s))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func utf16ToString(b []byte) (string, error) {
	s, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(b)
	if err != nil {
		return "", err
	}

	return string(s), nil
}
