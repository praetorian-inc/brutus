package ntlmssp

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"errors"
)

type SecuritySession struct {
	negotiateFlags, outgoingSeqNum, incomingSeqNum uint32
	outgoingSigningKey, incomingSigningKey         []byte
	outgoingHandle, incomingHandle                 *rc4.Cipher
}

var (
	clientSigning = concat([]byte("session key to client-to-server signing key magic constant"), []byte{0x00})
	serverSigning = concat([]byte("session key to server-to-client signing key magic constant"), []byte{0x00})
	clientSealing = concat([]byte("session key to client-to-server sealing key magic constant"), []byte{0x00})
	serverSealing = concat([]byte("session key to server-to-client sealing key magic constant"), []byte{0x00})
)

type securitySource int

const (
	sourceClient securitySource = iota
	sourceServer
)

func newSecuritySession(flags uint32, exportedSessionKey []byte, source securitySource) (*SecuritySession, error) {
	s := &SecuritySession{
		negotiateFlags: flags,
	}

	clientSealingKey := sealKey(s.negotiateFlags, exportedSessionKey, clientSealing)
	serverSealingKey := sealKey(s.negotiateFlags, exportedSessionKey, serverSealing)

	var err error

	switch source {
	case sourceClient:
		s.outgoingSigningKey = signKey(exportedSessionKey, clientSigning)
		s.incomingSigningKey = signKey(exportedSessionKey, serverSigning)

		s.outgoingHandle, err = initRC4(clientSealingKey)
		if err != nil {
			return nil, err
		}

		s.incomingHandle, err = initRC4(serverSealingKey)
		if err != nil {
			return nil, err
		}
	case sourceServer:
		s.outgoingSigningKey = signKey(exportedSessionKey, serverSigning)
		s.incomingSigningKey = signKey(exportedSessionKey, clientSigning)

		s.outgoingHandle, err = initRC4(serverSealingKey)
		if err != nil {
			return nil, err
		}

		s.incomingHandle, err = initRC4(clientSealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown source")
	}

	return s, nil
}

func (s *SecuritySession) Wrap(b []byte) ([]byte, []byte, error) {
	m := append(b[:0:0], b...)
	switch {
	case ntlmsspNegotiateSeal.IsSet(s.negotiateFlags):
		m = encryptRC4(s.outgoingHandle, m)
		fallthrough
	case ntlmsspNegotiateSign.IsSet(s.negotiateFlags):
		// Signature is always created on the original unencrypted message
		signature, err := calculateSignature(b, s.negotiateFlags, s.outgoingSigningKey, s.outgoingSeqNum, s.outgoingHandle)
		if err != nil {
			return nil, nil, err
		}

		s.outgoingSeqNum++

		return m, signature, nil
	default:
		return m, nil, nil
	}
}

func (s *SecuritySession) Unwrap(b, signature []byte) ([]byte, error) {
	m := append(b[:0:0], b...)
	switch {
	case ntlmsspNegotiateSeal.IsSet(s.negotiateFlags):
		m = encryptRC4(s.incomingHandle, m)
		fallthrough
	case ntlmsspNegotiateSign.IsSet(s.negotiateFlags):
		// Signature is checked after any decryption
		expected, err := calculateSignature(m, s.negotiateFlags, s.incomingSigningKey, s.incomingSeqNum, s.incomingHandle)
		if err != nil {
			return nil, err
		}

		offset := 8
		if ntlmsspNegotiateExtendedSessionsecurity.IsSet(s.negotiateFlags) {
			offset = 4
		}

		// Compare the checksum portion of the signature
		if !bytes.Equal(signature[offset:12], expected[offset:12]) {
			return nil, errors.New("checksum does not match")
		}

		// Compare the sequence number portion of the signature
		if !bytes.Equal(signature[12:16], expected[12:16]) {
			return nil, errors.New("sequence number does not match")
		}

		s.incomingSeqNum++

		fallthrough
	default:
		return m, nil
	}
}

func signKey(exportedSessionKey, constant []byte) []byte {
	return hashMD5(concat(exportedSessionKey, constant))
}

func sealKey(flags uint32, exportedSessionKey, constant []byte) []byte {
	switch {
	case ntlmsspNegotiateExtendedSessionsecurity.IsSet(flags) && ntlmsspNegotiate128.IsSet(flags):
		// NTLM2 with 128-bit key
		return hashMD5(concat(exportedSessionKey, constant))
	case ntlmsspNegotiateExtendedSessionsecurity.IsSet(flags) && ntlmsspNegotiate56.IsSet(flags):
		// NTLM2 with 56-bit key
		return hashMD5(concat(exportedSessionKey[:7], constant))
	case ntlmsspNegotiateExtendedSessionsecurity.IsSet(flags):
		// NTLM2 with 40-bit key
		return hashMD5(concat(exportedSessionKey[:5], constant))
	case ntlmsspNegotiateLMKey.IsSet(flags) && ntlmsspNegotiate56.IsSet(flags):
		// NTLM1 with 56-bit key
		return concat(exportedSessionKey[:7], []byte{0xa0})
	case ntlmsspNegotiateLMKey.IsSet(flags):
		// NTLM1 with 40-bit key
		return concat(exportedSessionKey[:5], []byte{0xe5, 0x38, 0xb0})
	default:
		return exportedSessionKey
	}
}

func calculateSignature(message []byte, flags uint32, signingKey []byte, sequenceNumber uint32, handle *rc4.Cipher) ([]byte, error) {
	var version uint32 = 1

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &version); err != nil {
		return nil, err
	}

	seqNum := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqNum, sequenceNumber)

	switch {
	case ntlmsspNegotiateExtendedSessionsecurity.IsSet(flags):
		checksum := hmacMD5(signingKey, concat(seqNum, message))[:8]

		if ntlmsspNegotiateKeyExch.IsSet(flags) {
			checksum = encryptRC4(handle, checksum)
		}

		// Checksum
		b.Write(checksum)

		// Sequence Number
		b.Write(seqNum)
	default:
		// The MS-NLMP specification doesn't match the examples. The
		// examples write out the encrypted random pad in the signature
		// whereas the pseudo code writes out zeroes.

		// RandomPad of 0
		_ = encryptRC4(handle, zeroBytes(4))
		b.Write(zeroBytes(4))

		// Checksum
		b.Write(encryptRC4(handle, hashCRC32(message)))

		encryptedSeqNum := encryptRC4(handle, zeroBytes(4))

		for i := 0; i < 4; i++ {
			encryptedSeqNum[i] ^= seqNum[i]
		}

		// Sequence Number
		b.Write(encryptedSeqNum)
	}

	return b.Bytes(), nil
}
