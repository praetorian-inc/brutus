package ntlmssp

import "bytes"

const (
	ntLmNegotiate uint32 = iota + 1
	ntLmChallenge
	ntLmAuthenticate
)

type messageHeader struct {
	Signature   [8]byte
	MessageType uint32
}

var signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

func (h messageHeader) IsValid() bool {
	return bytes.Equal(h.Signature[:], signature[:]) &&
		h.MessageType >= ntLmNegotiate && h.MessageType <= ntLmAuthenticate
}

func newMessageHeader(messageType uint32) messageHeader {
	return messageHeader{signature, messageType}
}
