package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
)

type avID uint16

const (
	msvAvEOL avID = iota
	msvAvNbComputerName
	msvAvNbDomainName
	msvAvDNSComputerName
	msvAvDNSDomainName
	msvAvDNSTreeName
	msvAvFlags
	msvAvTimestamp
	msvAvSingleHost
	msvAvTargetName
	msvChannelBindings
)

const (
	msvAvFlagAuthenticationConstrained uint32 = 1 << iota
	msvAvFlagMICProvided
	msvAvFlagUntrustedSPNSource
)

type avPair struct {
	ID     avID
	Length uint16
}

type targetInfo struct {
	Pairs map[avID][]uint8
	Order []avID
}

func newTargetInfo() targetInfo {
	return targetInfo{
		Pairs: make(map[avID][]uint8),
		Order: []avID{},
	}
}

func (t *targetInfo) Get(id avID) ([]uint8, bool) {
	v, ok := t.Pairs[id]
	return v, ok
}

func (t *targetInfo) Set(id avID, value []uint8) {
	if id == msvAvEOL {
		return
	}
	if _, ok := t.Get(id); !ok {
		t.Order = append(t.Order, id)
	}
	t.Pairs[id] = value
}

func (t *targetInfo) Del(id avID) {
	delete(t.Pairs, id)
	j := 0
	for _, n := range t.Order {
		if n != id {
			t.Order[j] = n
			j++
		}
	}
	t.Order = t.Order[:j]
}

func (t *targetInfo) Len() int {
	return len(t.Pairs)
}

func init() {
	gob.Register(targetInfo{})
}

func (t *targetInfo) Clone() (*targetInfo, error) {
	b := bytes.Buffer{}
	enc := gob.NewEncoder(&b)
	dec := gob.NewDecoder(&b)
	if err := enc.Encode(*t); err != nil {
		return nil, err
	}
	var copy targetInfo
	if err := dec.Decode(&copy); err != nil {
		return nil, err
	}
	return &copy, nil
}

func (t *targetInfo) Marshal() ([]byte, error) {
	b := bytes.Buffer{}

	for _, k := range t.Order {
		if k == msvAvEOL {
			continue
		}

		v := t.Pairs[k]

		if err := binary.Write(&b, binary.LittleEndian, &avPair{k, uint16(len(v))}); err != nil {
			return nil, err
		}

		b.Write(v)
	}

	// Append required MsvAvEOL pair
	if err := binary.Write(&b, binary.LittleEndian, &avPair{msvAvEOL, 0}); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (t *targetInfo) Unmarshal(b []byte) error {
	reader := bytes.NewReader(b)

	for {
		var pair avPair

		if err := binary.Read(reader, binary.LittleEndian, &pair); err != nil {
			return err
		}

		if pair.ID == msvAvEOL {
			break
		}

		value := make([]byte, pair.Length)
		n, err := reader.Read(value)
		if err != nil {
			return err
		}
		if n != int(pair.Length) {
			return fmt.Errorf("expected %d bytes, only read %d", pair.Length, n)
		}

		t.Set(pair.ID, value)
	}

	return nil
}
