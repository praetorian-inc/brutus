package ntlmssp

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"hash/crc32"

	"golang.org/x/crypto/md4"
)

func nonce(length int) ([]byte, error) {
	result := make([]byte, length)
	if _, err := rand.Read(result); err != nil {
		return nil, err
	}

	return result, nil
}

func createDESKey(b []byte) ([]byte, error) {
	if len(b) < 7 {
		return nil, errors.New("need at least 7 bytes")
	}

	key := zeroBytes(8)

	key[0] = b[0]
	key[1] = b[0]<<7 | b[1]>>1
	key[2] = b[1]<<6 | b[2]>>2
	key[3] = b[2]<<5 | b[3]>>3
	key[4] = b[3]<<4 | b[4]>>4
	key[5] = b[4]<<3 | b[5]>>5
	key[6] = b[5]<<2 | b[6]>>6
	key[7] = b[6] << 1

	// Calculate odd parity
	for i, x := range key {
		key[i] = (x & 0xfe) | ((((x >> 1) ^ (x >> 2) ^ (x >> 3) ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7)) ^ 0x01) & 0x01)
	}

	return key, nil
}

func encryptDES(k, d []byte) ([]byte, error) {
	key, err := createDESKey(k)
	if err != nil {
		return nil, err
	}

	cipher, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(d))
	cipher.Encrypt(result, d)

	return result, nil
}

func encryptDESL(k, d []byte) ([]byte, error) {
	b := bytes.Buffer{}

	padded := zeroPad(k, 21)

	for _, i := range []int{0, 7, 14} {
		result, err := encryptDES(padded[i:], d)
		if err != nil {
			return nil, err
		}

		if _, err := b.Write(result); err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

func initRC4(k []byte) (*rc4.Cipher, error) {
	cipher, err := rc4.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func encryptRC4(cipher *rc4.Cipher, d []byte) []byte {
	result := make([]byte, len(d))
	cipher.XORKeyStream(result, d)
	return result
}

func encryptRC4K(k, d []byte) ([]byte, error) {
	cipher, err := initRC4(k)
	if err != nil {
		return nil, err
	}
	return encryptRC4(cipher, d), nil
}

func hashMD4(b []byte) []byte {
	md4 := md4.New()
	md4.Write(b)

	return md4.Sum(nil)
}

func hashMD5(b []byte) []byte {
	md5 := md5.New()
	md5.Write(b)

	return md5.Sum(nil)
}

func hmacMD5(k, m []byte) []byte {
	mac := hmac.New(md5.New, k)
	mac.Write(m)

	return mac.Sum(nil)
}

func hashCRC32(b []byte) []byte {
	checksum := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksum, crc32.ChecksumIEEE(b))
	return checksum
}
