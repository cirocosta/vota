package blind

import (
	"crypto/sha512"
	"encoding/binary"
)

func encodePSS(message []byte, emBits int, salt []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, &Error{Code: "invalid_pss_salt"}
	}
	emLen := (emBits + 7) / 8
	hLen := sha512.Size384
	if emBits < 8*hLen+8*len(salt)+9 || emLen < hLen+len(salt)+2 {
		return nil, &Error{Code: "issuer_key_too_small"}
	}
	messageHash := sha512.Sum384(message)
	hashInput := make([]byte, 8+hLen+len(salt))
	copy(hashInput[8:], messageHash[:])
	copy(hashInput[8+hLen:], salt)
	hash := sha512.Sum384(hashInput)
	dbLen := emLen - hLen - 1
	db := make([]byte, dbLen)
	db[dbLen-len(salt)-1] = 1
	copy(db[dbLen-len(salt):], salt)
	mask := mgf1SHA384(hash[:], dbLen)
	for index := range db {
		db[index] ^= mask[index]
	}
	unusedBits := 8*emLen - emBits
	db[0] &= byte(0xff >> unusedBits)
	encoded := make([]byte, emLen)
	copy(encoded, db)
	copy(encoded[dbLen:], hash[:])
	encoded[emLen-1] = 0xbc
	return encoded, nil
}

func mgf1SHA384(seed []byte, length int) []byte {
	output := make([]byte, 0, length)
	var counter [4]byte
	for index := uint32(0); len(output) < length; index++ {
		binary.BigEndian.PutUint32(counter[:], index)
		hash := sha512.New384()
		_, _ = hash.Write(seed)
		_, _ = hash.Write(counter[:])
		output = append(output, hash.Sum(nil)...)
	}
	return output[:length]
}
