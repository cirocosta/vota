package election

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
)

func randomScalar(random io.Reader) (*ristretto255.Scalar, error) {
	if random == nil {
		random = rand.Reader
	}
	for range 128 {
		uniform := make([]byte, 64)
		if _, err := io.ReadFull(random, uniform); err != nil {
			return nil, &Error{Code: "random_failed", Err: err}
		}
		scalar, err := ristretto255.NewScalar().SetUniformBytes(uniform)
		if err != nil {
			return nil, &Error{Code: "random_failed", Err: err}
		}
		if scalar.Equal(ristretto255.NewScalar()) != 1 {
			return scalar, nil
		}
	}
	return nil, &Error{Code: "random_failed", Err: fmt.Errorf("generated zero scalar repeatedly")}
}

func decodeScalar(value Scalar) (*ristretto255.Scalar, error) {
	scalar, err := ristretto255.NewScalar().SetCanonicalBytes(value[:])
	if err != nil {
		return nil, fmt.Errorf("decode scalar: %w", err)
	}
	return scalar, nil
}

func decodePoint(value Point) (*ristretto255.Element, error) {
	point, err := ristretto255.NewIdentityElement().SetCanonicalBytes(value[:])
	if err != nil {
		return nil, fmt.Errorf("decode point: %w", err)
	}
	return point, nil
}

func decodePublicPoint(value Point) (*ristretto255.Element, error) {
	point, err := decodePoint(value)
	if err != nil {
		return nil, err
	}
	if point.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, fmt.Errorf("identity public point")
	}
	return point, nil
}

func scalarBytes(value *ristretto255.Scalar) Scalar {
	var result Scalar
	copy(result[:], value.Bytes())
	return result
}

func pointBytes(value *ristretto255.Element) Point {
	var result Point
	copy(result[:], value.Bytes())
	return result
}

func scalarFromIndex(index uint16) *ristretto255.Scalar {
	var encoded Scalar
	binary.LittleEndian.PutUint16(encoded[:2], index)
	scalar, err := decodeScalar(encoded)
	if err != nil {
		panic(fmt.Sprintf("decode trustee index: %v", err))
	}
	return scalar
}

func hashScalar(domain string, fields ...[]byte) *ristretto255.Scalar {
	hash := sha512.New()
	writeField(hash, []byte(domain))
	for _, field := range fields {
		writeField(hash, field)
	}
	digest := hash.Sum(nil)
	scalar, err := ristretto255.NewScalar().SetUniformBytes(digest)
	if err != nil {
		panic(fmt.Sprintf("set transcript scalar: %v", err))
	}
	return scalar
}

func writeField(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func indexBytes(index int) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(index))
	return encoded[:]
}

func subtractPoints(left, right *ristretto255.Element) *ristretto255.Element {
	return ristretto255.NewIdentityElement().Subtract(left, right)
}
