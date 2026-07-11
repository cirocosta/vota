package main

import (
	"crypto/sha512"
	"io"
	"testing"
)

func TestRingProofAndLinkability(t *testing.T) {
	result, err := demonstrate(newHashReader("ring-signature"))
	if err != nil {
		t.Fatal(err)
	}
	if result.ringSize != 5 || !result.proofVerified || !result.samePollLinked || !result.crossPollLinked || !result.changedMessageFails {
		t.Fatalf("result = %+v", result)
	}
	if len(result.keyImage) != 64 {
		t.Fatalf("key image length = %d", len(result.keyImage))
	}
}

type hashReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newHashReader(seed string) io.Reader { return &hashReader{seed: []byte(seed)} }

func (reader *hashReader) Read(output []byte) (int, error) {
	written := 0
	for written < len(output) {
		if len(reader.buffer) == 0 {
			input := append([]byte(nil), reader.seed...)
			input = append(input, byte(reader.counter>>56), byte(reader.counter>>48), byte(reader.counter>>40), byte(reader.counter>>32), byte(reader.counter>>24), byte(reader.counter>>16), byte(reader.counter>>8), byte(reader.counter))
			digest := sha512.Sum512(input)
			reader.buffer = append(reader.buffer[:0], digest[:]...)
			reader.counter++
		}
		count := copy(output[written:], reader.buffer)
		reader.buffer = reader.buffer[count:]
		written += count
	}
	return written, nil
}
