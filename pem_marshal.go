package pki

import (
	"io"
)

type (
	marshalledPemBlock []byte
)

// This function writes the marshalled pem block to a writer and returns the
// number of written bytes and eventual errors.
func (b marshalledPemBlock) WriteTo(stream io.Writer) (int64, error) {
	numBytes, err := stream.Write(b)
	return int64(numBytes), err
}
