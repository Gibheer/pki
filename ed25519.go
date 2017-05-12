package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"

	"github.com/agl/ed25519"
)

const (
	PemLabelEd25519 = "ED25519 PRIVATE KEY" // TODO find correct label
)

type (
	Ed25519PrivateKey struct {
		private_key [ed25519.PrivateKeySize]byte
	}

	Ed25519PublicKey struct {
		public_key [ed25519.PublicKeySize]byte
	}
)

// Create a new private key of type ed25519.
func NewPrivateKeyEd25519() (*Ed25519PrivateKey, error) {
	_, pr_raw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519PrivateKey{*pr_raw}, nil
}

// Restore an ed25519 private key from a raw byte stream.
// TODO does this have to be asn1? all other functions expect asn1
func LoadPrivateKeyEd25519(raw []byte) (*Ed25519PrivateKey, error) {
	var pr_loaded [ed25519.PrivateKeySize]byte
	length := copy(pr_loaded[:], raw)
	if length != ed25519.PrivateKeySize {
		return nil, errors.New("private key length incorrect")
	}
	return &Ed25519PrivateKey{pr_loaded}, nil
}

// TODO implement the raw API for the private key
func (pr *Ed25519PrivateKey) PrivateKey() crypto.PrivateKey {
	return nil
}

// Return the public key for this private key.
func (pr *Ed25519PrivateKey) Public() PublicKey {
	buf := bytes.NewBufferString(string(pr.private_key[:])) // create a bytes buffer to read the private key
	pu_raw, _, err := ed25519.GenerateKey(buf)              // use the already built private key again
	if err != nil {
		return nil
	}
	return &Ed25519PublicKey{*pu_raw}
}

// Hash the message given the hash algorythm and sign the hash using the private key.
func (pr *Ed25519PrivateKey) Sign(message []byte, hash crypto.Hash) ([]byte, error) {
	hashed_message := hash.New()
	hashed_message.Write(message)
	result := ed25519.Sign(&pr.private_key, hashed_message.Sum(nil))[:]
	return result, nil
}

// Export the private key into the Pem format.
func (pr Ed25519PrivateKey) MarshalPem() (io.WriterTo, error) {
	pem_block, err := pr.ToPem()
	if err != nil { // it does not currently return an error, but maybe that will change
		return nil, err
	}
	return marshalledPemBlock(pem.EncodeToMemory(&pem_block)), nil
}

func (pr Ed25519PrivateKey) ToPem() (pem.Block, error) {
	return pem.Block{Type: PemLabelEd25519, Bytes: pr.private_key[:]}, nil
}

// Load the public key from a raw byte stream.
// TODO should this be read from ASN.1? All other functions do that.
func LoadPublicKeyEd25519(raw []byte) (*Ed25519PublicKey, error) {
	var pu_loaded [ed25519.PublicKeySize]byte
	length := copy(pu_loaded[:], raw)
	if length != ed25519.PublicKeySize {
		return nil, errors.New("public key length incorrect")
	}
	return &Ed25519PublicKey{pu_loaded}, nil
}

// ToPem returns the pem encoded public key.
func (pu Ed25519PublicKey) ToPem() (pem.Block, error) {
	return pem.Block{Type: PemLabelPublic, Bytes: pu.public_key[:]}, nil
}

// Export the public key into the pem format.
func (pu Ed25519PublicKey) MarshalPem() (io.WriterTo, error) {
	pem_block, err := pu.ToPem()
	if err != nil {
		return nil, err
	}
	return marshalledPemBlock(pem.EncodeToMemory(&pem_block)), nil
}

// Hash the message with the hash algorythm and check the signature against the result.
func (pu Ed25519PublicKey) Verify(message []byte, signature []byte, hash crypto.Hash) (bool, error) {
	var sig [ed25519.SignatureSize]byte
	length := copy(sig[:], signature)
	if length != ed25519.SignatureSize {
		return false, errors.New("signature does not fit length")
	}
	hashed_message := hash.New()
	hashed_message.Write(message)
	return ed25519.Verify(&pu.public_key, hashed_message.Sum(nil), &sig), nil
}
