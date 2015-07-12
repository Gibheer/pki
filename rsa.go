package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

const (
	PemLabelRsa = "RSA PRIVATE KEY"
)

type (
	RsaPrivateKey struct {
		private_key *rsa.PrivateKey
	}

	RsaPublicKey struct {
		public_key *rsa.PublicKey
	}
)

// generate a new rsa private key
func NewPrivateKeyRsa(size int) (*RsaPrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	return &RsaPrivateKey{key}, nil
}

// load a rsa private key its ASN.1 presentation
func LoadPrivateKeyRsa(raw []byte) (*RsaPrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return &RsaPrivateKey{key}, nil
}

func (pr *RsaPrivateKey) Public() PublicKey {
	return &RsaPublicKey{pr.private_key.Public().(*rsa.PublicKey)}
}

func (pr RsaPrivateKey) Sign(message []byte, hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return make([]byte, 0), errors.New("Hash method is not available!")
	}
	hashed_message := hash.New()
	hashed_message.Write(message)
	return rsa.SignPKCS1v15(rand.Reader, pr.private_key, hash, hashed_message.Sum(nil))
}

// get the private key
func (pr RsaPrivateKey) PrivateKey() crypto.PrivateKey {
	return pr.private_key
}

func (pr RsaPrivateKey) MarshalPem() (io.WriterTo, error) {
	asn1 := x509.MarshalPKCS1PrivateKey(pr.private_key)
	pem_block := pem.Block{Type: PemLabelRsa, Bytes: asn1}
	return marshalledPemBlock(pem.EncodeToMemory(&pem_block)), nil
}

// restore a rsa public key
func LoadPublicKeyRsa(raw []byte) (*RsaPublicKey, error) {
	pub := &RsaPublicKey{}
	if pub_raw, err := x509.ParsePKIXPublicKey(raw); err != nil {
		return nil, err
	} else {
		pub.public_key = pub_raw.(*rsa.PublicKey)
	}
	return pub, nil
}

// marshal a rsa public key into pem format
func (pu *RsaPublicKey) MarshalPem() (io.WriterTo, error) {
	asn1, err := x509.MarshalPKIXPublicKey(pu.public_key)
	if err != nil {
		return nil, err
	}
	pem_block := pem.Block{Type: PemLabelPublic, Bytes: asn1}
	return marshalledPemBlock(pem.EncodeToMemory(&pem_block)), nil
}

// verify a message with a signature using the public key
func (pu *RsaPublicKey) Verify(message []byte, signature []byte, hash crypto.Hash) (bool, error) {
	hashed_message := hash.New()
	hashed_message.Write(message)
	if err := rsa.VerifyPKCS1v15(pu.public_key, hash, hashed_message.Sum(nil), signature); err != nil {
		return false, err
	}
	return true, nil
}
