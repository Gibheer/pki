package pki

import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "errors"
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
  if err != nil { return nil, err }
  return &RsaPrivateKey{key}, nil
}

// load a rsa private key its ASN.1 presentation
func LoadPrivateKeyRsa(raw []byte) (*RsaPrivateKey, error) {
  key, err := x509.ParsePKCS1PrivateKey(raw)
  if err != nil { return nil, err }
  return &RsaPrivateKey{key}, nil
}

func (pr *RsaPrivateKey) Public() PublicKey {
  return &RsaPublicKey{pr.private_key.Public().(*rsa.PublicKey)}
}

func (pr RsaPrivateKey) Sign(message []byte) ([]byte, error) {
  return make([]byte, 0), errors.New("not implemented yet!")
}

// get the private key
func (pr RsaPrivateKey) privateKey() crypto.PrivateKey {
  return pr.private_key
}

func (pr RsaPrivateKey) MarshalPem() (marshalledPemBlock, error) {
  asn1 := x509.MarshalPKCS1PrivateKey(pr.private_key)
  pem_block := pem.Block{Type: PemLabelRsa, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

func (pu *RsaPublicKey) MarshalPem() (marshalledPemBlock, error) {
  asn1, err := x509.MarshalPKIXPublicKey(pu.public_key)
  if err != nil { return nil, err }
  pem_block := pem.Block{Type: PemLabelPublic, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

func (pu *RsaPublicKey) Verify(message []byte, signature []byte) (bool, error) {
  return false, errors.New("not implemented yet!")
}
