package pkilib

import (
  "crypto"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/x509"
  "encoding/pem"
  "errors"
)

const (
  PemLabelEcdsa = "EC PRIVATE KEY"
)

type (
  // This type handles the function calls to the ecdsa private key by
  // implementing the interface.
  EcdsaPrivateKey struct {
    private_key *ecdsa.PrivateKey
  }

  EcdsaPublicKey struct {
    public_key *ecdsa.PublicKey
  }
)

// generate a new ecdsa private key
func NewPrivateKeyEcdsa(curve elliptic.Curve) (*EcdsaPrivateKey, error) {
  key, err := ecdsa.GenerateKey(curve, rand.Reader)
  if err != nil { return nil, err }
  return &EcdsaPrivateKey{key}, nil
}

// load the private key from the raw data
func LoadPrivateKeyEcdsa(raw []byte) (*EcdsaPrivateKey, error) {
  key, err := x509.ParseECPrivateKey(raw)
  if err != nil { return nil, err }
  return &EcdsaPrivateKey{key}, nil
}

// derive a public key from the private key
func (pr EcdsaPrivateKey) Public() PublicKey {
  return &EcdsaPublicKey{pr.private_key.Public().(*ecdsa.PublicKey)}
}

// sign a message with the private key
func (pr EcdsaPrivateKey) Sign(message []byte) ([]byte, error) {
  return make([]byte, 0), errors.New("not implemented yet!")
}

// get the private key
func (pr EcdsaPrivateKey) privateKey() crypto.PrivateKey {
  return pr.private_key
}

// implement Pemmer interface
func (pr EcdsaPrivateKey) MarshalPem() (marshalledPemBlock, error) {
  asn1, err := x509.MarshalECPrivateKey(pr.private_key)
  if err != nil { return nil, err }
  pem_block := pem.Block{Type: PemLabelEcdsa, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

// verify a message using the ecdsa public key
func (pu *EcdsaPublicKey) Verify(message []byte, signature []byte) (bool, error) {
  return false, errors.New("not implemented yet!")
}
