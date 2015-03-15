package pki

import (
  "crypto"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/x509"
  "encoding/asn1"
  "encoding/pem"
  "errors"
  "math/big"
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

  signatureEcdsa struct {
    R, S *big.Int
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
func (pr EcdsaPrivateKey) Sign(message []byte, hash crypto.Hash) ([]byte, error) {
  empty := make([]byte, 0)
  if !hash.Available() {
    return empty, errors.New("Hash method is not available!")
  }
  hashed_message := hash.New()
  hashed_message.Write(message)
  return pr.private_key.Sign(rand.Reader, hashed_message.Sum(nil), hash)
}

// get the private key
func (pr EcdsaPrivateKey) PrivateKey() crypto.PrivateKey {
  return pr.private_key
}

// implement Pemmer interface
func (pr EcdsaPrivateKey) MarshalPem() (marshalledPemBlock, error) {
  asn1, err := x509.MarshalECPrivateKey(pr.private_key)
  if err != nil { return nil, err }
  pem_block := pem.Block{Type: PemLabelEcdsa, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

// load an ecdsa public key
func LoadPublicKeyEcdsa(raw []byte) (*EcdsaPublicKey, error) {
  raw_pub, err := x509.ParsePKIXPublicKey(raw)
  if err != nil { return nil, err }

  pub, ok := raw_pub.(*ecdsa.PublicKey)
  if !ok { return nil, errors.New("Not an ecdsa key!") }
  return &EcdsaPublicKey{pub}, nil
}

// marshal the public key to a pem block
func (pu *EcdsaPublicKey) MarshalPem() (marshalledPemBlock, error) {
  asn1, err := x509.MarshalPKIXPublicKey(pu.public_key)
  if err != nil { return nil, err }
  pem_block := pem.Block{Type: PemLabelPublic, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

// verify a message using the ecdsa public key
func (pu *EcdsaPublicKey) Verify(message []byte, signature_raw []byte, hash crypto.Hash) (bool, error) {
  var sig signatureEcdsa
  _, err := asn1.Unmarshal(signature_raw, &sig)
  if err != nil { return false, err }
  hashed_message := hash.New()
  hashed_message.Write(message)
  return ecdsa.Verify(pu.public_key, hashed_message.Sum(nil), sig.R, sig.S), nil
}
