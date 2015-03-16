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

// This label is used as the type in the pem encoding of ECDSA private keys.
const PemLabelEcdsa = "EC PRIVATE KEY"

type (
  // This type handles the function calls to the ecdsa private key by
  // implementing the interface.
  EcdsaPrivateKey struct {
    private_key *ecdsa.PrivateKey
  }

  // EcdsaPublicKey is the specific public key type for ecdsa. It implements the
  // the PublicKey interface.
  EcdsaPublicKey struct {
    public_key *ecdsa.PublicKey
  }

  // This struct is used to marshal and parse the ecdsa signature.
  signatureEcdsa struct {
    R, S *big.Int
  }
)

// Create a new ECDSA private key using the specified curve.
// For available curves, please take a look at the crypto/elliptic package.
func NewPrivateKeyEcdsa(curve elliptic.Curve) (*EcdsaPrivateKey, error) {
  key, err := ecdsa.GenerateKey(curve, rand.Reader)
  if err != nil { return nil, err }
  return &EcdsaPrivateKey{key}, nil
}

// Load the private key from the asn1 representation.
func LoadPrivateKeyEcdsa(raw []byte) (*EcdsaPrivateKey, error) {
  key, err := x509.ParseECPrivateKey(raw)
  if err != nil { return nil, err }
  return &EcdsaPrivateKey{key}, nil
}

// Create a new public key from the private key.
func (pr EcdsaPrivateKey) Public() PublicKey {
  return &EcdsaPublicKey{pr.private_key.Public().(*ecdsa.PublicKey)}
}

// Sign a message using the private key and the provided hash function.
func (pr EcdsaPrivateKey) Sign(message []byte, hash crypto.Hash) ([]byte, error) {
  empty := make([]byte, 0)
  if !hash.Available() {
    return empty, errors.New("Hash method is not available!")
  }
  hashed_message := hash.New()
  hashed_message.Write(message)
  return pr.private_key.Sign(rand.Reader, hashed_message.Sum(nil), hash)
}

// This function returns the crypto.PrivateKey structure of the ECDSA key.
func (pr EcdsaPrivateKey) PrivateKey() crypto.PrivateKey {
  return pr.private_key
}

// This function implements the Pemmer interface to marshal the private key
// into a pem block.
func (pr EcdsaPrivateKey) MarshalPem() (marshalledPemBlock, error) {
  asn1, err := x509.MarshalECPrivateKey(pr.private_key)
  if err != nil { return nil, err }
  pem_block := pem.Block{Type: PemLabelEcdsa, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

// This functoin loads an ecdsa public key from the asn.1 representation.
func LoadPublicKeyEcdsa(raw []byte) (*EcdsaPublicKey, error) {
  raw_pub, err := x509.ParsePKIXPublicKey(raw)
  if err != nil { return nil, err }

  pub, ok := raw_pub.(*ecdsa.PublicKey)
  if !ok { return nil, errors.New("Not an ecdsa key!") }
  return &EcdsaPublicKey{pub}, nil
}

// This function implements the Pemmer interface to marshal the public key into
// a pem block.
func (pu *EcdsaPublicKey) MarshalPem() (marshalledPemBlock, error) {
  asn1, err := x509.MarshalPKIXPublicKey(pu.public_key)
  if err != nil { return nil, err }
  pem_block := pem.Block{Type: PemLabelPublic, Bytes: asn1}
  return pem.EncodeToMemory(&pem_block), nil
}

// This function verifies a message using the public key, signature and hash
// function.
// The hash function must be the same as was used to create the signature.
func (pu *EcdsaPublicKey) Verify(message []byte, signature_raw []byte, hash crypto.Hash) (bool, error) {
  var sig signatureEcdsa
  _, err := asn1.Unmarshal(signature_raw, &sig)
  if err != nil { return false, err }
  hashed_message := hash.New()
  hashed_message.Write(message)
  return ecdsa.Verify(pu.public_key, hashed_message.Sum(nil), sig.R, sig.S), nil
}
