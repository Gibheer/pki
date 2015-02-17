package pki

import (
  "crypto"
)

// this file holds all the interfaces used in the program until it can be split
// properly

const PemLabelPublic = "PUBLIC KEY"

type (
  // interface for any private key
  PrivateKey interface {
    // derive a public key from the private key
    Public() PublicKey
    // sign a message with the private key
    Sign(message []byte) ([]byte, error)

    // return the private key structure
    privateKey() crypto.PrivateKey
  }

  // interface for any public key
  PublicKey interface {
    Pemmer
    // use the public key to verify a message against a signature
    Verify(message []byte, signature []byte) (bool, error)
  }

  Pemmer interface {
    MarshalPem() (marshalledPemBlock, error)
  }
)
