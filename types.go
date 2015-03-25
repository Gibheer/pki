// Package pki provides an easier way to create crypto related structures
// with the intent of making the management of these structures easier for
// other programs.
// Currently it provides mechanisms to create private keys in ECDSA and RSA,
// create public keys, create certificate sign requests and certificates.
//
// To create a new private key, there are two ways
// for an ecdsa key
//   private_key, err := NewPrivateKeyEcdsa(elliptic.P521())
// or for a RSA key
//   private_key, err := NewPrivateKeyRSA(4096)
//
// Getting a private key from the private key can be done with
//   public_key := private_key.Public()
package pki

import (
  "crypto"
  "io"
)

// This label is used as the type in the pem encoding of public keys.
const PemLabelPublic = "PUBLIC KEY"

type (
  // PrivateKey is a common interface for all crypto implementations to provide
  // the same functions, like deriving a public key or signing a message.
  PrivateKey interface {
    // Derive a new public key from the private key.
    Public() PublicKey
    // Sign a message using the public key and the given hash method.
    // To use a hash method, include the package
    //   import _ "crypto/sha512"
    Sign(message []byte, hash crypto.Hash) ([]byte, error)

    // Return the original go structure of the private key.
    PrivateKey() crypto.PrivateKey
  }

  // PublicKey is used by the different crypto implementations to provide the
  // same functionality like verifying a message against a signature.
  PublicKey interface {
    Pemmer
    // This function can be used to verify a message against a provided signature
    // using the given hash function.
    Verify(message []byte, signature []byte, hash crypto.Hash) (bool, error)
  }

  // Pemmer is used by all crypto structures which need to be available
  // in the pem format. The result can then be written to any structure
  // implementing the io.Writer interface.
  Pemmer interface {
    MarshalPem() (io.WriterTo, error)
  }
)
