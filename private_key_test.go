package pki

import (
  "crypto"
  "crypto/elliptic"
  "encoding/pem"
  "testing"
)

var (
  SignatureMessage = []byte("foobar")
  SignatureHash    = crypto.SHA512
)

type (
  Loader func(raw []byte) (PublicKey, error)
)

// run the marshal test
func RunMarshalTest(pkType string, pe Pemmer, label string, t *testing.T) ([]byte, error) {
  marshPem, err := pe.MarshalPem()
  if err != nil {
    t.Errorf("%s: marshal pem not working: %s", pkType, err)
    return nil, err
  }

  block, _ := pem.Decode(marshPem)
  if block.Type != label {
    t.Errorf("%s: marshalled pem wrong: %s", pkType, err)
    return nil, err
  }
  return block.Bytes, nil
}

// test other private key functions
func RunPrivateKeyTests(pkType string, pk PrivateKey, pu PublicKey, t *testing.T) {
  signature, err := pk.Sign(SignatureMessage, SignatureHash)
  if err != nil { t.Errorf("%s: error creating a signature: %s", pkType, err) }

  valid, err := pu.Verify(SignatureMessage, signature, SignatureHash)
  if err != nil { t.Errorf("%s: could not verify message: %s", pkType, err) }
  if !valid { t.Errorf("%s: signature invalid, but should be valid!", pkType) }
}

// test ecdsa private key functions
func TestEcdsaFunctions(t *testing.T) {
  pk, err := NewPrivateKeyEcdsa(elliptic.P521())
  if err != nil { t.Errorf("ecdsa: creating private key failed: %s", err) }

  blockBytes, err := RunMarshalTest("ecdsa", pk, PemLabelEcdsa, t)
  if err != nil { return }

  pk, err = LoadPrivateKeyEcdsa(blockBytes)
  if err != nil { t.Errorf("ecdsa: pem content wrong: %s", err) }

  blockBytes, err = RunMarshalTest("ecdsa-public", pk.Public(), PemLabelPublic, t)
  if err != nil { return }

  pu, err := LoadPublicKeyEcdsa(blockBytes)
  if err != nil { t.Errorf("ecdsa-public: pem content wrong: %s", err) }

  RunPrivateKeyTests("ecdsa", pk, pu, t)
}

// test rsa private key functions
func TestRsaFunctions(t *testing.T) {
  pk, err := NewPrivateKeyRsa(2048)
  if err != nil { t.Errorf("rsa: creating private key failed: %s", err) }

  blockBytes, err := RunMarshalTest("rsa", pk, PemLabelRsa, t)
  if err != nil { return }

  pk, err = LoadPrivateKeyRsa(blockBytes)
  if err != nil { t.Errorf("rsa: pem content wrong: %s", err) }


  blockBytes, err = RunMarshalTest("rsa-public", pk.Public(), PemLabelPublic, t)
  if err != nil { return }

  pu, err := LoadPublicKeyRsa(blockBytes)
  if err != nil { t.Errorf("rsa-public: pem content wrong: %s", err) }

  RunPrivateKeyTests("rsa", pk, pu, t)
}
