package pki

import (
  "crypto/elliptic"
  "encoding/pem"
  "testing"
)

var (
  SignatureMessage = []byte("foobar")
)

// run the marshal test
func RunMarshalTest(pk_type string, pe Pemmer, label string, t *testing.T) ([]byte, error) {
  marsh_pem, err := pe.MarshalPem()
  if err != nil {
    t.Errorf("%s: marshal pem not working: %s", pk_type, err)
    return nil, err
  }

  block, _ := pem.Decode(marsh_pem)
  if block.Type != label {
    t.Errorf("%s: marshalled pem wrong: %s", pk_type, err)
    return nil, err
  }
  return block.Bytes, nil
}

// test other private key functions
func RunPrivateKeyTests(pk_type string, pk PrivateKey, t *testing.T) {
  pu := pk.Public()

  // TODO check return result of the marshalled public key
  _, err := RunMarshalTest(pk_type + "-public", pu, PemLabelPublic, t)
  if err != nil { return }

  signature, err := pk.Sign(SignatureMessage)
  if err != nil { t.Errorf("%s: error creating a signature: %s", pk_type, err) }

  valid, err := pu.Verify(SignatureMessage, signature)
  if err != nil { t.Errorf("%s: could not verify message: %s", pk_type, err) }
  if !valid { t.Errorf("%s: signature invalid, but should be valid!", pk_type) }
}

// test ecdsa private key functions
func TestEcdsaFunctions(t *testing.T) {
  pk, err := NewPrivateKeyEcdsa(elliptic.P521())
  if err != nil { t.Errorf("ecdsa: creating private key failed: %s", err) }

  block_bytes, err := RunMarshalTest("ecdsa", pk, PemLabelEcdsa, t)
  if err != nil { return }

  pk, err = LoadPrivateKeyEcdsa(block_bytes)
  if err != nil { t.Errorf("ecdsa: pem content wrong: %s", err) }

  RunPrivateKeyTests("ecdsa", pk, t)
}

// test rsa private key functions
func TestRsaFunctions(t *testing.T) {
  pk, err := NewPrivateKeyRsa(2048)
  if err != nil { t.Errorf("rsa: creating private key failed: %s", err) }

  block_bytes, err := RunMarshalTest("rsa", pk, PemLabelRsa, t)
  if err != nil { return }

  pk, err = LoadPrivateKeyRsa(block_bytes)
  if err != nil { t.Errorf("rsa: pem content wrong: %s", err) }

  RunPrivateKeyTests("rsa", pk, t)
}
