package pki

import (
	"bytes"
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

	buf := &bytes.Buffer{}
	marshPem.WriteTo(buf)

	block, _ := pem.Decode(buf.Bytes())
	if block.Type != label {
		t.Errorf("%s: marshalled pem wrong: %s", pkType, err)
		return nil, err
	}
	return block.Bytes, nil
}

// test other private key functions
func RunPrivateKeyTests(pkType string, pk PrivateKey, pu PublicKey, t *testing.T) {
	signature, err := pk.Sign(SignatureMessage, SignatureHash)
	if err != nil {
		t.Errorf("%s: error creating a signature: %s", pkType, err)
	}

	valid, err := pu.Verify(SignatureMessage, signature, SignatureHash)
	if err != nil {
		t.Errorf("%s: could not verify message: %s", pkType, err)
	}
	if !valid {
		t.Errorf("%s: signature invalid, but should be valid!", pkType)
	}
}

// test ecdsa private key functions
func TestEcdsaFunctions(t *testing.T) {
	pk, err := NewPrivateKeyEcdsa(elliptic.P521())
	if err != nil {
		t.Errorf("ecdsa: creating private key failed: %s", err)
		return
	}

	blockBytes, err := RunMarshalTest("ecdsa", pk, PemLabelEcdsa, t)
	if err != nil {
		return
	}

	pk, err = LoadPrivateKeyEcdsa(blockBytes)
	if err != nil {
		t.Errorf("ecdsa: pem content wrong: %s", err)
		return
	}

	blockBytes, err = RunMarshalTest("ecdsa-public", pk.Public(), PemLabelPublic, t)
	if err != nil {
		return
	}

	pu, err := LoadPublicKeyEcdsa(blockBytes)
	if err != nil {
		t.Errorf("ecdsa-public: pem content wrong: %s", err)
		return
	}

	RunPrivateKeyTests("ecdsa", pk, pu, t)
}

// test rsa private key functions
func TestRsaFunctions(t *testing.T) {
	pk, err := NewPrivateKeyRsa(2048)
	if err != nil {
		t.Errorf("rsa: creating private key failed: %s", err)
		return
	}

	blockBytes, err := RunMarshalTest("rsa", pk, PemLabelRsa, t)
	if err != nil {
		return
	}

	pk, err = LoadPrivateKeyRsa(blockBytes)
	if err != nil {
		t.Errorf("rsa: pem content wrong: %s", err)
		return
	}

	blockBytes, err = RunMarshalTest("rsa-public", pk.Public(), PemLabelPublic, t)
	if err != nil {
		return
	}

	pu, err := LoadPublicKeyRsa(blockBytes)
	if err != nil {
		t.Errorf("rsa-public: pem content wrong: %s", err)
		return
	}

	RunPrivateKeyTests("rsa", pk, pu, t)
}

// test rsa private key functions
func TestEd25519Functions(t *testing.T) {
	pk, err := NewPrivateKeyEd25519()
	if err != nil {
		t.Errorf("ed25519: creating private key failed: %s", err)
		return
	}

	blockBytes, err := RunMarshalTest("ed25519", pk, PemLabelEd25519, t)
	if err != nil {
		return
	}

	pk, err = LoadPrivateKeyEd25519(blockBytes)
	if err != nil {
		t.Errorf("ed25519: pem content wrong: %s", err)
		return
	}

	blockBytes, err = RunMarshalTest("ed25519-public", pk.Public(), PemLabelPublic, t)
	if err != nil {
		return
	}

	pu, err := LoadPublicKeyEd25519(blockBytes)
	if err != nil {
		t.Errorf("ed25519-public: pem content wrong: %s", err)
		return
	}

	RunPrivateKeyTests("ed25519", pk, pu, t)
}
