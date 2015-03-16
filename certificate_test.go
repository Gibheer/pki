package pki

import (
  "crypto/elliptic"
//  "crypto/x509"
  "crypto/x509/pkix"
  "math/big"
  "reflect"
  "testing"
)

var (
  TestCertificateData = CertificateData{
    Subject:  pkix.Name{CommonName: "foobar"},
    DNSNames: []string{"foo.bar", "example.com"},
  }
)

func TestCertificateCreation(t *testing.T) {
  pk, err := NewPrivateKeyEcdsa(elliptic.P224())
  if err != nil { t.Errorf("cert: creating private key failed: %s", err) }

  csr, err := TestCertificateData.ToCertificateRequest(pk)
  if err != nil { t.Errorf("cert: creating csr failed: %s", err) }

  cert_opts := CertificateOptions{
    // KeyUsage:  x509.KeyUsageEncipherOnly | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
    SerialNumber: big.NewInt(1),
  }

  cert, err := csr.ToCertificate(pk, cert_opts, nil)
  if err != nil { t.Errorf("cert: creating cert failed: %s", err) }

  if !fieldsAreSame(TestCertificateData, cert) {
    t.Errorf("cert: Fields are not the same")
  }
}

func fieldsAreSame(data CertificateData, cert *Certificate) bool {
  if data.Subject.CommonName != cert.Subject.CommonName             { return false }
  if !reflect.DeepEqual(data.Subject.Country, cert.Subject.Country) { return false }
  if !reflect.DeepEqual(data.DNSNames, cert.DNSNames)               { return false }
  if !reflect.DeepEqual(data.IPAddresses, cert.IPAddresses)         { return false }
  if !reflect.DeepEqual(data.EmailAddresses, cert.EmailAddresses)   { return false }
  return true
}
