package pki

import (
  "crypto/rand"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "net"
)

const PemLabelCertificateRequest = "CERTIFICATE REQUEST"

type (
  CertificateData struct {
    Subject  pkix.Name

    DnsNames       []string
    EmailAddresses []string
    IpAddresses    []net.IP
  }

  Certificate x509.Certificate
  CertificateRequest x509.CertificateRequest
)

// Create a certificate sign request from the input data and the private key of
// the request creator.
func (c *CertificateData) ToCertificateRequest(private_key PrivateKey) (*CertificateRequest, error) {
  csr := &x509.CertificateRequest{}

  csr.Subject        = c.Subject
  csr.DNSNames       = c.DnsNames
  csr.IPAddresses    = c.IpAddresses
  csr.EmailAddresses = c.EmailAddresses

  csr_asn1, err := x509.CreateCertificateRequest(rand.Reader, csr, private_key.PrivateKey())
  if err != nil { return nil, err }
  return LoadCertificateSignRequest(csr_asn1)
}

// Load a certificate sign request from its asn1 representation.
func LoadCertificateSignRequest(raw []byte) (*CertificateRequest, error) {
  csr, err = x509.ParseCertificateRequest(csr_asn1)
  if err != nil { return nil, err }
  return (*CertificateRequest)(csr), nil
}

// Return the certificate sign request as a pem block.
func (c *CertificateRequest) MarshalPem() (marshalledPemBlock, error) {
  block := pem.Block{Type: PemLabelCertificateRequest, Bytes: c.Raw}
  return pem.EncodeToMemory(block), nil
}

func (c *CertificateRequest) ToCertificate() {
}
