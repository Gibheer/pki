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

func NewCertificateData() *CertificateData {
  return &CertificateData{Subject: pkix.Name{}}
}

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
  csr, err := x509.ParseCertificateRequest(raw)
  if err != nil { return nil, err }
  return (*CertificateRequest)(csr), nil
}

// Return the certificate sign request as a pem block.
func (c *CertificateRequest) MarshalPem() (marshalledPemBlock, error) {
  block := &pem.Block{Type: PemLabelCertificateRequest, Bytes: c.Raw}
  return pem.EncodeToMemory(block), nil
}

// Convert the certificate sign request to a certificate using the private key
// of the signer and the certificate of the signer.
// If the certificate is null, the sign request will be used to sign itself.
// For more information, please read http://golang.org/pkg/crypto/x509/#CreateCertificate
func (c *CertificateRequest) ToCertificate(private_key PrivateKey, ca *Certificate) (*Certificate, error) {
  template := &x509.Certificate{}
  template.Subject        = c.Subject
  template.DNSNames       = c.DNSNames
  template.IPAddresses    = c.IPAddresses
  template.EmailAddresses = c.EmailAddresses

  var cert_asn1 []byte
  var err  error
  if ca == nil {
    cert_asn1, err = x509.CreateCertificate(rand.Reader, template, template, c.PublicKey, private_key)
  } else {
    cert_asn1, err = x509.CreateCertificate(rand.Reader, template, (*x509.Certificate)(ca), c.PublicKey, private_key)
  }
  if err != nil { return nil, err }
  return LoadCertificate(cert_asn1)
}

// Load a certificate from its asn1 representation.
func LoadCertificate(raw []byte) (*Certificate, error) {
  cert, err := x509.ParseCertificate(raw)
  if err != nil { return nil, err }
  return (*Certificate)(cert), nil
}
