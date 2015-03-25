package pki

import (
  "crypto/rand"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "fmt"
  "math/big"
  "net"
  "time"
)

// labels used in the pem file format to mark certificate sign requests and certificates
const (
  PemLabelCertificateRequest = "CERTIFICATE REQUEST"
  PemLabelCertificate        = "CERTIFICATE"
)

type (
  // Use CertificateData to fill in the minimum data you need to create a certificate
  // sign request.
  CertificateData struct {
    Subject  pkix.Name

    DNSNames       []string
    EmailAddresses []string
    IPAddresses    []net.IP
  }

  // Certificate is an alias on the x509.Certificate to add some methods.
  Certificate x509.Certificate
  // CertificateRequest is an alias on the x509.CertificateRequest to add some methods.
  CertificateRequest x509.CertificateRequest

  // CertificateOptions is used to provide the necessary information to create
  // a certificate from a certificate sign request.
  CertificateOptions struct {
    SerialNumber        *big.Int
    NotBefore           time.Time
    NotAfter            time.Time // Validity bounds.
    IsCA                bool
    // how many sub ca are allowed between this ca and the end/final certificate
    // if it is -1, then no limit will be set
    CALength            int
    KeyUsage            x509.KeyUsage
  }
)

// Create a new set of certificate data.
func NewCertificateData() *CertificateData {
  return &CertificateData{Subject: pkix.Name{}}
}

// Create a certificate sign request from the input data and the private key of
// the request creator.
func (c *CertificateData) ToCertificateRequest(private_key PrivateKey) (*CertificateRequest, error) {
  csr := &x509.CertificateRequest{}

  csr.Subject        = c.Subject
  csr.DNSNames       = c.DNSNames
  csr.IPAddresses    = c.IPAddresses
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
// Please also see the certificate options struct for information on mandatory fields.
// For more information, please read http://golang.org/pkg/crypto/x509/#CreateCertificate
func (c *CertificateRequest) ToCertificate(private_key PrivateKey,
        cert_opts CertificateOptions, ca *Certificate) (*Certificate, error) {

  if err := cert_opts.Valid(); err != nil { return nil, err }

  template := &x509.Certificate{}
  template.Subject        = c.Subject
  template.DNSNames       = c.DNSNames
  template.IPAddresses    = c.IPAddresses
  template.EmailAddresses = c.EmailAddresses

  // if no ca is given, we have to set IsCA to self sign
  if ca == nil {
    template.IsCA = true
  }

  template.NotBefore    = cert_opts.NotBefore
  template.NotAfter     = cert_opts.NotAfter
  template.KeyUsage     = cert_opts.KeyUsage
  template.IsCA         = cert_opts.IsCA
  if cert_opts.IsCA {
    template.BasicConstraintsValid = true
  }
  if cert_opts.CALength >= 0 {
    template.MaxPathLen   = cert_opts.CALength
    template.MaxPathLenZero = true
    template.BasicConstraintsValid = true
  }
  template.SerialNumber = cert_opts.SerialNumber

  var cert_asn1 []byte
  var err  error
  // if we have no ca which can sign the cert, a self signed cert is wanted
  // (or isn't it? Maybe we should split creation of the template? But that would be ugly)
  if ca == nil {
    cert_asn1, err = x509.CreateCertificate(rand.Reader, template, template, c.PublicKey, private_key.PrivateKey())
  } else {
    cert_asn1, err = x509.CreateCertificate(rand.Reader, template, (*x509.Certificate)(ca), c.PublicKey, private_key.PrivateKey())
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

// marshal the certificate to a pem block
func (c *Certificate) MarshalPem() (marshalledPemBlock, error) {
  block := &pem.Block{Type: PemLabelCertificate, Bytes: c.Raw}
  return pem.EncodeToMemory(block), nil
}

// Check if the certificate options have the required fields set.
func (co *CertificateOptions) Valid() error {
  if co.SerialNumber == nil { return fmt.Errorf("No serial number set!") }
  return nil
}
