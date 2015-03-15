package pki

import (
//  "crypto/x509/pkix"
  "errors"
  "net"
)

var (
  ErrTypeMisMatch = errors.New("types mismatched")
)

type (
  CertificateData struct {
    // required fields
    SerialNumber   string
    CommonName     string

    // alternative data
    DNSNames       []string
    EmailAddresses []string
    IPAddresses    []net.IP

    // address data
    Country        []string
    Province       []string
    Locality       []string
    PostalCode     []string
    StreetAddress  []string
    Organization   []string
    OrganizationalUnit []string
  }
)

// create a certificate sign request with the certificate data
//func (c *CertificateData) CreateCertificateRequest(priv PrivateKey) (*Certificate, error) {
//  csr := x509.CertificateRequest{}
//  csr.Subject := c.createSubject()
//}
//
//// create a pkix.Name for the subject of a cert or csr
//func (c *CertificateData) createSubject() (pkix.Name) {
//  name := pkix.Name{}
//  errors := make([]error, 0)
//}
