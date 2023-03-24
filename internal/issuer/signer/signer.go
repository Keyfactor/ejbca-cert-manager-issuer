package signer

import (
    "context"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
    ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
    "math/rand"
    "strings"
    "time"
)

type HealthChecker interface {
    Check() error
}

type HealthCheckerBuilder func(*ejbcaissuer.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
    Sign([]byte) ([]byte, error)
}

type Builder func(*ejbcaissuer.IssuerSpec, map[string][]byte) (Signer, error)

func EjbcaHealthCheckerFromIssuerAndSecretData(*ejbcaissuer.IssuerSpec, map[string][]byte) (HealthChecker, error) {
    return &ejbcaSigner{}, nil
}

func EjbcaSignerFromIssuerAndSecretData(*ejbcaissuer.IssuerSpec, map[string][]byte) (Signer, error) {
    return &ejbcaSigner{}, nil
}

type ejbcaSigner struct {
    client                   *ejbca.APIClient
    certificateProfileName   string
    endEntityProfileName     string
    certificateAuthorityName string
}

func (s *ejbcaSigner) Check() error {
    return nil
}

func (s *ejbcaSigner) Sign(csrBytes []byte) ([]byte, error) {
    csr, err := parseCSR(csrBytes)
    if err != nil {
        return nil, err
    }

    // If the CSR has a CommonName, use it as the EJBCA end entity name
    var ejbcaEeName string
    if csr.Subject.CommonName != "" {
        ejbcaEeName = csr.Subject.CommonName
    } else {
        ejbcaEeName = csr.Subject.SerialNumber
    }

    // Configure EJBCA PKCS#10 request
    enroll := ejbca.EnrollCertificateRestRequest{
        CertificateRequest:       ptr(string(csrBytes)),
        CertificateProfileName:   ptr(s.certificateProfileName),
        EndEntityProfileName:     ptr(s.endEntityProfileName),
        CertificateAuthorityName: ptr(s.certificateAuthorityName),
        Username:                 ptr(ejbcaEeName),
        Password:                 ptr(generateRandomString(20)),
        IncludeChain:             ptr(true),
    }

    // Enroll certificate
    certificateObject, _, err := s.client.V1CertificateApi.EnrollPkcs10Certificate(context.Background()).EnrollCertificateRestRequest(enroll).Execute()
    if err != nil {
        return nil, err
    }

    certAndChain, _, err := getCertificatesFromEjbcaObject(*certificateObject)
    if err != nil {
        return nil, err
    }

    // Return the certificate and chain in PEM format
    return []byte(compileCertificatesToPemString(certAndChain)), nil
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
    // extract PEM from request object
    block, _ := pem.Decode(pemBytes)
    if block == nil || block.Type != "CERTIFICATE REQUEST" {
        return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
    }
    return x509.ParseCertificateRequest(block.Bytes)
}

func getCertificatesFromEjbcaObject(ejbcaCert ejbca.CertificateRestResponse) ([]*x509.Certificate, bool, error) {
    var certBytes []byte
    var err error
    certChainFound := false

    if ejbcaCert.GetResponseFormat() == "PEM" {
        // Extract the certificate from the PEM string
        block, _ := pem.Decode([]byte(ejbcaCert.GetCertificate()))
        if block == nil {
            return nil, false, errors.New("failed to parse certificate PEM")
        }
        certBytes = block.Bytes
    } else if ejbcaCert.GetResponseFormat() == "DER" {
        // Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
        // Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
        // will give more insight into the failure.
        bytes := []byte(ejbcaCert.GetCertificate())
        for i := 0; i < 2; i++ {
            var tempBytes []byte
            tempBytes, err = base64.StdEncoding.DecodeString(string(bytes))
            if err == nil {
                bytes = tempBytes
            }
        }
        certBytes = append(certBytes, bytes...)

        // If the certificate chain is present, append it to the certificate bytes
        if len(ejbcaCert.GetCertificateChain()) > 0 {
            var chainCertBytes []byte

            certChainFound = true
            for _, chainCert := range ejbcaCert.GetCertificateChain() {
                // Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
                // Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
                // will give more insight into the failure.
                for i := 0; i < 2; i++ {
                    var tempBytes []byte
                    tempBytes, err = base64.StdEncoding.DecodeString(chainCert)
                    if err == nil {
                        chainCertBytes = tempBytes
                    }
                }

                certBytes = append(certBytes, chainCertBytes...)
            }
        }
    } else {
        return nil, false, errors.New("ejbca returned unknown certificate format: " + ejbcaCert.GetResponseFormat())
    }

    certs, err := x509.ParseCertificates(certBytes)
    if err != nil {
        return nil, false, err
    }

    return certs, certChainFound, nil
}

// compileCertificatesToPemString takes a slice of x509 certificates and returns a string containing the certificates in PEM format
// If an error occurred, the function logs the error and continues to parse the remaining objects.
func compileCertificatesToPemString(certificates []*x509.Certificate) string {
    var pemBuilder strings.Builder

    for _, certificate := range certificates {
        err := pem.Encode(&pemBuilder, &pem.Block{
            Type:  "CERTIFICATE",
            Bytes: certificate.Raw,
        })
        if err != nil {
            // TODO logging
        }
    }

    return pemBuilder.String()
}

func ptr[T any](v T) *T {
    return &v
}

func generateRandomString(length int) string {
    rand.Seed(time.Now().UnixNano())
    letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    b := make([]rune, length)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}