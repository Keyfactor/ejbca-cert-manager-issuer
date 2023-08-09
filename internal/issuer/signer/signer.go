/*
Copyright 2023 Keyfactor.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
	"math/rand"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"time"
)

type ejbcaSigner struct {
	client                   *ejbca.APIClient
	certificateProfileName   string
	endEntityProfileName     string
	certificateAuthorityName string
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(context.Context, *ejbcaissuer.IssuerSpec, map[string][]byte, map[string][]byte) (HealthChecker, error)
type EjbcaSignerBuilder func(context.Context, *ejbcaissuer.IssuerSpec, map[string][]byte, map[string][]byte) (Signer, error)

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

func EjbcaHealthCheckerFromIssuerAndSecretData(ctx context.Context, spec *ejbcaissuer.IssuerSpec, clientCertSecretData map[string][]byte, caCertSecretData map[string][]byte) (HealthChecker, error) {
	signer := ejbcaSigner{}

	client, err := createClientFromSecretMap(ctx, spec.Hostname, clientCertSecretData, caCertSecretData)
	if err != nil {
		return nil, err
	}

	signer.client = client

	return &signer, nil
}

func EjbcaSignerFromIssuerAndSecretData(ctx context.Context, spec *ejbcaissuer.IssuerSpec, clientCertSecretData map[string][]byte, caCertSecretData map[string][]byte) (Signer, error) {
	signer := ejbcaSigner{}
	// secretData contains data from a K8s TLS secret object

	client, err := createClientFromSecretMap(ctx, spec.Hostname, clientCertSecretData, caCertSecretData)
	if err != nil {
		return nil, err
	}
	signer.client = client

	// Validate EJBCA signing metadata
	if spec.CertificateProfileName == "" {
		return nil, errors.New("certificateProfileName not found in secret data")
	}
	if spec.EndEntityProfileName == "" {
		return nil, errors.New("endEntityProfileName not found in secret data")
	}
	if spec.CertificateAuthorityName == "" {
		return nil, errors.New("certificateAuthorityName not found in secret data")
	}
	signer.certificateProfileName = spec.CertificateProfileName
	signer.endEntityProfileName = spec.EndEntityProfileName
	signer.certificateAuthorityName = spec.CertificateAuthorityName

	return &signer, nil
}

func (s *ejbcaSigner) Check() error {
	// Check EJBCA API status
	_, _, err := s.client.V1CertificateApi.Status2(context.Background()).Execute()
	if err != nil {
		return err
	}

	return nil
}

func (s *ejbcaSigner) Sign(ctx context.Context, csrBytes []byte) ([]byte, error) {
	k8sLog := log.FromContext(ctx)

	csr, err := parseCSR(csrBytes)
	if err != nil {
		return nil, err
	}

	// Log the common metadata of the CSR
	k8sLog.Info(fmt.Sprintf("Found CSR wtih Common Name \"%s\" and %d DNS SANs, %d IP SANs, and %d URI SANs", csr.Subject.CommonName, len(csr.DNSNames), len(csr.IPAddresses), len(csr.URIs)))

	// If the CSR has a CommonName, use it as the EJBCA end entity name
	var ejbcaEeName string
	if csr.Subject.CommonName != "" {
		ejbcaEeName = csr.Subject.CommonName
	} else {
		ejbcaEeName = csr.Subject.SerialNumber
	}

	k8sLog.Info(fmt.Sprintf("Using or Creating EJBCA End Entity called \"%s\"", ejbcaEeName))

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

	k8sLog.Info(fmt.Sprintf("Enrolling certificate with EJBCA with certificate profile name \"%s\", end entity profile name \"%s\", and certificate authority name \"%s\"", s.certificateProfileName, s.endEntityProfileName, s.certificateAuthorityName))

	// Enroll certificate
	certificateObject, _, err := s.client.V1CertificateApi.EnrollPkcs10Certificate(context.Background()).EnrollCertificateRestRequest(enroll).Execute()
	if err != nil {
		detail := fmt.Sprintf("error enrolling certificate with EJBCA. verify that the certificate profile name, end entity profile name, and certificate authority name are appropriate for the certificate request.")

		var bodyError *ejbca.GenericOpenAPIError
		ok := errors.As(err, &bodyError)
		if ok {
			detail += fmt.Sprintf(" - %s", string(bodyError.Body()))
		}

		k8sLog.Error(err, detail)

		return nil, fmt.Errorf(detail)
	}

	certAndChain, _, err := getCertificatesFromEjbcaObject(*certificateObject)
	if err != nil {
		k8sLog.Error(err, fmt.Sprintf("error getting certificate from EJBCA response: %s", err.Error()))
		return nil, err
	}

	k8sLog.Info(fmt.Sprintf("Successfully enrolled certificate with EJBCA"))

	// Return the certificate and chain in PEM format
	return compileCertificatesToPemBytes(certAndChain)
}

func createClientFromSecretMap(ctx context.Context, hostname string, clientCertSecretData map[string][]byte, caCertSecretData map[string][]byte) (*ejbca.APIClient, error) {
	var err error
	k8sLog := log.FromContext(ctx)

	// Create EJBCA API Client
	ejbcaConfig := ejbca.NewConfiguration()

	if ejbcaConfig.Host == "" {
		ejbcaConfig.Host = hostname
	}

	clientCertByte, ok := clientCertSecretData["tls.crt"]
	if !ok || len(clientCertByte) == 0 {
		return nil, errors.New("tls.crt not found in secret data")
	}

	// Try to decode client certificate as a PEM formatted block
	clientCertPemBlock, clientKeyPemBlock := decodePEMBytes(clientCertByte)

	// If clientCertPemBlock is empty, try to decode the certificate as a DER formatted block
	if len(clientCertPemBlock) == 0 {
		k8sLog.Info("tls.crt does not appear to be PEM formatted. Attempting to decode as DER formatted block.")
		// Try to b64 decode the DER formatted block, but don't error if it fails
		clientCertBytes, err := base64.StdEncoding.DecodeString(string(clientCertByte))
		if err == nil {
			clientCertPemBlock = append(clientCertPemBlock, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
		} else {
			// If b64 decoding fails, assume the certificate is DER formatted
			clientCertPemBlock = append(clientCertPemBlock, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertByte})
		}
	}

	// Determine if ejbcaCert contains a private key
	clientCertContainsKey := false
	if clientKeyPemBlock != nil {
		clientCertContainsKey = true
	}

	if !clientCertContainsKey {
		clientKeyBytes, ok := clientCertSecretData["tls.key"]
		if !ok || len(clientKeyBytes) == 0 {
			return nil, errors.New("tls.pem not found in secret data")
		}

		// Try to decode client key as a PEM formatted block
		_, tempKeyPemBlock := decodePEMBytes(clientKeyBytes)
		if tempKeyPemBlock != nil {
			clientKeyPemBlock = tempKeyPemBlock
		} else {
			k8sLog.Info("tls.key does not appear to be PEM formatted. Attempting to decode as DER formatted block.")
			// Try to b64 decode the DER formatted block, but don't error if it fails
			tempKeyBytes, err := base64.StdEncoding.DecodeString(string(clientKeyBytes))
			if err == nil {
				clientKeyPemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: tempKeyBytes}
			} else {
				// If b64 decoding fails, assume the private key is DER formatted
				clientKeyPemBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyBytes}
			}
		}
	}

	// Create a TLS certificate object
	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(clientCertPemBlock[0]), pem.EncodeToMemory(clientKeyPemBlock))
	if err != nil {
		return nil, err
	}

	// Add the TLS certificate to the EJBCA configuration
	ejbcaConfig.SetClientCertificate(&tlsCert)

	// If the CA certificate is provided, add it to the EJBCA configuration
	if caCertSecretData != nil && len(caCertSecretData) > 0 {
		// There is no requirement that the CA certificate is stored under a specific key in the secret, so we can just iterate over the map
		var caCertBytes []byte
		for _, caCertBytes = range caCertSecretData {
		}

		// Try to decode caCertBytes as a PEM formatted block
		caChainBlocks, _ := decodePEMBytes(caCertBytes)
		if caChainBlocks != nil {
			var caChain []*x509.Certificate
			for _, block := range caChainBlocks {
				// Parse the PEM block into an x509 certificate
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}

				caChain = append(caChain, cert)
			}

			ejbcaConfig.SetCaCertificates(caChain)
		}
	}

	// Create EJBCA API Client
	client, err := ejbca.NewAPIClient(ejbcaConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
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
func compileCertificatesToPemBytes(certificates []*x509.Certificate) ([]byte, error) {
	var pemBuilder strings.Builder

	for _, certificate := range certificates {
		err := pem.Encode(&pemBuilder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
		if err != nil {
			return make([]byte, 0, 0), err
		}
	}

	return []byte(pemBuilder.String()), nil
}

func decodePEMBytes(buf []byte) ([]*pem.Block, *pem.Block) {
	var privKey *pem.Block
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			privKey = block
		} else {
			certificates = append(certificates, block)
		}
	}
	return certificates, privKey
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
