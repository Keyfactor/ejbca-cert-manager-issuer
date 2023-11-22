/*
Copyright 2023 The Keyfactor Command Authors.

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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestEjbcaHealthCheckerFromIssuerAndSecretData(t *testing.T) {
	pathToClientCert := os.Getenv("EJBCA_CLIENT_CERT_PATH")
	pathToCaCert := os.Getenv("EJBCA_CA_CERT_PATH")
	hostname := os.Getenv("EJBCA_HOSTNAME")

	if pathToClientCert == "" || hostname == "" {
		t.Fatal("EJBCA_CLIENT_CERT_PATH and EJBCA_HOSTNAME must be set to run this test")
	}

	// Read the client cert and key from the file system.
	clientCertBytes, err := os.ReadFile(pathToClientCert)
	if err != nil {
		t.Fatal(err)
	}

	authSecretData := map[string][]byte{}
	authSecretData["tls.crt"] = clientCertBytes

	// Read the CA cert from the file system.
	caCertBytes, err := os.ReadFile(pathToCaCert)
	if err != nil {
		t.Log("CA cert not found, assuming that EJBCA is using a trusted CA")
	}

	caSecretData := map[string][]byte{}
	if len(caCertBytes) != 0 {
		caSecretData["tls.crt"] = caCertBytes
	}

	spec := ejbcaissuer.IssuerSpec{
		Hostname: hostname,
	}

	// Create the signer
	checker, err := EjbcaHealthCheckerFromIssuerAndSecretData(context.Background(), &spec, authSecretData, caSecretData)
	if err != nil {
		t.Fatal(err)
	}

	err = checker.Check()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Health check passed")
}

func TestEjbcaSignerFromIssuerAndSecretData(t *testing.T) {
	ctx := context.Background()

	pathToClientCert := os.Getenv("EJBCA_CLIENT_CERT_PATH")
	pathToCaCert := os.Getenv("EJBCA_CA_CERT_PATH")
	hostname := os.Getenv("EJBCA_HOSTNAME")
	ejbcaCaName := os.Getenv("EJBCA_CA_NAME")
	ejbcaCertificateProfileName := os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME")
	ejbcaEndEntityProfileName := os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME")
	ejbcaCsrDn := os.Getenv("EJBCA_CSR_SUBJECT")

	if pathToClientCert == "" || hostname == "" {
		t.Fatal("EJBCA_CLIENT_CERT_PATH and EJBCA_HOSTNAME must be set to run this test")
	}

	if ejbcaCaName == "" || ejbcaCertificateProfileName == "" || ejbcaEndEntityProfileName == "" {
		t.Fatal("EJBCA_CA_NAME, EJBCA_CERTIFICATE_PROFILE_NAME, and EJBCA_END_ENTITY_PROFILE_NAME must be set to run this test")
	}

	if ejbcaCsrDn == "" {
		t.Fatal("EJBCA_CSR_SUBJECT must be set to run this test")
	}

	// Read the client cert and key from the file system.
	clientCertBytes, err := os.ReadFile(pathToClientCert)
	if err != nil {
		return
	}

	authSecretData := map[string][]byte{}
	authSecretData["tls.crt"] = clientCertBytes

	spec := ejbcaissuer.IssuerSpec{
		Hostname:                 hostname,
		CertificateProfileName:   ejbcaCertificateProfileName,
		EndEntityProfileName:     ejbcaEndEntityProfileName,
		CertificateAuthorityName: ejbcaCaName,
	}

	// Read the CA cert from the file system.
	caCertBytes, err := os.ReadFile(pathToCaCert)
	if err != nil {
		t.Log("CA cert not found, assuming that EJBCA is using a trusted CA")
	}

	caSecretData := map[string][]byte{}
	if len(caCertBytes) != 0 {
		caSecretData["tls.crt"] = caCertBytes
	}

	t.Run("No Annotations", func(t *testing.T) {
		// Create the signer
		signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
		if err != nil {
			t.Fatal(err)
		}

		// Generate a CSR
		csr, _, err := generateCSR(ejbcaCsrDn, []string{""}, []string{""}, []string{""})
		if err != nil {
			t.Fatal(err)
		}

		signedCert, chain, err := signer.Sign(context.Background(), csr)
		if err != nil {
			t.Fatal(err)
		}

		t.Log(fmt.Sprintf("Signed certificate: %s", string(signedCert)))
		t.Log(fmt.Sprintf("Chain: %s", string(chain)))
	})

	t.Run("With Annotations", func(t *testing.T) {
		// Create test annotations
		annotations := map[string]string{
			"ejbca-issuer.keyfactor.com/certificateAuthorityName": "TestCertificateAuthority",
			"ejbca-issuer.keyfactor.com/certificateProfileName":   "TestCertificateProfile",
			"ejbca-issuer.keyfactor.com/endEntityName":            "TestEndEntity",
			"ejbca-issuer.keyfactor.com/endEntityProfileName":     "TestEndEntityProfile",
		}

		// Create the signer
		signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, annotations, authSecretData, caSecretData)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "TestCertificateAuthority", signer.certificateAuthorityName)
		assert.Equal(t, "TestCertificateProfile", signer.certificateProfileName)
		assert.Equal(t, "TestEndEntity", signer.endEntityName)
		assert.Equal(t, "TestEndEntityProfile", signer.endEntityProfileName)
	})

	// Test the default end entity name conditionals
	t.Run("Default End Entity Name Tests", func(t *testing.T) {

		// Test when endEntityName is not set
		t.Run("endEntityName is not set", func(t *testing.T) {
			spec.EndEntityName = ""

			// Create the signer
			signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("CN", func(t *testing.T) {
				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, "purplecat.example.com", signer.getEndEntityName(ctx, csr))
			})

			t.Run("DNS", func(t *testing.T) {
				// Generate a CSR
				_, csr, err := generateCSR("", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "reddog.example.com")
			})

			t.Run("URI", func(t *testing.T) {
				// Generate a CSR
				_, csr, err := generateCSR("", []string{""}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, "https://blueelephant.example.com", signer.getEndEntityName(ctx, csr))
			})

			t.Run("IP", func(t *testing.T) {
				// Generate a CSR
				_, csr, err := generateCSR("", []string{""}, []string{""}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "192.168.1.1")
			})
		})

		// Test when endEntityName is set
		t.Run("endEntityName is set", func(t *testing.T) {
			t.Run("CN", func(t *testing.T) {
				spec.EndEntityName = "cn"

				// Create the signer
				signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
				if err != nil {
					t.Fatal(err)
				}

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "purplecat.example.com")
			})

			t.Run("DNS", func(t *testing.T) {
				spec.EndEntityName = "dns"

				// Create the signer
				signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
				if err != nil {
					t.Fatal(err)
				}

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "reddog.example.com")
			})

			t.Run("URI", func(t *testing.T) {
				spec.EndEntityName = "uri"

				// Create the signer
				signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
				if err != nil {
					t.Fatal(err)
				}

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "https://blueelephant.example.com")
			})

			t.Run("IP", func(t *testing.T) {
				spec.EndEntityName = "ip"

				// Create the signer
				signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
				if err != nil {
					t.Fatal(err)
				}

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "192.168.1.1")
			})

			t.Run("certificateName", func(t *testing.T) {
				spec.EndEntityName = "certificateName"

				// Create test annotations
				annotations := map[string]string{
					"cert-manager.io/certificate-name": "test-cert-manager-certificate",
				}

				// Create the signer
				signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, annotations, authSecretData, caSecretData)
				if err != nil {
					t.Fatal(err)
				}

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "test-cert-manager-certificate")
			})

			t.Run("endEntityName", func(t *testing.T) {
				spec.EndEntityName = "Hello World!"

				// Create the signer
				signer, err := ejbcaSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
				if err != nil {
					t.Fatal(err)
				}

				// Generate a CSR
				_, csr, err := generateCSR("CN=purplecat.example.com", []string{"reddog.example.com"}, []string{"https://blueelephant.example.com"}, []string{"192.168.1.1"})
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, signer.getEndEntityName(ctx, csr), "Hello World!")
			})
		})
	})
}

func generateCSR(subject string, dnsNames []string, uris []string, ipAddresses []string) ([]byte, *x509.CertificateRequest, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
	if err != nil {
		return nil, nil, err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if len(dnsNames) > 0 {
		template.DNSNames = dnsNames
	}

	// Parse and add URIs
	var uriPointers []*url.URL
	for _, u := range uris {
		if u == "" {
			continue
		}
		uriPointer, err := url.Parse(u)
		if err != nil {
			return nil, nil, err
		}
		uriPointers = append(uriPointers, uriPointer)
	}
	template.URIs = uriPointers

	// Parse and add IPAddresses
	var ipAddrs []net.IP
	for _, ipStr := range ipAddresses {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddrs = append(ipAddrs, ip)
	}
	template.IPAddresses = ipAddrs

	// Generate the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, nil, err
	}

	var csrBuf bytes.Buffer
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return nil, nil, err
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, err
	}

	return csrBuf.Bytes(), parsedCSR, nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com"
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
	var name pkix.Name

	if subject == "" {
		return name, nil
	}

	// Split the subject into its individual parts
	parts := strings.Split(subject, ",")

	for _, part := range parts {
		// Split the part into key and value
		keyValue := strings.SplitN(part, "=", 2)

		if len(keyValue) != 2 {
			return pkix.Name{}, asn1.SyntaxError{Msg: "malformed subject DN"}
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		// Map the key to the appropriate field in the pkix.Name struct
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			if randomizeCn {
				value = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}
