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

	// Create the signer
	signer, err := EjbcaSignerFromIssuerAndSecretData(context.Background(), &spec, authSecretData, caSecretData)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a CSR
	csr, err := generateCSR(ejbcaCsrDn)
	if err != nil {
		t.Fatal(err)
	}

	signedCert, err := signer.Sign(context.Background(), csr)
	if err != nil {
		return
	}

	t.Log(string(signedCert))
}

func generateCSR(subject string) ([]byte, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
	if err != nil {
		return make([]byte, 0, 0), err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return make([]byte, 0, 0), err
	}

	return csrBuf.Bytes(), nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com"
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
	var name pkix.Name

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
