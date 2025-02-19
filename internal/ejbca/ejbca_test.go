/*
Copyright © 2024 Keyfactor

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

package ejbca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEjbcaAuthenticator struct {
	client *http.Client
}

// GetHTTPClient implements ejbcaclient.Authenticator
func (f *fakeEjbcaAuthenticator) GetHTTPClient() (*http.Client, error) {
	return f.client, nil
}

type fakeClientConfig struct {
	testServer *httptest.Server
}

func (f *fakeClientConfig) newFakeAuthenticator(context.Context) (ejbca.Authenticator, error) {
	return &fakeEjbcaAuthenticator{
		client: f.testServer.Client(),
	}, nil
}

func TestNewSigner(t *testing.T) {
	caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	serverCert, _ := issueTestCertificate(t, "Server", caCert, rootKey)
	serverCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})

	authCert, authKey := issueTestCertificate(t, "Auth", caCert, rootKey)
	keyByte, err := x509.MarshalECPrivateKey(authKey)
	require.NoError(t, err)
	authCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authCert.Raw})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyByte})

	for i, tt := range []struct {
		name string
		opts []Option

		expectError                bool
		expectedErrorMessagePrefix string
	}{
		{
			name: "No opts provided",

			expectError:                true,
			expectedErrorMessagePrefix: "",
		},
		{
			name: "No hostname",
			opts: []Option{
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "hostname is required",
		},
		{
			name: "No CA name",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "certificateAuthorityName is required",
		},
		{
			name: "No Certificate Profile name",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "certificateProfileName is required",
		},
		{
			name: "No End Entity Profile name",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "endEntityProfileName is required",
		},
		{
			name: "No Client Certificate",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientKey: keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "client certificate is required",
		},
		{
			name: "No Client Key",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "client key is required",
		},
		{
			name: "Invalid CA certificate",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts([]byte("not-a-ca-cert")),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "failed to create new EJBCA API client: failed to create new EJBCA API authenticator: didn't find pem certificate in ca cert configmap",
		},
		{
			name: "Invalid Client Certificate",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: []byte("not-a-client-cert"),
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "failed to create new EJBCA API client: failed to create new EJBCA API authenticator: failed to load client certificate",
		},
		{
			name: "Invalid Client Key",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  []byte("not-a-client-key"),
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "failed to create new EJBCA API client: failed to create new EJBCA API authenticator: failed to load client certificate",
		},
		{
			name: "No Token URL",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithOAuth(&OAuth{
					ClientID:     "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ",
					ClientSecret: "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H",
					Scopes:       "read:certificates,write:certificates",
					Audience:     "https://ejbca.example.com",
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "token URL is required",
		},
		{
			name: "No Client ID",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithOAuth(&OAuth{
					TokenURL:     "https://dev.idp.com/oauth/token",
					ClientSecret: "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H",
					Scopes:       "read:certificates,write:certificates",
					Audience:     "https://ejbca.example.com",
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "client ID is required",
		},
		{
			name: "No Client Secret",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithOAuth(&OAuth{
					TokenURL: "https://dev.idp.com/oauth/token",
					ClientID: "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ",
					Scopes:   "read:certificates,write:certificates",
					Audience: "https://ejbca.example.com",
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectError:                true,
			expectedErrorMessagePrefix: "client secret is required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if len(tt.opts) == 0 {
				_, err = NewSigner(context.Background())
			} else {
				_, err = NewSigner(context.Background(), tt.opts...)
			}

			if tt.expectError {
				t.Logf("\ntestcase[%d] and expected error:%+v\n", i, tt.expectedErrorMessagePrefix)
			} else {
				t.Logf("\ntestcase[%d] and no error expected\n", i)
			}

			if tt.expectError {
				assert.Error(t, err)
				if err != nil && !strings.HasPrefix(err.Error(), tt.expectedErrorMessagePrefix) {
					t.Errorf("expected error to start with %q, got %q", tt.expectedErrorMessagePrefix, err.Error())
				}
			}
		})
	}

	for _, tt := range []struct {
		name string
		opts []Option

		expectedSignerConfig *Config
	}{
		{
			name: "Cert Auth",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectedSignerConfig: &Config{
				hostname:     "ejbca.example.org",
				caCertsBytes: append(serverCertPem, caCertPem...),
				certAuth: &CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				},
				certificateAuthorityName: "Root-CA",
				certificateProfileName:   "Server",
				endEntityProfileName:     "Server",
				endEntityName:            "cn",
			},
		},
		{
			name: "OAuth",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithOAuth(&OAuth{
					TokenURL:     "https://dev.idp.com/oauth/token",
					ClientID:     "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ",
					ClientSecret: "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H",
					Scopes:       "read:certificates,write:certificates",
					Audience:     "https://ejbca.example.com",
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
			},

			expectedSignerConfig: &Config{
				hostname:     "ejbca.example.org",
				caCertsBytes: append(serverCertPem, caCertPem...),
				oauth: &OAuth{
					TokenURL:     "https://dev.idp.com/oauth/token",
					ClientID:     "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ",
					ClientSecret: "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H",
					Scopes:       "read:certificates,write:certificates",
					Audience:     "https://ejbca.example.com",
				},
				certificateAuthorityName: "Root-CA",
				certificateProfileName:   "Server",
				endEntityProfileName:     "Server",
				endEntityName:            "cn",
			},
		},
		{
			name: "Override All Fields with Annotations",
			opts: []Option{
				WithHostname("ejbca.example.org"),
				WithCACerts(append(serverCertPem, caCertPem...)),
				WithClientCert(&CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				}),
				WithCertificateAuthority("Root-CA"),
				WithCertificateProfileName("Server"),
				WithEndEntityProfileName("Server"),
				WithEndEntityName("cn"),
				WithAnnotations(map[string]string{
					ejbcaAnnotationPrefix + "certificateAuthorityName": "AnnotationTestCertificateAuthority",
					ejbcaAnnotationPrefix + "certificateProfileName":   "AnnotationTestCertificateProfile",
					ejbcaAnnotationPrefix + "endEntityName":            "AnnotationTestEndEntity",
					ejbcaAnnotationPrefix + "endEntityProfileName":     "AnnotationTestEndEntityProfile",
					"cert-manager.io/certificate-name":                 "test-cert-manager-certificate",
				}),
			},

			expectedSignerConfig: &Config{
				hostname:     "ejbca.example.org",
				caCertsBytes: append(serverCertPem, caCertPem...),
				certAuth: &CertAuth{
					ClientCert: authCertPem,
					ClientKey:  keyPem,
				},
				certificateAuthorityName:   "AnnotationTestCertificateAuthority",
				certificateProfileName:     "AnnotationTestCertificateProfile",
				endEntityProfileName:       "AnnotationTestEndEntityProfile",
				endEntityName:              "AnnotationTestEndEntity",
				certManagerCertificateName: "test-cert-manager-certificate",
				annotations: map[string]string{
					ejbcaAnnotationPrefix + "certificateAuthorityName": "AnnotationTestCertificateAuthority",
					ejbcaAnnotationPrefix + "certificateProfileName":   "AnnotationTestCertificateProfile",
					ejbcaAnnotationPrefix + "endEntityName":            "AnnotationTestEndEntity",
					ejbcaAnnotationPrefix + "endEntityProfileName":     "AnnotationTestEndEntityProfile",
					"cert-manager.io/certificate-name":                 "test-cert-manager-certificate",
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := newInternalSigner(context.Background(), tt.opts...)
			require.NoError(t, err)

			actualConfig := signer.getConfig()
			assert.Equal(t, tt.expectedSignerConfig, actualConfig)
		})
	}
}

func TestGetEndEntityName(t *testing.T) {
	for _, tt := range []struct {
		name string

		defaultEndEntityName string

		subject         string
		dnsNames        []string
		uris            []string
		ips             []string
		certificateName string

		expectedEndEntityName string
	}{
		{
			name:                 "defaultEndEntityName unset use cn",
			defaultEndEntityName: "",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "purplecat.example.com",
		},
		{
			name:                 "defaultEndEntityName unset use dns",
			defaultEndEntityName: "",
			subject:              "",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "reddog.example.com",
		},
		{
			name:                 "defaultEndEntityName unset use uri",
			defaultEndEntityName: "",
			subject:              "",
			dnsNames:             []string{""},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "https://blueelephant.example.com",
		},
		{
			name:                 "defaultEndEntityName unset use ip",
			defaultEndEntityName: "",
			subject:              "",
			dnsNames:             []string{""},
			uris:                 []string{""},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "192.168.1.1",
		},
		{
			name:                 "defaultEndEntityName set use cn",
			defaultEndEntityName: "cn",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "purplecat.example.com",
		},
		{
			name:                 "defaultEndEntityName set use dns",
			defaultEndEntityName: "dns",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "reddog.example.com",
		},
		{
			name:                 "defaultEndEntityName set use uri",
			defaultEndEntityName: "uri",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "https://blueelephant.example.com",
		},
		{
			name:                 "defaultEndEntityName set use ip",
			defaultEndEntityName: "ip",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "192.168.1.1",
		},
		{
			name:                 "defaultEndEntityName set use certificateName",
			defaultEndEntityName: "certificateName",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},
			certificateName:      "aCertificateResourceInTheCluster",

			expectedEndEntityName: "aCertificateResourceInTheCluster",
		},
		{
			name:                 "defaultEndEntityName set use custom",
			defaultEndEntityName: "aNonStandardValue",
			subject:              "CN=purplecat.example.com",
			dnsNames:             []string{"reddog.example.com"},
			uris:                 []string{"https://blueelephant.example.com"},
			ips:                  []string{"192.168.1.1"},

			expectedEndEntityName: "aNonStandardValue",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer := &signer{
				config: &Config{
					endEntityName:              tt.defaultEndEntityName,
					certManagerCertificateName: tt.certificateName,
				},
			}

			csr, err := generateCSR(tt.subject, tt.dnsNames, tt.uris, tt.ips)
			require.NoError(t, err)

			endEntityName := signer.getEndEntityName(context.Background(), csr)
			require.NoError(t, err)
			require.Equal(t, tt.expectedEndEntityName, endEntityName)
		})
	}
}

func TestSign(t *testing.T) {
	caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	issuingCert, issuingKey := issueTestCertificate(t, "Sub-CA", caCert, rootKey)
	issuingCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingCert.Raw})

	leafCert, _ := issueTestCertificate(t, "LeafCert", issuingCert, issuingKey)
	leafCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	expectedLeafAndChain := append([]*x509.Certificate{leafCert}, issuingCert)

	for _, tt := range []struct {
		name string

		certificateResponseFormat string
		ejbcaStatusCode           int

		// Request
		caName                 string
		endEntityProfileName   string
		certificateProfileName string
		endEntityName          string
		accountBindingID       string

		// Expected
		errorExpected              bool
		expectedErrorMessagePrefix string
	}{
		{
			name: "Success PEM",

			certificateResponseFormat: "PEM",
			ejbcaStatusCode:           http.StatusOK,

			caName:                 "Fake-Sub-CA",
			endEntityProfileName:   "fakeSubEAP",
			certificateProfileName: "fakeSubCACP",
			endEntityName:          "",
			accountBindingID:       "",

			errorExpected: false,
		},
		{
			name: "Success DER",

			certificateResponseFormat: "DER",
			ejbcaStatusCode:           http.StatusOK,

			caName:                 "Fake-Sub-CA",
			endEntityProfileName:   "fakeSubEAP",
			certificateProfileName: "fakeSubCACP",
			endEntityName:          "",
			accountBindingID:       "",

			errorExpected: false,
		},
		{
			name: "EJBCA API error",

			certificateResponseFormat: "DER",
			ejbcaStatusCode:           http.StatusInternalServerError,

			caName:                 "Fake-Sub-CA",
			endEntityProfileName:   "fakeSubEAP",
			certificateProfileName: "fakeSubCACP",
			endEntityName:          "",
			accountBindingID:       "",

			errorExpected:              true,
			expectedErrorMessagePrefix: "failed to enroll CSR - 500 Internal Server Error - EJBCA API returned error",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cn := "ejbca.example.org"

			testServer := httptest.NewTLSServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					enrollRestRequest := ejbca.EnrollCertificateRestRequest{}
					err := json.NewDecoder(r.Body).Decode(&enrollRestRequest)
					require.NoError(t, err)

					// Perform assertions before fake enrollment
					require.Equal(t, tt.caName, enrollRestRequest.GetCertificateAuthorityName())
					require.Equal(t, tt.endEntityProfileName, enrollRestRequest.GetEndEntityProfileName())
					require.Equal(t, tt.certificateProfileName, enrollRestRequest.GetCertificateProfileName())
					require.Equal(t, tt.accountBindingID, enrollRestRequest.GetAccountBindingId())
					require.Equal(t, cn, enrollRestRequest.GetUsername())

					response := certificateRestResponseFromExpectedCerts(t, expectedLeafAndChain, []*x509.Certificate{caCert}, tt.certificateResponseFormat)

					w.Header().Add("Content-Type", "application/json")
					w.WriteHeader(tt.ejbcaStatusCode)
					err = json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
			defer testServer.Close()

			fakeClientConfig := fakeClientConfig{
				testServer: testServer,
			}

			signer, err := NewSigner(context.Background(),
				WithHostname(testServer.URL),
				WithOAuth(&OAuth{
					TokenURL:     "https://dev.idp.com/oauth/token",
					ClientID:     "fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ",
					ClientSecret: "1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H",
					Scopes:       "read:certificates,write:certificates",
					Audience:     "https://ejbca.example.com",
				}),
				WithCertificateAuthority(tt.caName),
				WithCertificateProfileName(tt.certificateProfileName),
				WithEndEntityProfileName(tt.endEntityProfileName),
				WithEndEntityName("cn"),
				withAuthenticator(fakeClientConfig.newFakeAuthenticator),
			)
			require.NoError(t, err)

			csrBytes, err := generateCSR("CN=ejbca.example.org", nil, nil, nil)
			require.NoError(t, err)
			csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes.Raw})

			leafAndCA, root, err := signer.Sign(context.Background(), csrPem)
			if tt.errorExpected {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrorMessagePrefix)
				return
			}

			require.NoError(t, err)
			require.Equal(t, leafAndCA, append(leafCertPem, issuingCertPem...))
			require.Equal(t, root, caCertPem)
		})
	}
}

func certificateRestResponseFromExpectedCerts(t *testing.T, leafCertAndChain []*x509.Certificate, rootCAs []*x509.Certificate, format string) *ejbca.CertificateRestResponse {
	require.NotEqual(t, 0, len(leafCertAndChain))
	var issuingCa string
	if format == "PEM" {
		issuingCa = string(pem.EncodeToMemory(&pem.Block{Bytes: leafCertAndChain[0].Raw, Type: "CERTIFICATE"}))
	} else {
		issuingCa = base64.StdEncoding.EncodeToString(leafCertAndChain[0].Raw)
	}

	var caChain []string
	if format == "PEM" {
		for _, cert := range leafCertAndChain[1:] {
			caChain = append(caChain, string(pem.EncodeToMemory(&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"})))
		}
		for _, cert := range rootCAs {
			caChain = append(caChain, string(pem.EncodeToMemory(&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"})))
		}
	} else {
		for _, cert := range leafCertAndChain[1:] {
			caChain = append(caChain, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		for _, cert := range rootCAs {
			caChain = append(caChain, base64.StdEncoding.EncodeToString(cert.Raw))
		}
	}

	response := &ejbca.CertificateRestResponse{}
	response.SetResponseFormat(format)
	response.SetCertificate(issuingCa)
	response.SetCertificateChain(caChain)
	return response
}

func generateCSR(subject string, dnsNames []string, uris []string, ipAddresses []string) (*x509.CertificateRequest, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	var name pkix.Name

	if subject != "" {
		// Split the subject into its individual parts
		parts := strings.Split(subject, ",")

		for _, part := range parts {
			// Split the part into key and value
			keyValue := strings.SplitN(part, "=", 2)

			if len(keyValue) != 2 {
				return nil, errors.New("invalid subject")
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
				name.CommonName = value
			default:
				// Ignore any unknown keys
			}
		}
	}

	template := x509.CertificateRequest{
		Subject:            name,
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
			return nil, err
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
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddrs = append(ipAddrs, ip)
	}
	template.IPAddresses = ipAddrs

	// Generate the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, err
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return parsedCSR, nil
}

func issueTestCertificate(t *testing.T, cn string, parent *x509.Certificate, signingKey any) (*x509.Certificate, *ecdsa.PrivateKey) {
	var err error
	var key *ecdsa.PrivateKey
	now := time.Now()

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey := &key.PublicKey
	signerPrivateKey := key
	if signingKey != nil {
		signerPrivateKey = signingKey.(*ecdsa.PrivateKey)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1337))
	certTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		SerialNumber:          serial,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
	}

	if parent == nil {
		parent = certTemplate
	}

	certData, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, publicKey, signerPrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certData)
	require.NoError(t, err)

	return cert, key
}
