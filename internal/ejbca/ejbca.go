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

package ejbca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	ejbcaAnnotationPrefix = "ejbca-issuer.keyfactor.com/"
)

type HealthCheckerBuilder func(ctx context.Context, opts ...Option) (HealthChecker, error)
type SignerBuilder func(ctx context.Context, opts ...Option) (Signer, error)
type newEjbcaAuthenticatorFunc func(context.Context) (ejbca.Authenticator, error)

type HealthChecker interface {
	Check() error
}

type Signer interface {
	Sign(context.Context, []byte) ([]byte, []byte, error)
}

type internalSigner interface {
	Signer
	getConfig() *Config
}

type signer struct {
	client CertificateClient
	config *Config

	hooks struct {
		newAuthenticator newEjbcaAuthenticatorFunc
	}
}

type CertAuth struct {
	ClientCert []byte
	ClientKey  []byte
}

type OAuth struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       string
	Audience     string
}

type Config struct {
	hostname                   string
	caCertsBytes               []byte
	certAuth                   *CertAuth
	oauth                      *OAuth
	certificateProfileName     string
	endEntityProfileName       string
	certificateAuthorityName   string
	endEntityName              string
	certManagerCertificateName string
	annotations                map[string]string
}

func (c *Config) validate(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("config.validate")
	// Override defaults from annotations
	if value, exists := c.annotations[ejbcaAnnotationPrefix+"certificateAuthorityName"]; exists {
		logger.Info("Found annotation override for certificateAuthorityName", "was", c.certificateAuthorityName, "now", value)
		c.certificateAuthorityName = value
	}
	if value, exists := c.annotations[ejbcaAnnotationPrefix+"certificateProfileName"]; exists {
		logger.Info("Found annotation override for certificateProfileName", "was", c.certificateProfileName, "now", value)
		c.certificateProfileName = value
	}
	if value, exists := c.annotations[ejbcaAnnotationPrefix+"endEntityName"]; exists {
		logger.Info("Found annotation override for endEntityName", "was", c.endEntityName, "now", value)
		c.endEntityName = value
	}
	if value, exists := c.annotations[ejbcaAnnotationPrefix+"endEntityProfileName"]; exists {
		logger.Info("Found annotation override for endEntityProfileName", "was", c.endEntityProfileName, "now", value)
		c.endEntityProfileName = value
	}
	if value, exists := c.annotations["cert-manager.io/certificate-name"]; exists {
		c.certManagerCertificateName = value
		logger.Info("CertificateRequest annotations contained a cert-manager.io/certificate-name annotation", "value", value)
	}

	switch {
	case c.hostname == "":
		err := errors.New("hostname is required")
		logger.Error(err, "hostname is required")
		return err
	case c.certificateProfileName == "":
		err := errors.New("certificateProfileName is required")
		logger.Error(err, "certificateProfileName is required")
		return err
	case c.endEntityProfileName == "":
		err := errors.New("endEntityProfileName is required")
		logger.Error(err, "endEntityProfileName is required")
		return err
	case c.certificateAuthorityName == "":
		err := errors.New("certificateAuthorityName is required")
		logger.Error(err, "certificateAuthorityName is required")
		return err
	}

	if c.certAuth == nil && c.oauth == nil {
		return errors.New("the issuer/clusterissuer must be configured with either certAuth or oauth")
	}

	var oauthOrMtls string
	if c.certAuth != nil {
		if len(c.certAuth.ClientCert) == 0 {
			err := errors.New("client certificate is required")
			logger.Error(err, "client certificate is required")
			return err
		}
		if len(c.certAuth.ClientKey) == 0 {
			err := errors.New("client key is required")
			logger.Error(err, "client key is required")
			return err
		}
		oauthOrMtls = "mtls"
	} else {
		if c.oauth.TokenURL == "" {
			err := errors.New("token URL is required")
			logger.Error(err, "token URL is required")
			return err
		}
		if c.oauth.ClientID == "" {
			err := errors.New("client ID is required")
			logger.Error(err, "client ID is required")
			return err
		}
		if c.oauth.ClientSecret == "" {
			err := errors.New("client secret is required")
			logger.Error(err, "client secret is required")
			return err
		}
		oauthOrMtls = "oauth"
	}

	logger.Info("Configuration validated", "authentication", oauthOrMtls, "hostname", c.hostname, "certificateProfileName", c.certificateProfileName, "endEntityProfileName", c.endEntityProfileName, "certificateAuthorityName", c.certificateAuthorityName, "endEntityName", c.endEntityName, "certManagerCertificateName", c.certManagerCertificateName)
	return nil
}

type Option func(*signer)

func newInternalSigner(ctx context.Context, opts ...Option) (internalSigner, error) {
	s := &signer{
		config: &Config{},
	}
	if s.hooks.newAuthenticator == nil {
		// Default newAuthenticator hook is the production one. Can be overridden by tests.
		s.hooks.newAuthenticator = s.newAuthenticator
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.config.validate(ctx); err != nil {
		return nil, err
	}
	client, err := s.newEjbcaClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create new EJBCA API client: %w", err)
	}

	s.client = client
	return s, nil
}

func NewSigner(ctx context.Context, opts ...Option) (Signer, error) {
	return newInternalSigner(ctx, opts...)
}

func NewHealthChecker(ctx context.Context, opts ...Option) (HealthChecker, error) {
	s := &signer{
		config: &Config{},
	}
	if s.hooks.newAuthenticator == nil {
		// Default newAuthenticator hook is the production one. Can be overridden by tests.
		s.hooks.newAuthenticator = s.newAuthenticator
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.config.validate(ctx); err != nil {
		return nil, err
	}
	client, err := s.newEjbcaClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create new EJBCA API client: %w", err)
	}

	s.client = client
	return s, nil
}

func WithHostname(hostname string) Option {
	return func(s *signer) {
		s.config.hostname = hostname
	}
}

func WithCACerts(caBytes []byte) Option {
	return func(s *signer) {
		s.config.caCertsBytes = caBytes
	}
}

func WithClientCert(certAuth *CertAuth) Option {
	return func(s *signer) {
		s.config.certAuth = certAuth
	}
}

func WithOAuth(oAuth *OAuth) Option {
	return func(s *signer) {
		s.config.oauth = oAuth
	}
}

func WithCertificateProfileName(cpn string) Option {
	return func(s *signer) {
		s.config.certificateProfileName = cpn
	}
}

func WithEndEntityProfileName(eepn string) Option {
	return func(s *signer) {
		s.config.endEntityProfileName = eepn
	}
}

func WithEndEntityName(ee string) Option {
	return func(s *signer) {
		s.config.endEntityName = ee
	}
}

func WithCertificateAuthority(ca string) Option {
	return func(s *signer) {
		s.config.certificateAuthorityName = ca
	}
}

func WithAnnotations(annotations map[string]string) Option {
	return func(s *signer) {
		s.config.annotations = annotations
	}
}

func withAuthenticator(newAuthenticator newEjbcaAuthenticatorFunc) Option {
	return func(s *signer) {
		s.hooks.newAuthenticator = newAuthenticator
	}
}

// Check checks the status of the EJBCA API
func (s *signer) Check() error {
	_, r, err := s.client.Status2(context.Background()).Execute()
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return nil
}

// Sign signs a CSR with EJBCA
func (s *signer) Sign(ctx context.Context, csrBytes []byte) ([]byte, []byte, error) {
	logger := log.FromContext(ctx).WithName("signer.Sign")

	csr, err := parseCSR(csrBytes)
	if err != nil {
		return nil, nil, err
	}

	logger.Info("Parsed CSR from CertificateRequest", "commonName", csr.Subject.CommonName, "dnsNames", csr.DNSNames, "ipAddresses", csr.IPAddresses, "uriSans", csr.URIs)

	ejbcaEeName := s.getEndEntityName(ctx, csr)
	if ejbcaEeName == "" {
		return nil, nil, errors.New("failed to determine the EJBCA end entity name")
	}

	logger.Info(fmt.Sprintf("Using or Creating EJBCA End Entity called %q", ejbcaEeName))

	password, err := generateRandomString(20)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}

	// Configure EJBCA PKCS#10 request
	enroll := ejbca.NewEnrollCertificateRestRequest()
	enroll.SetCertificateRequest(string(csrBytes))
	enroll.SetCertificateProfileName(s.config.certificateProfileName)
	enroll.SetEndEntityProfileName(s.config.endEntityProfileName)
	enroll.SetCertificateAuthorityName(s.config.certificateAuthorityName)
	enroll.SetUsername(ejbcaEeName)
	enroll.SetPassword(password)
	enroll.SetIncludeChain(true)

	logger.Info("Enrolling certificate with EJBCA", "commonName", csr.Subject.CommonName, "dnsNames", csr.DNSNames, "ipAddresses", csr.IPAddresses, "uriSans", csr.URIs)

	enrollResponse, r, err := s.client.EnrollPkcs10Certificate(ctx).
		EnrollCertificateRestRequest(*enroll).
		Execute()
	if err != nil {
		return nil, nil, s.parseEjbcaError(ctx, "failed to enroll CSR", err)
	}
	defer r.Body.Close()

	var certBytes []byte
	var caBytes []byte
	switch {
	case enrollResponse.GetResponseFormat() == "PEM":
		logger.Info("EJBCA returned certificate in PEM format - serializing")

		block, _ := pem.Decode([]byte(enrollResponse.GetCertificate()))
		if block == nil {
			return nil, nil, errors.New("failed to parse certificate PEM")
		}
		certBytes = block.Bytes

		for _, ca := range enrollResponse.CertificateChain {
			block, _ := pem.Decode([]byte(ca))
			if block == nil {
				return nil, nil, errors.New("failed to parse CA certificate PEM")
			}
			caBytes = append(caBytes, block.Bytes...)
		}
	case enrollResponse.GetResponseFormat() == "DER":
		logger.Info("EJBCA returned certificate in DER format - serializing")

		bytes := []byte(enrollResponse.GetCertificate())
		bytes, err := base64.StdEncoding.DecodeString(string(bytes))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to base64 decode DER certificate: %w", err)
		}
		certBytes = append(certBytes, bytes...)

		for _, ca := range enrollResponse.CertificateChain {
			bytes := []byte(ca)
			bytes, err := base64.StdEncoding.DecodeString(string(bytes))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to base64 decode DER CA certificate: %w", err)
			}
			caBytes = append(caBytes, bytes...)
		}
	default:
		return nil, nil, errors.New("ejbca returned unsupported certificate format: " + enrollResponse.GetResponseFormat())
	}

	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate issued by EJBCA: %w", err)
	}

	caChain, err := x509.ParseCertificates(caBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA chain returned by EJBCA: %w", err)
	}

	if len(caChain) == 0 {
		return nil, nil, errors.New("EJBCA did not return a CA chain")
	}

	bundlePEM, err := cmpki.ParseSingleCertificateChain(append([]*x509.Certificate{leaf}, caChain...))
	if err != nil {
		return nil, nil, err
	}
	logger.Info("Successfully enrolled certificate with EJBCA")
	return bundlePEM.ChainPEM, bundlePEM.CAPEM, nil
}

func (s *signer) getConfig() *Config {
	return s.config
}

// getEndEntityName determines the end entity name to use for the EJBCA request
func (s *signer) getEndEntityName(ctx context.Context, csr *x509.CertificateRequest) string {
	logger := log.FromContext(ctx).WithName("signer.getEndEntityName")
	eeName := ""
	// 1. If the endEntityName option is set, determine the end entity name based on the option
	// 2. If the endEntityName option is not set, determine the end entity name based on the CSR

	// cn: Use the CommonName from the CertificateRequest's DN
	if s.config.endEntityName == "cn" || s.config.endEntityName == "" {
		if csr.Subject.CommonName != "" {
			eeName = csr.Subject.CommonName
			logger.Info(fmt.Sprintf("Using CommonName from the CertificateRequest's DN as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	// dns: Use the first DNSName from the CertificateRequest's DNSNames SANs
	if s.config.endEntityName == "dns" || s.config.endEntityName == "" {
		if len(csr.DNSNames) > 0 && csr.DNSNames[0] != "" {
			eeName = csr.DNSNames[0]
			logger.Info(fmt.Sprintf("Using the first DNSName from the CertificateRequest's DNSNames SANs as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	// uri: Use the first URI from the CertificateRequest's URI Sans
	if s.config.endEntityName == "uri" || s.config.endEntityName == "" {
		if len(csr.URIs) > 0 {
			eeName = csr.URIs[0].String()
			logger.Info(fmt.Sprintf("Using the first URI from the CertificateRequest's URI Sans as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	// ip: Use the first IPAddress from the CertificateRequest's IPAddresses SANs
	if s.config.endEntityName == "ip" || s.config.endEntityName == "" {
		if len(csr.IPAddresses) > 0 {
			eeName = csr.IPAddresses[0].String()
			logger.Info(fmt.Sprintf("Using the first IPAddress from the CertificateRequest's IPAddresses SANs as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	// certificateName: Use the value of the CertificateRequest's certificateName annotation
	if s.config.endEntityName == "certificateName" || s.config.endEntityName == "" {
		eeName = s.config.certManagerCertificateName
		logger.Info(fmt.Sprintf("Using the name of the cert-manager.io/Certificate object as the EJBCA end entity name: %q", eeName))
		return eeName
	}

	// End of defaults; if the endEntityName option is set to anything but cn, dns, or uri, use the option as the end entity name
	if s.config.endEntityName != "" && s.config.endEntityName != "cn" && s.config.endEntityName != "dns" && s.config.endEntityName != "uri" && s.config.endEntityName != "certificateName" {
		eeName = s.config.endEntityName
		logger.Info(fmt.Sprintf("Using the endEntityName option as the EJBCA end entity name: %q", eeName))
		return eeName
	}

	// If we get here, we were unable to determine the end entity name
	logger.Error(fmt.Errorf("unsuccessfully determined end entity name"), fmt.Sprintf("the endEntityName option is set to %q, but no valid end entity name could be determined from the CertificateRequest", s.config.endEntityName))

	return eeName
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// decodePEMBytes takes a byte array containing PEM encoded data and returns a slice of PEM blocks and a private key PEM block
func decodePEMBytes(buf []byte) []*pem.Block {
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}
		certificates = append(certificates, block)
	}
	return certificates
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) (string, error) {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[num.Int64()]
	}
	return string(b), nil
}
