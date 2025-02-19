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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type CertificateClient interface {
	EnrollPkcs10Certificate(ctx context.Context) ejbca.ApiEnrollPkcs10CertificateRequest
	Status2(ctx context.Context) ejbca.ApiStatus2Request
}

func (s *signer) newAuthenticator(ctx context.Context) (ejbca.Authenticator, error) {
	var err error
	logger := log.FromContext(ctx).WithName("signer.newEjbcaClient")

	var caChain []*x509.Certificate
	if len(s.config.caCertsBytes) > 0 {
		logger.Info("CA chain present - Parsing CA chain from configuration")

		blocks := decodePEMBytes(s.config.caCertsBytes)
		if len(blocks) == 0 {
			return nil, fmt.Errorf("didn't find pem certificate in ca cert configmap")
		}

		for _, block := range blocks {
			// Parse the PEM block into an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}

			caChain = append(caChain, cert)
		}

		logger.Info("Parsed CA chain", "length", len(caChain))
	}

	var authenticator ejbca.Authenticator
	switch {
	case s.config.oauth != nil:
		logger.Info("Creating OAuth authenticator")
		scopes := strings.Split(s.config.oauth.Scopes, " ")

		authenticator, err = ejbca.NewOAuthAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithTokenUrl(s.config.oauth.TokenURL).
			WithClientId(s.config.oauth.ClientID).
			WithClientSecret(s.config.oauth.ClientSecret).
			WithAudience(s.config.oauth.Audience).
			WithScopes(scopes).
			Build()
		if err != nil {
			logger.Error(err, "Failed to build OAuth authenticator")
			return nil, fmt.Errorf("failed to build OAuth authenticator: %w", err)
		}

		logger.Info("Created OAuth authenticator")
	case s.config.certAuth != nil:
		logger.Info("Creating mTLS authenticator")

		var tlsCert tls.Certificate
		tlsCert, err := tls.X509KeyPair(s.config.certAuth.ClientCert, s.config.certAuth.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		authenticator, err = ejbca.NewMTLSAuthenticatorBuilder().
			WithCaCertificates(caChain).
			WithClientCertificate(&tlsCert).
			Build()
		if err != nil {
			logger.Error(err, "Failed to build mTLS authenticator")
			return nil, fmt.Errorf("failed to build MTLS authenticator: %w", err)
		}

		logger.Info("Created mTLS authenticator")
	default:
		err := errors.New("no authentication method specified")
		logger.Error(err, "No authentication method specified")
		return nil, err
	}

	return authenticator, nil
}

// newEjbcaClient generates a new EJBCA client based on the provided configuration.
func (s *signer) newEjbcaClient(ctx context.Context) (CertificateClient, error) {
	if s.config == nil || s.hooks.newAuthenticator == nil {
		return nil, errors.New("newEjbcaClient was called incorrectly - this is a bug - please report it to the EJBCA authors")
	}

	logger := log.FromContext(ctx).WithName("signer.newEjbcaClient")

	authenticator, err := s.hooks.newAuthenticator(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create new EJBCA API authenticator: %w", err)
	}
	if authenticator == nil {
		return nil, errors.New("authenticator is nil - this is a bug - please report it to the EJBCA authors")
	}

	configuration := ejbca.NewConfiguration()
	configuration.Host = s.config.hostname

	configuration.SetAuthenticator(authenticator)

	ejbcaClient, err := ejbca.NewAPIClient(configuration)
	if err != nil {
		return nil, err
	}

	logger.Info("Created EJBCA REST API client")
	return ejbcaClient.V1CertificateApi, nil
}

// parseEjbcaError parses an error returned by the EJBCA API and returns a gRPC status error.
func (s *signer) parseEjbcaError(ctx context.Context, detail string, err error) error {
	if err == nil {
		return nil
	}
	logger := log.FromContext(ctx).WithName("signer.parseEjbcaError")
	errString := fmt.Sprintf("%s - %s", detail, err.Error())

	ejbcaError := &ejbca.GenericOpenAPIError{}
	if errors.As(err, &ejbcaError) {
		errString += fmt.Sprintf(" - EJBCA API returned error %s", ejbcaError.Body())
	}

	logger.Error(err, "EJBCA returned an error")

	return fmt.Errorf("%s", errString)
}
