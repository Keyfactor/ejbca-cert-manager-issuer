# Testing the Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The test cases for the controller require a set of environment variables to be set. These variables are used to
authenticate to an EJBCA API server and to enroll a certificate. The test cases are run using the `make test` command.

The following environment variables must be exported before testing the controller:
* `EJBCA_HOSTNAME` - The hostname of the EJBCA instance to use for testing.
* `EJBCA_CLIENT_CERT_PATH` - A relative or absolute path to a client certificate that is authorized to enroll certificates in EJBCA. The file must include the certificate and associated private key in unencrypted PKCS#8 format.
* `EJBCA_CA_NAME` - The name of the CA in EJBCA to use for testing.
* `EJBCA_CERTIFICATE_PROFILE_NAME` - The name of the certificate profile in EJBCA to use for testing.
* `EJBCA_END_ENTITY_PROFILE_NAME` - The name of the end entity profile in EJBCA to use for testing.
* `EJBCA_CSR_SUBJECT` - The subject of the certificate signing request (CSR) to use for testing.
* `EJBCA_CA_CERT_PATH` - A relative or absolute path to the CA certificate that the EJBCA instance uses for TLS. The file must include the certificate in PEM format.

To run the test cases, run:
```shell
make test
```
