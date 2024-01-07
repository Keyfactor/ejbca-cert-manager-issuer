<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The EJBCA external issuer for cert-manager allows users to enroll certificates from Keyfactor EJBCA using cert-manager.

Cert-manager is a native Kubernetes certificate management controller which allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.

## EJBCA API Usage
The EJBCA Issuer for cert-manager requires the following API endpoints:
* `/ejbca-rest-api/v1/certificate/pkcs10enroll`
* `/ejbca/ejbca-rest-api/v1/certificate/status`

## Docs

* [Installation](install.md)
* Usage
    * [Usage](config_usage.md)
    * [Customization](annotations.md)
    * [End Entity Name Selection](endentitynamecustomization.md)
* [Testing the Source](testing.md)
* [License](../LICENSE)
