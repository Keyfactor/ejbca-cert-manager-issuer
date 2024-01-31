# Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The EJBCA external issuer for cert-manager allows users to enroll certificates from Keyfactor EJBCA using cert-manager.

Cert-manager is a native Kubernetes certificate management controller that allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.

## Get started

* To install the tool, see [Installation](docs/install.md).
* To configure and use the tool, see: 
  * [Usage](docs/config_usage.md)
  * [Customization](docs/annotations.md)
  * [End Entity Name Selection](docs/endentitynamecustomization.md)
* To test the tool, see [Testing the Source](docs/testing.md).

## Community supported
We welcome contributions.

This tool is open source and community-supported, meaning that **no SLA** is applicable.

* To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab.
* If you want to contribute actual bug fixes or proposed enhancements, see the **[contributing guidelines](CONTRIBUTING.md)** and use the **[Pull requests](../../pulls)** tab.

## License
This tool is licensed under this **[LICENSE](LICENSE)**. 
