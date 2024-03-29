
# ejbca-cert-manager-issuer

cert-manager external issuer for EJBCA

#### Integration status: Pilot - Ready for use in test environments. Not for use in production.

## About the Keyfactor API Client

This API client allows for programmatic management of Keyfactor resources.

## Support for ejbca-cert-manager-issuer

ejbca-cert-manager-issuer is open source and supported on best effort level for this tool/library/client.  This means customers can report Bugs, Feature Requests, Documentation amendment or questions as well as requests for customer information required for setup that needs Keyfactor access to obtain. Such requests do not follow normal SLA commitments for response or resolution. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com/

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

---


---



<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The EJBCA external issuer for cert-manager allows users to enroll certificates from Keyfactor EJBCA using cert-manager.

Cert-manager is a native Kubernetes certificate management controller which allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.

## Community supported
We welcome contributions.

The cert-manager external issuer for Keyfactor EJBCA is open source and community supported, meaning that there is **no SLA** applicable for these tools.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, see the [contribution guidelines](https://github.com/Keyfactor/ejbca-k8s-csr-signer/blob/main/CONTRIBUTING.md) and use the **[Pull requests](../../pulls)** tab.

## EJBCA API Usage
The EJBCA Issuer for cert-manager requires the following API endpoints:
* `/ejbca-rest-api/v1/certificate/pkcs10enroll`
* `/ejbca/ejbca-rest-api/v1/certificate/status`

## Docs

* [Installation](docs/install.md)
* Usage
  * [Usage](docs/config_usage.md)
  * [Customization](docs/annotations.md)
  * [End Entity Name Selection](docs/endentitynamecustomization.md)
* [Testing the Source](docs/testing.md)
* [License](LICENSE)

