<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# EJBCA End Entity Name Configuration

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The `endEntityName` field in the Issuer and ClusterIssuer resource spec allows you to configure how the End Entity Name is selected when issuing certificates through EJBCA. This field offers flexibility by allowing you to select different components from the Certificate Signing Request (CSR) or other contextual data as the End Entity Name.

## EJBCA End Entity Name Configuration
The endEntityName field in the Issuer and ClusterIssuer resource spec allows you to configure how the End Entity Name is selected when issuing certificates through EJBCA. This field offers flexibility by allowing you to select different components from the Certificate Signing Request (CSR) or other contextual data as the End Entity Name.

### Configurable Options
Here are the different options you can set for endEntityName:

* **`cn`:** Uses the Common Name from the CSR's Distinguished Name.
* **`dns`:** Uses the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **`uri`:** Uses the first URI from the CSR's Subject Alternative Names (SANs).
* **`ip`:** Uses the first IP Address from the CSR's Subject Alternative Names (SANs).
* **`certificateName`:** Uses the name of the cert-manager.io/Certificate object.
* **Custom Value:** Any other string will be directly used as the End Entity Name.

### Default Behavior
If the endEntityName field is not explicitly set, the EJBCA Issuer will attempt to determine the End Entity Name using the following default behavior:

* **First, it will try to use the Common Name:** It looks at the Common Name from the CSR's Distinguished Name.
* **If the Common Name is not available, it will use the first DNS Name:** It looks at the first DNS Name from the CSR's Subject Alternative Names (SANs).
* **If the DNS Name is not available, it will use the first URI:** It looks at the first URI from the CSR's Subject Alternative Names (SANs).
* **If the URI is not available, it will use the first IP Address:** It looks at the first IP Address from the CSR's Subject Alternative Names (SANs).
* **If none of the above are available, it will use the name of the cert-manager.io/Certificate object:** It defaults to the name of the certificate object. 

If the Issuer is unable to determine a valid End Entity Name through these steps, an error will be logged and no End Entity Name will be set.
