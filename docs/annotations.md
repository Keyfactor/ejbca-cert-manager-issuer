<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

## Annotation Overrides for Issuer and ClusterIssuer Resources

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Keyfactor EJBCA external issuer for cert-manager allows you to override default settings in the Issuer and ClusterIssuer resources through the use of annotations. This gives you more granular control on a per-Certificate/CertificateRequest basis.

### Supported Annotations
Here are the supported annotations that can override the default values:

- **`ejbca-issuer.keyfactor.com/endEntityName`**: Overrides the `endEntityName` field from the resource spec. Allowed values include `"cn"`, `"dns"`, `"uri"`, `"ip"`, and `"certificateName"`, or any custom string.

    ```yaml
    ejbca-issuer.keyfactor.com/endEntityName: "dns"
    ```

- **`ejbca-issuer.keyfactor.com/certificateAuthorityName`**: Specifies the Certificate Authority (CA) name to use, overriding the default CA specified in the resource spec.

    ```yaml
    ejbca-issuer.keyfactor.com/certificateAuthorityName: "ManagementCA"
    ```

- **`ejbca-issuer.keyfactor.com/certificateProfileName`**: Specifies the Certificate Profile name to use, overriding the default profile specified in the resource spec.

    ```yaml
    ejbca-issuer.keyfactor.com/certificateProfileName: "tlsServerAuth"
    ```

- **`ejbca-issuer.keyfactor.com/endEntityProfileName`**: Specifies the End Entity Profile name to use, overriding the default profile specified in the resource spec.

    ```yaml
    ejbca-issuer.keyfactor.com/endEntityProfileName: "eep"
    ```

### How to Apply Annotations

To apply these annotations, include them in the metadata section of your CertificateRequest resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  annotations:
    ejbca-issuer.keyfactor.com/endEntityName: "dns"
    ejbca-issuer.keyfactor.com/certificateAuthorityName: "ManagementCA"
    # ... other annotations
spec:
# ... rest of the spec
```
