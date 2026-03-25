<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Installing the Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The cert-manager external issuer for Keyfactor EJBCA can be used to issue certificates from Keyfactor EJBCA using cert-manager.

### Authentication
The ejbca-cert-manager-issuer can authenticate to EJBCA using mTLS (client certificate & key) or the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).

The credential must be configured using a Kubernetes Secret. By default, the secret is expected to exist in the same namespace as the issuer controller (`ejbca-issuer-system` by default). This can be overridden by deploying the chart using the `--set "secretConfig.useClusterRoleForSecretAccess=true"` flag.

If the EJBCA API is configured to use a self-signed certificate or with a certificate that isn't publically trusted, the CA certificate must be provided as a Kubernetes secret or as a configmap.

```shell
kubectl -n ejbca-issuer-system create secret generic ejbca-ca-secret --from-file=ca.crt
```

```shell
kubectl -n ejbca-issuer-system create configmap ejbca-ca-configmap --from-file=ca.crt
```

#### mTLS

Create a K8s TLS secret containing the client certificate and key to authenticate with EJBCA:
```shell
kubectl -n ejbca-issuer-system create secret tls ejbca-secret --cert=client.crt --key=client.key
```

#### OAuth

Create an Opaque secret containing the client ID and client secret to authenticate with EJBCA:

```shell
token_url="<token url>"
client_id="<client id>"
client_secret="<client secret>"
audience="<audience>"
scopes="<scopes>"

kubectl -n ejbca-issuer-system create secret generic ejbca-secret \
    "--from-literal=tokenUrl=$token_url" \
    "--from-literal=clientId=$client_id" \
    "--from-literal=clientSecret=$client_secret" \
    "--from-literal=audience=$audience" \
    "--from-literal=scopes=$scopes"
```

> Audience and Scopes are optional

### Creating Issuer and ClusterIssuer resources
The `ejbca-issuer.keyfactor.com/v1alpha1` API version supports Issuer and ClusterIssuer resources.
The ejbca controller will automatically detect and process resources of both types.

The Issuer resource is namespaced, while the ClusterIssuer resource is cluster-scoped.
For example, ClusterIssuer resources can be used to issue certificates for resources in multiple namespaces, whereas Issuer resources can only be used to issue certificates for resources in the same namespace.

The `spec` field of both the Issuer and ClusterIssuer resources use the following fields:
* `hostname` - The hostname of the EJBCA instance
* `ejbcaSecretName` - The name of the Kubernetes secret containing the client certificate and key or OAuth 2.0 credentials.
* `certificateAuthorityName` - The name of the EJBCA certificate authority to use. For example, `ManagementCA`
* `certificateProfileName` - The name of the EJBCA certificate profile to use. For example, `ENDUSER`
* `endEntityProfileName` - The name of the EJBCA end entity profile to use. For example, `istio`
* `caBundleSecretName` - The name of the Kubernetes secret containing the CA certificate. This field is optional and only required if the EJBCA API is configured to use a self-signed certificate or with a certificate signed by an untrusted root.
* `caBundleConfigMapName` - The name of the Kubernetes config map containing the CA certificate. This field is optional and only required if the EJBCA API is configured to use a self-signed certificate or with a certificate signed by an untrusted root. The caBundleConfigMapName field takes precedence over caBundleSecretName if both are specified.
* `endEntityName` - The name of the end entity to use. This field is optional. More information on how the field is used can be found in the [EJBCA End Entity Name Configuration](#ejbca-end-entity-name-configuration) section.

###### If a different combination of hostname/certificate authority/certificate profile/end entity profile is required, a new Issuer or ClusterIssuer resource must be created. Each resource instantiation represents a single configuration.

The following is an example of an Issuer resource:
```yaml
apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: Issuer
metadata:
  labels:
    app.kubernetes.io/name: issuer
    app.kubernetes.io/instance: issuer-sample
    app.kubernetes.io/part-of: ejbca-issuer
    app.kubernetes.io/created-by: ejbca-issuer
  name: issuer-sample
spec:
  hostname: ""
  certificateAuthorityName: ""
  certificateProfileName: ""
  endEntityProfileName: ""
  caBundleConfigMapName: ""
  endEntityName: ""
```

The following is an example of a ClusterIssuer resource:
```yaml
apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata:
  labels:
    app.kubernetes.io/name: clusterissuer
    app.kubernetes.io/instance: clusterissuer-sample
    app.kubernetes.io/part-of: ejbca-issuer
    app.kubernetes.io/created-by: ejbca-issuer
  name: clusterissuer-sample
spec:
  hostname: ""
  ejbcaBundleSecretName: ""
  certificateAuthorityName: ""
  certificateProfileName: ""
  endEntityProfileName: ""
  endEntityName: ""
```

To create new resources from the above examples, replace the empty strings with the appropriate values and apply the resources to the cluster:
```shell
kubectl -n ejbca-issuer-system apply -f issuer.yaml
kubectl -n ejbca-issuer-system apply -f clusterissuer.yaml
```

To verify that Issuer and ClusterIssuer resources were created successfully, run the following commands:
```shell
kubectl -n ejbca-issuer-system get issuers.ejbca-issuer.keyfactor.com
kubectl -n ejbca-issuer-system get clusterissuers.ejbca-issuer.keyfactor.com
```

### Using Issuer and ClusterIssuer resources
Once the Issuer and ClusterIssuer resources are created, they can be used to issue certificates using cert-manager.
The two most important concepts are `Certificate` and `CertificateRequest` resources. `Certificate`
resources represent a single X.509 certificate and its associated attributes, and automatically renews the certificate
and keeps it up to date. When `Certificate` resources are created, they create `CertificateRequest` resources, which
use an Issuer or ClusterIssuer to actually issue the certificate.

###### To learn more about cert-manager, see the [cert-manager documentation](https://cert-manager.io/docs/).

The following is an example of a Certificate resource. This resource will create a corresponding CertificateRequest resource,
and will use the `issuer-sample` Issuer resource to issue the certificate. Once issued, the certificate will be stored in a
Kubernetes secret named `ejbca-certificate`.
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ejbca-certificate
spec:
  commonName: ejbca-issuer-sample
  secretName: ejbca-certificate
  issuerRef:
    name: issuer-sample
    group: ejbca-issuer.keyfactor.com
    kind: Issuer
```

###### Certificate resources support many more fields than the above example. See the [Certificate resource documentation](https://cert-manager.io/docs/usage/certificate/) for more information.

Similarly, a CertificateRequest resource can be created directly. The following is an example of a CertificateRequest resource.
```yaml
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: ejbca-certificate
spec:
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2REQ0NBVndDQVFBd0x6RUxNQWtHQTFVRUN4TUNTVlF4SURBZUJnTlZCQU1NRjJWcVltTmhYM1JsY25KaApabTl5YlY5MFpYTjBZV05qTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4blNSCklqZDZSN2NYdUNWRHZscXlFcUhKalhIazljN21pNTdFY3A1RXVnblBXa0YwTHBVc25PMld6WTE1bjV2MHBTdXMKMnpYSURhS3NtZU9ZQzlNOWtyRjFvOGZBelEreHJJWk5SWmg0cUZXRmpyNFV3a0EySTdUb05veitET2lWZzJkUgo1cnNmaFdHMmwrOVNPT3VscUJFcWVEcVROaWxyNS85OVpaemlBTnlnL2RiQXJibWRQQ1o5OGhQLzU0NDZhci9NCjdSd2ludjVCMnNRcWM0VFZwTTh3Nm5uUHJaQXA3RG16SktZbzVOQ3JyTmw4elhIRGEzc3hIQncrTU9DQUw0T00KTkJuZHpHSm5KenVyS0c3RU5UT3FjRlZ6Z3liamZLMktyMXRLS3pyVW5keTF1bTlmTWtWMEZCQnZ0SGt1ZG0xdwpMUzRleW1CemVtakZXQi9yRVFJREFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJhdFpIVTdOczg2Cmgxc1h0d0tsSi95MG1peG1vRWJhUTNRYXAzQXVFQ2x1U09mdjFDZXBQZjF1N2dydEp5ZGRha1NLeUlNMVNzazAKcWNER2NncUsxVVZDR21vRkp2REZEaEUxMkVnM0ZBQ056UytFNFBoSko1N0JBSkxWNGZaeEpZQ3JyRDUxWnk3NgpPd01ORGRYTEVib0w0T3oxV3k5ZHQ3bngyd3IwWTNZVjAyL2c0dlBwaDVzTHl0NVZOWVd6eXJTMzJYckJwUWhPCnhGMmNNUkVEMUlaRHhuMjR2ZEtINjMzSFo1QXd0YzRYamdYQ3N5VW5mVUE0ZjR1cHBEZWJWYmxlRFlyTW1iUlcKWW1NTzdLTjlPb0MyZ1lVVVpZUVltdHlKZTJkYXlZSHVyUUlpK0ZsUU5zZjhna1hYeG45V2drTnV4ZTY3U0x5dApVNHF4amE4OCs1ST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t
  issuerRef:
    name: issuer-sample
    group: ejbca-issuer.keyfactor.com
    kind: Issuer
```

### Approving Certificate Requests
Unless the cert-manager internal approver automatically approves the request, newly created CertificateRequest resources
will be in a `Pending` state until they are approved. CertificateRequest resources can be approved manually by using
[cmctl](https://cert-manager.io/docs/reference/cmctl/#approve-and-deny-certificaterequests). The following is an example
of approving a CertificateRequest resource named `ejbca-certificate` in the `ejbca-issuer-system` namespace.
```shell
cmctl -n ejbca-issuer-system approve ejbca-certificate
```

Once a certificate request has been approved, the certificate will be issued and stored in the secret specified in the
CertificateRequest resource. The following is an example of retrieving the certificate from the secret.
```shell
kubectl get secret ejbca-certificate -n ejbca-issuer-system -o jsonpath='{.data.tls\.crt}' | base64 -d
```

###### To learn more about certificate approval and RBAC configuration, see the [cert-manager documentation](https://cert-manager.io/docs/concepts/certificaterequest/#approval).
