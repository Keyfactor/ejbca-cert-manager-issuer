<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer)
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

## Quick Start

The quick start guide will walk you through the process of installing the cert-manager external issuer for Keyfactor EJBCA.
The controller image is pulled from [Docker Hub](https://hub.docker.com/r/m8rmclarenkf/command-external-issuer). 

###### To build  the container from sources, refer to the [Building Container Image from Source](#building-container-image-from-source) section.

### Requirements
* [Git](https://git-scm.com/)
* [Make](https://www.gnu.org/software/make/)
* [Docker](https://docs.docker.com/engine/install/) >= v20.10.0
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) >= v1.11.3
* Kubernetes >= v1.19
  * [Kubernetes](https://kubernetes.io/docs/tasks/tools/), [Minikube](https://minikube.sigs.k8s.io/docs/start/), or [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [cert-manager](https://cert-manager.io/docs/installation/) >= v1.11.0
* [cmctl](https://cert-manager.io/docs/reference/cmctl/)

Before starting, ensure that all the requirements above are met, and that at least one Kubernetes node is running by running the following command:
```shell
kubectl get nodes
```

Once Kubernetes is running, a static installation of cert-manager can be installed with the following command:
```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

Then, install the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor EJBCA:
```shell
make install
```

Finally, deploy the controller to the cluster:
```shell
make deploy
```

## Usage
The cert-manager external issuer for Keyfactor EJBCA can be used to issue certificates from Keyfactor EJBCA using cert-manager.

### Authentication
Authentication to the EJBCA platform is done using a client certificate and key. The client certificate and key must be provided as a Kubernetes secret.

Create a K8s TLS secret containing the client certificate and key to authenticate with EJBCA:
```shell
kubectl -n ejbca-issuer-system create secret tls ejbca-secret --cert=client.crt --key=client.key
```

If the EJBCA API is configured to use a self-signed certificate or with a certificate signed by an untrusted root, the CA certificate must be provided as a Kubernetes secret.
```shell
kubectl -n ejbca-issuer-system create secret generic ejbca-ca-secret --from-file=ca.crt
```

### Creating Issuer and ClusterIssuer resources
The `ejbca-issuer.keyfactor.com/v1alpha1` API version supports Issuer and ClusterIssuer resources. 
The ejbca controller will automatically detect and process resources of both types.

The Issuer resource is namespaced, while the ClusterIssuer resource is cluster-scoped.
For example, ClusterIssuer resources can be used to issue certificates for resources in multiple namespaces, whereas Issuer resources can only be used to issue certificates for resources in the same namespace.

The `spec` field of both the Issuer and ClusterIssuer resources use the following fields:
* `hostname` - The hostname of the EJBCA instance
* `ejbcaSecretName` - The name of the Kubernetes secret containing the client certificate and key
* `certificateAuthorityName` - The name of the EJBCA certificate authority to use. For example, `ManagementCA`
* `certificateProfileName` - The name of the EJBCA certificate profile to use. For example, `ENDUSER`
* `endEntityProfileName` - The name of the EJBCA end entity profile to use. For example, `ENDUSER`
* `caBundleSecretName` - The name of the Kubernetes secret containing the CA certificate. This field is optional and only required if the EJBCA API is configured to use a self-signed certificate or with a certificate signed by an untrusted root.

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
  ejbcaBundleSecretName: ""
  certificateAuthorityName: ""
  certificateProfileName: ""
  endEntityProfileName: ""
  caBundleSecretName: ""
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
  caBundleSecretName: ""
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

## Cleanup
To list the certificates and certificate requests created, run the following commands:
```shell
kubectl get certificates -n ejbca-issuer-system
kubectl get certificaterequests -n ejbca-issuer-system
```

To remove the certificate and certificate request resources, run the following commands:
```shell
kubectl delete certificate ejbca-certificate -n ejbca-issuer-system
kubectl delete certificaterequest ejbca-certificate -n ejbca-issuer-system
```

To list the issuer and cluster issuer resources created, run the following commands:
```shell
kubectl -n ejbca-issuer-system get issuers.ejbca-issuer.keyfactor.com
kubectl -n ejbca-issuer-system get clusterissuers.ejbca-issuer.keyfactor.com
```

To remove the issuer and cluster issuer resources, run the following commands:
```shell
kubectl -n ejbca-issuer-system delete issuers.ejbca-issuer.keyfactor.com <issuer-name>
kubectl -n ejbca-issuer-system delete clusterissuers.ejbca-issuer.keyfactor.com <issuer-name>
```

To remove the controller from the cluster, run:
```shell
make undeploy
```

To remove the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor EJBCA, run:
```shell
make uninstall
```

## Building Container Image from Source

### Requirements
* [Golang](https://golang.org/) >= v1.19

Building the container from source first runs appropriate test cases, which requires all requirements also listed in the
Quick Start section. As part of this testing is an enrollment of a certificate with EJBCA, so a running instance of EJBCA
is also required.

The following environment variables must be exported before building the container image:
* `EJBCA_HOSTNAME` - The hostname of the EJBCA instance to use for testing.
* `EJBCA_CLIENT_CERT_PATH` - A relative or absolute path to a client certificate that is authorized to enroll certificates in EJBCA. The file must include the certificate and associated private key in unencrypted PKCS#8 format.
* `EJBCA_CA_NAME` - The name of the CA in EJBCA to use for testing.
* `EJBCA_CERTIFICATE_PROFILE_NAME` - The name of the certificate profile in EJBCA to use for testing.
* `EJBCA_END_ENTITY_PROFILE_NAME` - The name of the end entity profile in EJBCA to use for testing.
* `EJBCA_CSR_SUBJECT` - The subject of the certificate signing request (CSR) to use for testing.
* `EJBCA_CA_CERT_PATH` - A relative or absolute path to the CA certificate that the EJBCA instance uses for TLS. The file must include the certificate in PEM format.

To build the cert-manager external issuer for Keyfactor EJBCA, run:
```shell
make docker-build
```
