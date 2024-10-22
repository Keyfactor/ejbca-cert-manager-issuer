# Overview

The EJBCA Issuer for [cert-manager](https://cert-manager.io/) is a [CertificateRequest](https://cert-manager.io/docs/usage/certificaterequest/) controller that issues certificates using [EJBCA](https://ejbca.org/).

# Requirements

Before starting, ensure that the following requirements are met:

- [Suported](https://docs.keyfactor.com/ejbca/latest/supported-versions) version of EJBCA [Community](https://www.ejbca.org/) or EJBCA [Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/)
    - EJBCA must be properly configured according to the [product docs](https://software.keyfactor.com/Content/MasterTopics/Home.htm). 
    - The "REST Certificate Management" protocol must be enabled under System Configuration > Protocol Configuration. The following endpoints must be available:
        - `/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll`
        - `/ejbca/ejbca-rest-api/v1/certificate/status`
- Kubernetes >= v1.19
    - [Kubernetes](https://kubernetes.io/docs/tasks/tools/), [Minikube](https://minikube.sigs.k8s.io/docs/start/), [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/), etc.
    > You must have permission to create [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) in your Kubernetes cluster.
- [Supported cert-manager release](https://cert-manager.io/docs/releases/) installed in your cluster. Please see the [cert-manager installation](https://cert-manager.io/docs/installation/) for details.
- [Supported version of Helm](https://helm.sh/docs/topics/version_skew/) for your Kubernetes version

# Badges

<a href="https://github.com/keyfactor/ejbca-cert-manager-issuer/releases/latest"><img src="https://img.shields.io/github/v/release/keyfactor/ejbca-cert-manager-issuer?style=flat-square" alt="Latest Release"></a>
<a href="https://ejbca.org"><img src="https://img.shields.io/badge/valid_for-ejbca_community-FF9371" alt="Valid for EJBCA Community"></a>
<a href="https://www.keyfactor.com/products/ejbca-enterprise/"><img src="https://img.shields.io/badge/valid_for-ejbca_enterprise-5F61FF" alt="Valid for EJBCA Enterprise"></a>
<a href="https://goreportcard.com/report/github.com/keyfactor/ejbca-cert-manager-issuer"><img src="https://goreportcard.com/badge/github.com/keyfactor/ejbca-cert-manager-issuer" alt="Go Report Card"></a>
<a href="https://img.shields.io/badge/License-Apache%202.0-blue.svg"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License Apache 2.0"></a>

# Getting Started

## Configuring EJBCA

EJBCA Issuer enrolls certificates by creating or updating an [End Entity](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/end-entities-overview) via the PKCS10 Enroll REST request. Before using EJBCA Issuer, you must create or identify an End Entity Profile _and_ a Certificate Profile suitable for your usecase.

1. **Create or identify a Certificate Profile**

    Certificate Profiles in EJBCA define the properties and constraints of the certificates being issued. This includes settings like key usage, extended key usage, validity period, allowed key algorithms, and signature algorithms.

    - If you haven't created a Certificate Profile before, [this guide](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-operations-guide/ca-operations-guide/managing-certificate-profiles/create-a-certificate-profile-for-ssl-servers) walks you through how to create a Certificate Profile in the EJBCA AdminWeb.

    You should make careful note of the allowed Key Types and Key Sizes on the Certificate Profile. When creating cert-manager [Certificates](https://cert-manager.io/docs/usage/certificate/), you must make sure that the key `algorithm` and `size` are allowed by your Certificate Profile in EJBCA.    

2. **Create or identify an End Entity Profile**

    End Entity Profiles in EJBCA define the rules for managing certificate requesters (end entities) and their associated data. They define which fields are required, optional, or hidden during the certificate enrollment process (e.g., common name, email, organization, SANs). End Entity Profiles control the type of information that end entities must provide and how that information is validated before issuing certificates.

    - If you haven't created an End Entity Profile before, [this guide](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-operations-guide/ca-operations-guide/end-entity-profile-operations/create-an-end-entity-profile-for-ssl-servers) walks you through how to create an End Entity Profile in the EJBCA AdminWeb.

    You should make careful note of the **Subject DN Attributes** and **Other Subject Attributes** specified by your End Entity Profile. When creating cert-manager [Certificates](https://cert-manager.io/docs/usage/certificate/), you must make sure that the `subject`, `commonName`, `dnsNames`, etc. are allowed and/or configured correctly by your End Entity Profile in EJBCA.

3. **Configure EJBCA Roles and Access Rules**

    Roles define groups of users or administrators with specific permissions. In EJBCA, users and administrators are identified by being members of a particular role. Access Rules are permissions that dictate what actions a role can perform and what parts of the system it can interact with.  

    - If you haven't created Roles and Access rules before, [this guide](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/roles-and-access-rules) provides a primer on these concepts in EJCBA.

    If your security policy requires fine-grain access control, EJBCA Issuer requires the following Access Rules.

    | Regular Access Rules                    | Permission         |
    |-----------------------------------------|--------------------|
    | `/ra_functionality/approve_end_entity/` | Allow              |
    | `/ra_functionality/create_end_entity/`  | Allow              |
    | `/ra_functionality/edit_end_entity/`    | Allow              |

    | CA Access Rules                         | Permission         |
    |-----------------------------------------|--------------------|
    | `/ca/<your CA name>/`                   | Allow              |

    | End Entity Profile Access Rules                           | Permission         |
    |-----------------------------------------------------------|--------------------|
    | `/endentityprofilesrules/<your End Entity Profile Name>/` | Allow              |

## Installing EJBCA Issuer

EJBCA Issuer is installed using a Helm chart. The chart is available in the [EJBCA cert-manager Helm repository](https://keyfactor.github.io/ejbca-cert-manager-issuer/).

1. Verify that at least one Kubernetes node is running 

    ```shell
    kubectl get nodes
    ```

2. Add the Helm repository:

    ```shell
    helm repo add ejbca-issuer https://keyfactor.github.io/ejbca-cert-manager-issuer
    helm repo update
    ```

3. Then, install the chart:

    ```shell
    helm install ejbca-cert-manager-issuer ejbca-issuer/ejbca-cert-manager-issuer \
        --namespace ejbca-issuer-system \
        --create-namespace \
        # --set image.pullPolicy=Never # Only required if using a local image
    ```

> The Helm chart installs the EJBCA Issuer CRDs by default. The CRDs can be installed manually with the `make install` target.

# Authentication

EJBCA Issuer supports authentication to EJBCA using mTLS (client certificate & key) or the OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0).

Credentials must be configured using a Kubernetes Secret. By default, the secret is expected to exist in the same namespace as the issuer controller (`ejbca-issuer-system` by default). 

> EJBCA Issuer can read secrets in the Issuer namespace if `--set "secretConfig.useClusterRoleForSecretAccess=true"` flag is set when installing the Helm chart.

## mTLS

Create a K8s TLS secret containing the client certificate and key to authenticate with EJBCA:
```shell
kubectl -n ejbca-issuer-system create secret tls ejbca-secret --cert=client.crt --key=client.key
```

## OAuth

Create an Opaque secret containing the client ID and client secret to authenticate with EJBCA:

```shell
token_url="<token url>"
client_id="<client id>"
client_secret="<client secret>"
audience="<audience>"
scopes="<scopes>" # comma separated list of scopes

kubectl -n ejbca-issuer-system create secret generic ejbca-secret \
    "--from-literal=tokenUrl=$token_url" \
    "--from-literal=clientId=$client_id" \
    "--from-literal=clientSecret=$client_secret" \
    "--from-literal=audience=$audience" \
    "--from-literal=scopes=$scopes"
```

> Audience and Scopes are optional

# CA Bundle

If the EJBCA API is configured to use a self-signed certificate or with a certificate that isn't publically trusted, the CA certificate must be provided as a Kubernetes secret.

```shell
kubectl -n ejbca-issuer-system create secret generic ejbca-ca-secret --from-file=ca.crt
```

# Creating Issuer and ClusterIssuer resources

The `ejbca-issuer.keyfactor.com/v1alpha1` API version supports Issuer and ClusterIssuer resources. The Issuer resource is namespaced, while the ClusterIssuer resource is cluster-scoped.

For example, ClusterIssuer resources can be used to issue certificates for resources in multiple namespaces, whereas Issuer resources can only be used to issue certificates for resources in the same namespace.

1. **Prepare the `spec`**

    ```shell
    export HOSTNAME="<hostname>"
    export EJBCA_CA_NAME="<certificateAuthorityName>"
    export CERTIFICATE_PROFILE_NAME="<certificateProfileName>"
    export END_ENTITY_PROFILE_NAME="<endEntityProfileName>"
    ```

    The `spec` field of both the Issuer and ClusterIssuer resources use the following fields:
    | Field Name               | Description                                                                                                                                   |
    |--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
    | hostname                 | The hostname of the EJBCA instance                                                                                                           |
    | ejbcaSecretName          | The name of the Kubernetes secret containing the client certificate and key or OAuth 2.0 credentials                                          |
    | certificateAuthorityName | The name of the EJBCA certificate authority to use. For example, `ManagementCA`                                                              |
    | certificateProfileName   | The name of the EJBCA certificate profile to use. For example, `ENDUSER`                                                                     |
    | endEntityProfileName     | The name of the EJBCA end entity profile to use. For example, `istio`                                                                        |
    | caBundleSecretName       | The name of the Kubernetes secret containing the CA certificate. Optional, required if using a self-signed or untrusted root certificate      |
    | endEntityName            | The name of the end entity to use. Optional. Refer to the EJBCA End Entity Name Configuration section for more details on how this field is used |

    > If a different combination of hostname/certificate authority/certificate profile/end entity profile is required, a new Issuer or ClusterIssuer resource must be created. Each resource instantiation represents a single configuration.

2. **Create an Issuer or ClusterIssuer**

    - **Issuer**

        Create an Issuer resource using the environment variables prepared in step 1.

        ```yaml
        cat <<EOF > ./issuer.yaml
        apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
        kind: Issuer
        metadata:
          name: issuer-sample
          namespace: default
        spec:
          hostname: "$HOSTNAME"
          ejbcaSecretName: "ejbca-secret" # references the secret created above
          caBundleSecretName: "ejbca-ca-secret" # references the secret created above

          certificateAuthorityName: "$EJBCA_CA_NAME"
          certificateProfileName: "$CERTIFICATE_PROFILE_NAME"
          endEntityProfileName: "$END_ENTITY_PROFILE_NAME"

          endEntityName: ""
        EOF

        kubectl -n default apply -f issuer.yaml
        ```

    - **ClusterIssuer**
        
        Create a ClusterIssuer resource using the environment variables prepared in step 1.

        ```yaml
        cat <<EOF > ./clusterissuer.yaml
        apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
        kind: ClusterIssuer
        metadata:
          name: clusterissuer-sample
        spec:
          hostname: "$HOSTNAME"
          ejbcaSecretName: "ejbca-secret" # references the secret created above
          caBundleSecretName: "ejbca-ca-secret" # references the secret created above

          certificateAuthorityName: "$EJBCA_CA_NAME"
          certificateProfileName: "$CERTIFICATE_PROFILE_NAME"
          endEntityProfileName: "$END_ENTITY_PROFILE_NAME"

          endEntityName: ""
        EOF

        kubectl apply -f clusterissuer.yaml
        ```
    > **NOTE**
    >
    > The `endEntityName` field in the Issuer and ClusterIssuer spec is described [here](docs/endentitynamecustomization.md)

# Creating a Certificate

Once an Issuer or ClusterIssuer resource is created, they can be used to issue certificates using cert-manager. The two most important concepts are `Certificate` and `CertificateRequest` resources. 

1. `Certificate` resources represent a single X.509 certificate and its associated attributes. cert-manager maintains the corresponding certificate, including renewal when appropriate. 
2. When `Certificate` resources are created, cert-manager creates a corresponding `CertificateRequest` that targets a specific Issuer or ClusterIssuer to actually issue the certificate.

> To learn more about cert-manager, see the [cert-manager documentation](https://cert-manager.io/docs/).

The following is an example of a Certificate resource. This resource will create a corresponding CertificateRequest resource, and will use the `issuer-sample` Issuer resource to issue the certificate. Once issued, the certificate will be stored in a Kubernetes secret named `ejbca-certificate`.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ejbca-certificate
spec:
  issuerRef:
    name: issuer-sample
    group: ejbca-issuer.keyfactor.com
    kind: Issuer
  commonName: example.com
  secretName: ejbca-certificate
```

> Certificate resources support many more fields than the above example. See the [Certificate resource documentation](https://cert-manager.io/docs/usage/certificate/) for more information.

Similarly, a CertificateRequest resource can be created directly. The following is an example of a CertificateRequest resource.
```yaml
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: ejbca-certificate
spec:
  issuerRef:
    name: issuer-sample
    group: ejbca-issuer.keyfactor.com
    kind: Issuer
  request: <csr>
```

> All fields in EJBCA Issuer and ClusterIssuer `spec` can be overridden by applying Kubernetes Annotations to Certificates _and_ CertificateRequests. See [runtime customization for more](docs/annotations.md) 

## Approving Certificate Requests
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

> To learn more about certificate approval and RBAC configuration, see the [cert-manager documentation](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

