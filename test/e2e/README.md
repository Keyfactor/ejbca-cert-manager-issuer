# End-to-End Test Suite

This is a test suite intended to make it easy to run end-to-end tests on the ejbca-cert-manager-issuer project. This suite can test the local changes of the EJBCA issuer, and it is able to test existing Docker images.

The test suite does the following:
- Deploys ejbca-cert-manager-issuer to a Kubernetes cluster with the desired version
- Creates an issuer (Issuer and ClusterIssuer)
- Creates a Certificate custom resource
- Waits for cert-manager to create a CertificateRequest, then signs the request
- Waits for the issuer to handle the CertificateRequest
- Verifies the CertificateRequest has been successfully processed and an issuer secret is created with the related certificate information.

This is currently configured as a Bash script, so it is necessary to run this on a UNIX-compatible machine.

## Requirements
- An available EJBCA is running and configured as described in the [root README](../../README.md#configuring-ejbca)
    - OAuth is used to communicate with EJBCA
- Docker (>= 28.2.2)
- kubectl (>= v1.32.2)
- helm (>= v3.17.1)
- cmctl (>= v2.1.1)
- Minikube (>= v1.35.0) - only required if using `USE_MINIKUBE=true`

**Kubernetes cluster:**
- By default, tests run against your current kubeconfig context
- Set `USE_MINIKUBE=true` to use minikube instead

**EJBCA instance:**
- An available EJBCA instance is configured as described in the [root README](../../README.md#configuring-ejbca)
- OAuth credentials for API access
- A CA configured in EJBCA, and the CA's logical name set in the `EJBCA_CA_NAME` environment variable
- An end-entity profile configured to allow API-based enrollment, and the name of this profile set in the `END_ENTITY_PROFILE_NAME` environment variable
- A certificate profile configured to allow API-based enrollment, and the name of this profile set in the `CERTIFICATE_PROFILE_NAME` environment variable

## Configuring the environment variables
ejbca-cert-manager-issuer interacts with an external EJBCA instance. An environment variable file `.env` can be used to store the environment variables to be used to talk to the EJBCA instance.

A `.env.example` file is available as a template for your environment variables.

```bash
# copy .env.example to .env
cp .env.example .env
```

### Required variables

| Variable | Description |
|----------|-------------|
| `HOSTNAME` | Command instance hostname |
| `OAUTH_TOKEN_URL` | OAuth token endpoint URL |
| `OAUTH_CLIENT_ID` | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | OAuth client secret |
| `EJBCA_CA_NAME` | CA logical name in EJBCA |
| `CERTIFICATE_PROFILE_NAME` | Certificate profile name in EJBCA |
| `END_ENTITY_PROFILE_NAME` | End-entity profile name in EJBCA |

### Optional variables

| Variable | Description | Default |
|----------|-------------|---------|
| `USE_MINIKUBE` | Set to `true` to use minikube instead of the current kubeconfig context | `false` |
| `OAUTH_SCOPES` | OAuth scopes (optional, remove if not needed) | |
| `OAUTH_AUDIENCE` | OAuth audience (optional, remove if not needed) | |
| `IMAGE_TAG` | Docker image tag to test | `local` |
| `HELM_CHART_VERSION` | Helm chart version to test | `local` |
| `IMAGE_REGISTRY` | Optional registry to push the image to if `IMAGE_TAG` != `local` | |


## Configuring EJBCA Security Role
The EJBCA issuer needs to be able to interact with the EJBCA instance to sign the CertificateRequest. The OAuth subject defined in the `OAUTH_CLIENT_ID` environment variable needs to be configured with a security role with the permissions defined in the [Configure EJBCA Roles and Access Rules](../../README.md#configuring-ejbca) section of the root README.

## Configuring EJBCA Security Role
The EJBCA issuer needs to be able to interact with the EJBCA instance to sign the CertificateRequest. The OAuth subject defined in the `OAUTH_CLIENT_ID` environment variable needs to be configured with a security role with the permissions defined in the [Configure EJBCA Roles and Access Rules](../../README.md#configuring-ejbca) section of the root README.

## Running the script

```bash
# enable the script to be executed
chmod +x ./run_tests.sh

# load the environment variables
source .env

# run the end-to-end tests
./run_tests.sh
```
