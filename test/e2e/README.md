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
- Minikube (>= v1.35.0)
- kubectl (>= v1.32.2)
- helm (>= v3.17.1)
- cmctl (>= v2.1.1)

## Configuring the environment variables
ejbca-cert-manager-issuer interacts with an external EJBCA instance. An environment variable file `.env` can be used to store the environment variables to be used to talk to the EJBCA instance.

A `.env.example` file is available as a template for your environment variables.

```bash
# copy .env.example to .env
cp .env.example .env
```

Modify the fields as needed.

## Running the script

```bash
# enable the script to be executed
chmod +x ./run_test.sh

# load the environment variables
source .env

# run the end-to-end tests
./run_tests.sh
```
