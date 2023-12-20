# v1.3.1

## Features
* feat(controller): Implement Kubernetes `client-go` REST client for Secret/ConfigMap retrieval to bypass `controller-runtime` caching system. This enables the reconciler to retrieve Secret and ConfigMap resources at the namespace scope with only namespace-level permissions.
* feat(ci): Add GitHub Actions workflows to run unit tests and release container images when appropriate
* feat(helm): Create Helm chart to deploy the controller to a Kubernetes or OpenShift cluster

## Fixes
* fix(controller): Add logic to read secret from reconciler namespace or Issuer namespace depending on Helm configuration.