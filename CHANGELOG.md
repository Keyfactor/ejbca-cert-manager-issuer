# v2.1.0

## Chores
* Update Go library dependencies
* Update documentation for issuer and cluster issuer types
* Address linting issues

## Fixes
* Fix CI pipeline failures 

# v2.0.0

## Chores
* Refactor EJBCA signer module to remove tight dependency on Issuer/ClusterIssuer types.
* Migrate Kubebuilder from go/v3 to go/v4:
    * Upgrade kustomize version to v5.3.0.
    * Upgrade controller-gen to v0.15.0.
* Refactor test cases to use fake EJBCA API instead of requiring live EJBCA server.
* Write e2e integration test.

## Features
* Add support for OAuth2.0 client credential grant flow for EJBCA API authentication.

# v1.4.0

## Features
* feat(ci): feat(ci): Deploy ephemeral EJBCA/SignServer server as part of CI/CD test workflow. This enables the controller to be tested against a real CA.
* feat(ci): Reconcile Keyfactor actions and old workflows to match the new Keyfactor GitHub Actions workflows.
* feat(helm): Add namespace to resource definitions for helm template generation.
* feat(signer): Use in-tree cert-manager certificate reconstruction methods when compiling `status`

# v1.3.2

## Features
* feat(helm): Rename `secureMetrics` to `metrics` and add `metrics.secure` and `metrics.metricsAddress` as configuration values. This way, Prometheus can scrape the controller manager metrics without the secure metrics proxy.
* feat(helm): Add configuration element in Helm chart default values file to configure container ports on the controller manager container.

## Fixes
* fix(deps): Update golang.org/x/net to v0.19.0
* fix(dockerfile): Upgrade builder image to golang:1.20 to address [CVE-2023-38408](https://scout.docker.com/vulnerabilities/id/CVE-2023-38408?utm_source=hub&utm_medium=ExternalLink&_gl=1*hbs4zp*_ga*MTU5MTQ4Mzk3MC4xNjkxNDI2NjAy*_ga_XJWPQMJYHQ*MTcwMzE4NzcyNC4xMDEuMS4xNzAzMTg4OTUxLjM3LjAuMA..)

# v1.3.1

## Features
* feat(controller): Implement Kubernetes `client-go` REST client for Secret/ConfigMap retrieval to bypass `controller-runtime` caching system. This enables the reconciler to retrieve Secret and ConfigMap resources at the namespace scope with only namespace-level permissions.
* feat(ci): Add GitHub Actions workflows to run unit tests and release container images when appropriate
* feat(helm): Create Helm chart to deploy the controller to a Kubernetes or OpenShift cluster

## Fixes
* fix(controller): Add logic to read secret from reconciler namespace or Issuer namespace depending on Helm configuration.
