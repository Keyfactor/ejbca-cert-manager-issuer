# Contributing Guidelines

For information on how to contribute to EJBCA and related tools, see [EJBCA Contributing Guidelines](https://github.com/Keyfactor/ejbca-ce/blob/main/CONTRIBUTING.md). 

# EJBCA Cert Manager Issuer Contribution Guide

## Requirements
- Go (>= 1.25)
- golangci-lint (>= 2.4.0) ([installation notes](https://github.com/golangci/golangci-lint?tab=readme-ov-file#install-golangci-lint))
- helm (>= 3.x) — required to render chart templates for manifest linting ([installation notes](https://helm.sh/docs/intro/install/))
- conftest — policy testing tool powered by Open Policy Agent; installed automatically by `make lint-manifests`

## Installing dependencies
Project dependencies can be installed by running the following:

```bash
go mod download
```

The following command can be used to add missing requirements or remove unused modules:

```bash
go mod tidy
```

## Running unit tests
The following command can be run to run the project unit tests:

```bash
go test -v ./...
```

## Running linters
The project uses golangci-lint to lint the codebase. The following command can be run to run the linters:

```bash
golangci-lint run
```

## Updating generated manifests

This command will update the generated custom resource definitions under `config/crd/bases`:

```bash
make generate manifests
```

> [!IMPORTANT]
> There is no automated process to automatically update the CRDs under `deploy/charts/ejbca-cert-manager-issuer`. If any changes are made to the CRDs, the generated CRDs under `config/crd/bases` must be copied to `deploy/charts/ejbca-cert-manager-issuer/crds` to ensure the Helm chart is up to date.

## Linting Helm manifests

The Helm chart under `deploy/charts/ejbca-cert-manager-issuer` is linted with two tools on every PR:

- **conftest** — runs custom Rego policies located in the [`policy/`](policy/) directory against the rendered manifests

To run both checks locally:

```bash
make lint-manifests
```

`conftest` is downloaded automatically into `bin/` on first use; no manual installation is required.

To inspect the rendered templates without linting:

```bash
make helm-template
```

### Adding or modifying policies

Rego policies live in [`policy/`](policy/). Each `.rego` file in that directory is evaluated by conftest against every resource in the rendered chart. Add a new `.rego` file to enforce additional rules. For example, `policy/roles.rego` enforces that all `Role` resources declare an explicit namespace.

kube-linter checks can be tuned in [.kube-linter.yaml](.kube-linter.yaml). To exclude a check, add its name under the `exclude` key.

## Running end-to-end tests
A comprehensive end-to-end test suite is available to verify the issuer code works against cert-manager and an EJBCA instance.

Instructions on how to run the end-to-end test suite can be found [here](./test/e2e/README.md).