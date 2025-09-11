# Contributing Guidelines

For information on how to contribute to EJBCA and related tools, see [EJBCA Contributing Guidelines](https://github.com/Keyfactor/ejbca-ce/blob/main/CONTRIBUTING.md). 

# EJBCA Cert Manager Issuer Contribution Guide

## Requirements
- Go (>= 1.24)
- golangci-lint (v1.64.5) ([installation notes](https://github.com/golangci/golangci-lint?tab=readme-ov-file#install-golangci-lint))

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

## Running end-to-end tests
A comprehensive end-to-end test suite is available to verify the issuer code works against cert-manager and an EJBCA instance.

Instructions on how to run the end-to-end test suite can be found [here](./test/e2e/README.md).