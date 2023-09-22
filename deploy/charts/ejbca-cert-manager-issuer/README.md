<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Version: v0.1.0](https://img.shields.io/badge/Version-v0.1.0-informational?style=flat-square)
![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) 
![AppVersion: v1.3.1](https://img.shields.io/badge/AppVersion-v1.3.1-informational?style=flat-square)

A Helm chart for the Keyfactor EJBCA External Issuer for cert-manager.

The EJBCA external issuer for cert-manager allows users to enroll certificates from Keyfactor EJBCA using cert-manager.

## Configuration

The following table lists the configurable parameters of the `ejbca-cert-manager-issuer` chart and their default values.

| Parameter                         | Description                                         | Default                                                      |
|-----------------------------------|-----------------------------------------------------|--------------------------------------------------------------|
| `replicaCount`                    | Number of replica ejbca-cert-manager-issuers to run | `1`                                                          |
| `image.repository`                | Image repository                                    | `m8rmclarenkf/ejbca-cert-manager-external-issuer-controller` |
| `image.pullPolicy`                | Image pull policy                                   | `IfNotPresent`                                               |
| `image.tag`                       | Image tag                                           | `v1.3.1`                                                     |
| `imagePullSecrets`                | Image pull secrets                                  | `[]`                                                         |
| `nameOverride`                    | Name override                                       | `""`                                                         |
| `fullnameOverride`                | Full name override                                  | `""`                                                         |
| `crd.create`                      | Specifies if CRDs will be created                   | `true`                                                       |
| `crd.annotations`                 | Annotations to add to the CRD                       | `{}`                                                         |
| `serviceAccount.create`           | Specifies if a service account should be created    | `true`                                                       |
| `serviceAccount.annotations`      | Annotations to add to the service account           | `{}`                                                         |
| `serviceAccount.name`             | Name of the service account to use                  | `""` (uses the fullname template if `create` is true)        |
| `podAnnotations`                  | Annotations for the pod                             | `{}`                                                         |
| `podSecurityContext.runAsNonRoot` | Run pod as non-root                                 | `true`                                                       |
| `securityContext`                 | Security context for the pod                        | `{}` (with commented out options)                            |
| `resources`                       | CPU/Memory resource requests/limits                 | `{}` (with commented out options)                            |
| `nodeSelector`                    | Node labels for pod assignment                      | `{}`                                                         |
| `tolerations`                     | Tolerations for pod assignment                      | `[]`                                                         |
