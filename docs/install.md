<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Installing the Keyfactor EJBCA Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

### Prerequisites
Before starting, ensure that the following requirements are met
* [Git](https://git-scm.com/)
* [Make](https://www.gnu.org/software/make/)
* [Docker](https://docs.docker.com/engine/install/) >= v20.10.0
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) >= v1.11.3
* Kubernetes >= v1.19
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/), [Minikube](https://minikube.sigs.k8s.io/docs/start/), or [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
* [Keyfactor EJBCA](https://www.keyfactor.com/products/ejbca-enterprise/) >= v7.7
* [cert-manager](https://cert-manager.io/docs/installation/) >= v1.11.0
* [cmctl](https://cert-manager.io/docs/reference/cmctl/)
* Keyfactor EJBCA is properly configured according to the [product docs](https://software.keyfactor.com/Content/MasterTopics/Home.htm). 
* EJBCA REST API with the following API endpoints:
    * `/ejbca-rest-api/v1/certificate/pkcs10enroll`
    * `/ejbca/ejbca-rest-api/v1/certificate/status`

Additionally, verify that at least one Kubernetes node is running by running the following command:

```shell
kubectl get nodes
```

A static installation of cert-manager can be installed with the following command:

```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

###### :pushpin: Running the static cert-manager configuration is not recommended for production use. For more information, see [Installing cert-manager](https://cert-manager.io/docs/installation/).

### Installation from Helm Chart

The cert-manager external issuer for Keyfactor EJBCA is installed using a Helm chart. The chart is available in the [EJBCA cert-manager Helm repository](https://keyfactor.github.io/ejbca-cert-manager-issuer/).

1. Add the Helm repository:

    ```shell
    helm repo add ejbca-issuer https://keyfactor.github.io/ejbca-cert-manager-issuer
    helm repo update
    ```

2. Then, install the chart:

    ```shell
    helm install ejbca-cert-manager-issuer ejbca-issuer/ejbca-cert-manager-issuer \
        --namespace ejbca-issuer-system \
        --create-namespace \
        # --set image.pullPolicy=Never # Only required if using a local image
    ```

   1. Modifications can be made by overriding the default values in the `values.yaml` file with the `--set` flag. For example, to override the `secretConfig.useClusterRoleForSecretAccess` to configure the chart to use a cluster role for secret access, run the following command:

        ```shell
        helm install ejbca-cert-manager-issuer ejbca-issuer/ejbca-cert-manager-issuer \
            --namespace ejbca-issuer-system \
            --create-namespace \
            --set replicaCount=2
        ```

   2. Modifications can also be made by modifying the `values.yaml` file directly. For example, to override the `secretConfig.useClusterRoleForSecretAccess` value to configure the chart to use a cluster role for secret access, modify the `secretConfig.useClusterRoleForSecretAccess` value in the `values.yaml` file by creating an override file:

        ```yaml
        cat <<EOF > override.yaml
        secretConfig:
            useClusterRoleForSecretAccess: true
        EOF
        ```

        Then, use the `-f` flag to specify the `values.yaml` file:

        ```shell
        helm install ejbca-cert-manager-issuer ejbca-issuer/ejbca-cert-manager-issuer \
            --namespace command-issuer-system \
            -f override.yaml
        ```

Next, complete the [Usage](config_usage.md) steps to configure the cert-manager external issuer for Keyfactor EJBCA.

