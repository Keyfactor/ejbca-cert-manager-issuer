#!/bin/bash

reconciler_namespace="ejbca-issuer-system"
reconciler_chart_name="ejbca-cert-manager-issuer"
version="latest"

echo "Building docker image"
make docker-build DOCKER_REGISTRY=keyfactor DOCKER_IMAGE_NAME="$reconciler_chart_name" VERSION="$version"

docker images
kind load docker-image keyfactor/ejbca-cert-manager-issuer:latest

echo "Deploying $reconciler_chart_name Helm chart"
helm_install_args=(
    "install" 
    "--namespace" "$reconciler_namespace"
    "--create-namespace"
    "$reconciler_chart_name" 
    "deploy/charts/$reconciler_chart_name" 
    "--set" "image.repository=keyfactor/$reconciler_chart_name"
    "--set" "image.pullPolicy=Never"
    "--set" "image.tag=$version"
    "--set" "metrics.metricsAddress=:8080"
)

if ! helm "${helm_install_args[@]}" ; then
    echo "Failed to install EJBCA"
    kubectl delete namespace "$EJBCA_NAMESPACE"
    exit 1
fi

echo "Waiting for Pod to be ready"
if ! kubectl --namespace "$reconciler_namespace" wait --for=condition=ready pod -l app.kubernetes.io/instance="$reconciler_chart_name" --timeout=30s ; then
    echo "Failed to deploy $reconciler_chart_name"
    kubectl describe all -A
    exit 1
fi

if [[ $(kubectl get secret -n "$reconciler_namespace" -o json | jq -r '.items[] | select(.metadata.name == "ejbca-clusterissuer-secret")') == "" ]]; then
    echo "Creating TLS secret called ejbca-clusterissuer-secret"
    kubectl create secret tls "ejbca-clusterissuer-secret" \
        --cert="$EJBCA_CLIENT_CERT_PATH" \
        --key="$EJBCA_CLIENT_CERT_KEY_PATH" \
        -n "$reconciler_namespace"
fi

if [[ $(kubectl get secret -n "$reconciler_namespace" -o json | jq -r '.items[] | select(.metadata.name == "ejbca-clusterissuer-ca-secret")') == "" ]]; then
    echo "Creating secret called ejbca-clusterissuer-ca-secret"
    kubectl create secret generic "ejbca-clusterissuer-ca-secret" \
        "--from-file=$EJBCA_CA_CERT_PATH" \
        -n "$reconciler_namespace"
fi

#######################
# ClusterIssuer Tests #
#######################

echo "Creating ClusterIssuer"
kubectl apply -f - <<EOF
apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata:
  name: test-cluster-issuer
spec:
  hostname: "$EJBCA_IN_CLUSTER_HOSTNAME"
  ejbcaSecretName: "ejbca-clusterissuer-secret"
  caBundleSecretName: "ejbca-clusterissuer-ca-secret"
  certificateAuthorityName: "$EJBCA_CA_NAME"
  certificateProfileName: "$EJBCA_CERTIFICATE_PROFILE_NAME"
  endEntityProfileName: "$EJBCA_END_ENTITY_PROFILE_NAME"
  endEntityName: "ejbca-issuer-sample"
EOF

echo "Waiting for ClusterIssuer to be ready"
if ! kubectl wait --for=condition=ready ClusterIssuer.ejbca-issuer.keyfactor.com/test-cluster-issuer --timeout=30s ; then
    echo "Failed to create ClusterIssuer"
    kubectl delete ns "$reconciler_namespace"
    exit 1
fi

kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-clusterissuer-certificate
  annotations:
    ejbca-issuer.keyfactor.com/endEntityName: "dns"
    ejbca-issuer.keyfactor.com/certificateAuthorityName: "$EJBCA_CA_NAME"
    ejbca-issuer.keyfactor.com/certificateProfileName: "$EJBCA_CERTIFICATE_PROFILE_NAME"
    ejbca-issuer.keyfactor.com/endEntityProfileName: "$EJBCA_END_ENTITY_PROFILE_NAME"
spec:
  secretName: ejbca-certificate-secret
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: test-cluster-issuer
    group: ejbca-issuer.keyfactor.com
    kind: ClusterIssuer
EOF

echo "Waiting 10 seconds for CertificateRequest"
sleep 10

echo "Approving all CertificateRequests"
kubectl get certificaterequest.cert-manager.io -o json | jq -r '.items[].metadata.name' | xargs -I {} cmctl approve {}

echo "Waiting for certificate issuance"
if ! kubectl wait --for=condition=Ready certificate.cert-manager.io/test-clusterissuer-certificate --timeout=30s ; then
    echo "Failed to issue certificate"
    kubectl delete ns "$reconciler_namespace"
    exit 1
fi

echo "Deleting Certificate"
kubectl delete certificate.cert-manager.io/test-clusterissuer-certificate

echo "Deleting ClusterIssuer"
kubectl delete clusterissuers.ejbca-issuer.keyfactor.com/test-cluster-issuer

################
# Issuer Tests #
################

echo "Creating Issuer"
kubectl -n "$reconciler_namespace" apply -f - <<EOF
apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: Issuer
metadata:
  name: test-issuer
spec:
  hostname: "$EJBCA_IN_CLUSTER_HOSTNAME"
  ejbcaSecretName: "ejbca-clusterissuer-secret"
  caBundleSecretName: "ejbca-clusterissuer-ca-secret"
  certificateAuthorityName: "$EJBCA_CA_NAME"
  certificateProfileName: "$EJBCA_CERTIFICATE_PROFILE_NAME"
  endEntityProfileName: "$EJBCA_END_ENTITY_PROFILE_NAME"
  endEntityName: "ejbca-issuer-sample"
EOF

echo "Waiting for Issuer to be ready"
if ! kubectl -n "$reconciler_namespace" wait --for=condition=ready Issuer.ejbca-issuer.keyfactor.com/test-issuer --timeout=30s ; then
    echo "Failed to create Issuer"
    kubectl delete ns "$reconciler_namespace"
    exit 1
fi

kubectl -n "$reconciler_namespace" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-issuer-certificate
  annotations:
    ejbca-issuer.keyfactor.com/endEntityName: "dns"
    ejbca-issuer.keyfactor.com/certificateAuthorityName: "$EJBCA_CA_NAME"
    ejbca-issuer.keyfactor.com/certificateProfileName: "$EJBCA_CERTIFICATE_PROFILE_NAME"
    ejbca-issuer.keyfactor.com/endEntityProfileName: "$EJBCA_END_ENTITY_PROFILE_NAME"
spec:
  secretName: ejbca-certificate-secret
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: test-issuer
    group: ejbca-issuer.keyfactor.com
    kind: Issuer
EOF

echo "Waiting 10 seconds for CertificateRequest"
sleep 10

echo "Approving all CertificateRequests"
kubectl -n "$reconciler_namespace" get certificaterequest.cert-manager.io -o json | jq -r '.items[].metadata.name' | xargs -I {} cmctl -n "$reconciler_namespace" approve {}

echo "Waiting for certificate issuance"
if ! kubectl -n "$reconciler_namespace" wait --for=condition=Ready certificate.cert-manager.io/test-issuer-certificate --timeout=30s ; then
    echo "Failed to issue certificate"
    kubectl delete ns "$reconciler_namespace"
    exit 1
fi

echo "Deleting Certificate"
kubectl -n "$reconciler_namespace" delete certificate.cert-manager.io/test-issuer-certificate

echo "Deleting Issuer"
kubectl -n "$reconciler_namespace" delete issuers.ejbca-issuer.keyfactor.com/test-issuer

echo "Deleting $reconciler_chart_name Helm release"
helm delete "$reconciler_chart_name" -n "$reconciler_namespace"

echo "Deleting $reconciler_namespace namespace"
kubectl delete ns "$reconciler_namespace"
