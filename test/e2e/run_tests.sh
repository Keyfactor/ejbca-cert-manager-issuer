#!/bin/bash

## =======================   LICENSE     ===================================
# Copyright © 2025 Keyfactor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## ==========================================================================

## ======================= Description ===================================

# This script automates the deployment of the ejbca-cert-manager-issuer
# and runs end-to-end tests to validate its functionality.
# This script is intended for use in a Minikube environment.
# This script can be run multiple times to test various scenarios.

## =======================================================================

## ======================= How to run ===================================
# Enable the script to run:
# > chmod +x run_tests.sh
# Load the environment variables:
# > source .env
# Run the tests:
# > ./run_tests.sh
## ===========================================================================

IMAGE_REPO="keyfactor"
IMAGE_NAME="ejbca-cert-manager-issuer"
# IMAGE_TAG="2.1.0"
IMAGE_TAG="local" # Uncomment if you want to build the image locally
FULL_IMAGE_NAME="${IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}"

HELM_CHART_NAME="ejbca-cert-manager-issuer"
# HELM_CHART_VERSION="2.1.0" # Uncomment if you want to use a specific version from the Helm repository
HELM_CHART_VERSION="local" # Uncomment if you want to use the local Helm chart

IS_LOCAL_DEPLOYMENT=$([ "$IMAGE_TAG" = "local" ] && echo "true" || echo "false")
IS_LOCAL_HELM=$([ "$HELM_CHART_VERSION" = "local" ] && echo "true" || echo "false")

# TODO: Handle both in the e2e tests
ISSUER_TYPE="Issuer"
CLUSTER_ISSUER_TYPE="ClusterIssuer"

# ISSUER_OR_CLUSTER_ISSUER="ClusterIssuer"
ISSUER_OR_CLUSTER_ISSUER="Issuer"
ISSUER_CR_NAME="issuer"
ISSUER_CRD_FQTN="issuers.ejbca-issuer.keyfactor.com"
CLUSTER_ISSUER_CRD_FQTN="clusterissuers.ejbca-issuer.keyfactor.com"

CHART_PATH="./deploy/charts/ejbca-cert-manager-issuer"

CERT_MANAGER_VERSION="v1.17.0"

MANAGER_NAMESPACE="ejbca-issuer-system"
CERT_MANAGER_NAMESPACE="cert-manager"
ISSUER_NAMESPACE="issuer-playground"

SIGNER_SECRET_NAME="auth-secret"
SIGNER_CA_SECRET_NAME="ca-secret"

CERTIFICATE_CRD_FQTN="certificates.cert-manager.io"
CERTIFICATEREQUEST_CRD_FQTN="certificaterequests.cert-manager.io"

CR_C_NAME="cert"
CR_CR_NAME="cert-1"
CR_C_SECRET_NAME="$CR_C_NAME-tls"

set -e # Exit on any error

# checks if environment variable is available in system. if it is not present but the variable is required
# an error is thrown
validate_env_present() {
    local env_var=$1
    local required=$2
    if [ -z "${!env_var}" ]; then
        if [ "$required" = "false" ]; then
            echo "ℹ️    Optional environment variable $env_var is not set. Continuing..."
            return 0
        fi
        echo "⚠️    Required environment variable $env_var. Please check your .env file or set it in your shell."
        echo "     Run: source .env or export $env_var=<value>"
        exit 1
    fi
}

# checks whether the following environment variables are provided. some environment variables are optional.
check_env() {
    validate_env_present HOSTNAME true

    validate_env_present EJBCA_CA_NAME true
    validate_env_present CERTIFICATE_PROFILE_NAME true
    validate_env_present END_ENTITY_PROFILE_NAME true
    
    validate_env_present OAUTH_TOKEN_URL true
    validate_env_present OAUTH_CLIENT_ID true
    validate_env_present OAUTH_CLIENT_SECRET true
    validate_env_present OAUTH_AUDIENCE false
    validate_env_present OAUTH_SCOPES false
}

# checks whether the provided kubernetes namespace exists
ns_exists () {
    local ns=$1
    if [ "$(kubectl get namespace -o json | jq --arg namespace "$ns" -e '.items[] | select(.metadata.name == $namespace) | .metadata.name')" ]; then
        return 0
    fi
    return 1
}

# checks whether the provided helm chart has been deployed to the cluster (namespaced)
helm_exists () {
    local namespace=$1
    local chart_name=$2
    if helm list -n "$namespace" | grep -q "$chart_name"; then
        return 0
    fi
    return 1
}

# checks whether the provided custom resource can be found in the cluster (namespaced)
cr_exists () {
    local fqtn=$1
    local ns=$2
    local name=$3
    if [ "$(kubectl -n "$ns" get "$fqtn" -o json | jq --arg name "$name" -e '.items[] | select(.metadata.name == $name) | .metadata.name')" ]; then
        echo "$fqtn exists called $name in $ns"
        return 0
    fi
    return 1
}

# checks whether the provided secret name exists in the cluster (namespaced)
secret_exists () {
    local ns=$1
    local name=$2
    if [ "$(kubectl -n "$ns" get secret -o json | jq --arg name "$name" -e '.items[] | select(.metadata.name == $name) | .metadata.name')" ]; then
        echo "secret exists called $name in $ns"
        return 0
    fi
    return 1
}

# installs cert-manager onto the Kubernetes cluster
install_cert_manager() {
    echo "📦 Installing cert-manager..."

    # Add jetstack repository if not already added
    if ! helm repo list | grep -q jetstack; then
        echo "Adding jetstack Helm repository..."
        helm repo add jetstack https://charts.jetstack.io
    fi

    helm repo update

    echo "Installing cert-manager version ${CERT_MANAGER_VERSION}..."

    helm install cert-manager jetstack/cert-manager \
        --namespace ${CERT_MANAGER_NAMESPACE} \
        --create-namespace \
        --version ${CERT_MANAGER_VERSION} \
        --set crds.enabled=true \
        --wait

    echo "✅ cert-manager installed successfully"
}

# installs the issuer to the Kubernetes cluster
install_cert_manager_issuer() {
    echo "📦 Installing instance of $IMAGE_NAME with tag $IMAGE_TAG..."
    
    
    if [[ "$IS_LOCAL_HELM" == "true" ]]; then
        CHART_PATH=$CHART_PATH

        # Checking if chart path exists
        if [ ! -d "$CHART_PATH" ]; then
            echo "⚠️ Chart path not found at ${CHART_PATH}. Are you in the correct directory?"
            exit 1
        fi

        VERSION_PARAM=""
    else

        # Add ejbca-issuer repository if not already added
        if ! helm repo list | grep -q ejbca-issuer; then
            echo "Adding ejbca-issuer Helm repository..."
            helm repo add ejbca-issuer https://keyfactor.github.io/ejbca-cert-manager-issuer
        fi

        CHART_PATH="ejbca-issuer/ejbca-cert-manager-issuer"
        echo "Using Helm chart from repository for version ${HELM_CHART_VERSION}: $CHART_PATH..."
        VERSION_PARAM="--version ${HELM_CHART_VERSION}"
    fi

    # Only set the image repository parameter if we are deploying locally
    if [[ "$IS_LOCAL_DEPLOYMENT" == "true" ]]; then
        IMAGE_REPO_PARAM="--set image.repository=${IMAGE_REPO}/${IMAGE_NAME}"
    else
        IMAGE_REPO_PARAM=""
    fi

    # Only set the pull policy to Never if we are deploying locally
    if [[ "$IS_LOCAL_DEPLOYMENT" == "true" ]]; then
        PULL_POLICY_PARAM="--set image.pullPolicy=Never"
    else
        PULL_POLICY_PARAM=""
    fi
    
    # Helm chart could be out of date for release candidates, so we will install from
    # the chart defined in the repository.
    helm install $IMAGE_NAME ${CHART_PATH} \
        --namespace ${MANAGER_NAMESPACE} \
        $VERSION_PARAM \
        $IMAGE_REPO_PARAM \
        --set "fullnameOverride=${IMAGE_NAME}" \
        --set image.tag=${IMAGE_TAG} \
        $PULL_POLICY_PARAM \
        --wait \
        --timeout 30s
        
    echo "✅ $IMAGE_NAME installed successfully"
}

# performs a redeployment of the cert-manager. helpful for recycling TLS certificates that have expired.
deploy_cert_manager() {
    # Restart all cert-manager components
    kubectl rollout restart deployment/cert-manager -n cert-manager
    kubectl rollout restart deployment/cert-manager-webhook -n cert-manager
    kubectl rollout restart deployment/cert-manager-cainjector -n cert-manager

    # Wait for them to be ready
    kubectl rollout status deployment/cert-manager -n cert-manager
    kubectl rollout status deployment/cert-manager-webhook -n cert-manager
    kubectl rollout status deployment/cert-manager-cainjector -n cert-manager
}

# deploys the issuer to the Kubernetes cluster
deploy_cert_manager_issuer() {
    # Find the deployment name (assuming it follows a pattern)
    DEPLOYMENT_NAME=$(kubectl get deployments -n ${MANAGER_NAMESPACE} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "$IMAGE_NAME")

    # Between runs, we want to make sure that the running issuer has the latest version of the code we want.
    # Doing this patch and redeployment forces the container to restart with the latest desired version
    if kubectl get deployment ${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} >/dev/null 2>&1; then
        # Patch the deployment
        kubectl patch deployment ${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} -p "{
            \"spec\": {
                \"template\": {
                    \"spec\": {
                        \"containers\": [{
                            \"name\": \"${IMAGE_NAME}\",
                            \"image\": \"${FULL_IMAGE_NAME}\",
                            \"imagePullPolicy\": \"Never\"
                        }]
                    }
                }
            }
        }"

        # Rollout deployment changes and apply the patch
        kubectl rollout restart deployment/${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE}
            kubectl rollout status deployment/${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} --timeout=300s


        echo "✅ Deployment patched and rolled out successfully"
    else
        echo "⚠️  Deployment ${DEPLOYMENT_NAME} not found. The Helm chart might use a different naming convention."
        echo "Available deployments in ${MANAGER_NAMESPACE}:"
        kubectl get deployments -n ${MANAGER_NAMESPACE}
    fi

    echo ""
    echo "🎉 Deployment complete!"
    echo ""
}

# check the expiration of the cert-manager TLS certificate
check_cert_manager_webhook_cert() {
    local namespace=${1:-cert-manager}
    local secret_name=${2:-cert-manager-webhook-ca}
    
    echo "🔍 Checking cert-manager webhook certificate..."
    
    # Check if secret exists
    if ! kubectl get secret "$secret_name" -n "$namespace" >/dev/null 2>&1; then
        echo "❌ Secret $secret_name not found in namespace $namespace"
        return 1
    fi
    
    # Get certificate data
    local cert_data=$(kubectl get secret "$secret_name" -n "$namespace" -o jsonpath='{.data.tls\.crt}' 2>/dev/null)
    
    if [ -z "$cert_data" ]; then
        echo "❌ No certificate data found in secret"
        return 1
    fi
    
    # Decode and check certificate
    local cert_info=$(echo "$cert_data" | base64 -d | openssl x509 -noout -dates 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to parse certificate"
        return 1
    fi
    
    echo "📋 Certificate validity:"
    echo "$cert_info"
    
    # Check if certificate is currently valid
    if echo "$cert_data" | base64 -d | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
        echo "✅ Certificate is currently valid"
        
        # Check if expires within 7 days
        if ! echo "$cert_data" | base64 -d | openssl x509 -noout -checkend 604800 >/dev/null 2>&1; then
            echo "⚠️  Certificate expires within 7 days"
            return 2  # Warning status
        fi
        
        return 0  # Valid
    else
        echo "❌ Certificate is expired or not yet valid"
        return 1  # Expired
    fi
}

# creates a new issuer custom resource
create_issuer() {
    echo "🔐 Creating issuer resource..."

    secretJson='{}'
    secretJson=$(echo "$secretJson" | jq --arg version "v1" '.apiVersion = $version')
    secretJson=$(echo "$secretJson" | jq --arg kind "Secret" '.kind = $kind')
    secretJson=$(echo "$secretJson" | jq --arg name "$SIGNER_SECRET_NAME" '.metadata.name = $name')

    # OAuth credentials
    secretJson=$(echo "$secretJson" | jq --arg type "Opaque" '.type = $type')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_TOKEN_URL" '.stringData.tokenUrl = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_ID" '.stringData.clientId = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_SECRET" '.stringData.clientSecret = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_AUDIENCE" '.stringData.audience = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_SCOPES" '.stringData.scopes = $val')

    echo "Creating secret called $SIGNER_SECRET_NAME in namespace $MANAGER_NAMESPACE"
    if ! echo "$secretJson" | yq -P | kubectl -n "$MANAGER_NAMESPACE" apply -f -; then
        echo "Failed to create $SIGNER_SECRET_NAME"
        return 1
    fi

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: Issuer
metadata:
  name: "$ISSUER_CR_NAME"
spec:
  hostname: "$HOSTNAME"
  ejbcaSecretName: "$SIGNER_SECRET_NAME"
  
  certificateAuthorityName: "$EJBCA_CA_NAME"
  certificateProfileName: "$CERTIFICATE_PROFILE_NAME"
  endEntityProfileName: "$END_ENTITY_PROFILE_NAME"

  endEntityName: ""
EOF


    echo "✅ Issuer resources created successfully"
}

# creates a new cluster issuer custom resource
create_cluster_issuer() {
    echo "🔐 Creating cluster issuer resource..."

    secretJson='{}'
    secretJson=$(echo "$secretJson" | jq --arg version "v1" '.apiVersion = $version')
    secretJson=$(echo "$secretJson" | jq --arg kind "Secret" '.kind = $kind')
    secretJson=$(echo "$secretJson" | jq --arg name "$SIGNER_SECRET_NAME" '.metadata.name = $name')

    # OAuth credentials
    secretJson=$(echo "$secretJson" | jq --arg type "Opaque" '.type = $type')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_TOKEN_URL" '.stringData.tokenUrl = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_ID" '.stringData.clientId = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_SECRET" '.stringData.clientSecret = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_AUDIENCE" '.stringData.audience = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_SCOPES" '.stringData.scopes = $val')

    echo "Creating secret called $SIGNER_SECRET_NAME in namespace $MANAGER_NAMESPACE"
    if ! echo "$secretJson" | yq -P | kubectl -n "$MANAGER_NAMESPACE" apply -f -; then
        echo "Failed to create $SIGNER_SECRET_NAME"
        return 1
    fi

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: ejbca-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata:
  name: "$ISSUER_CR_NAME"
spec:
  hostname: "$HOSTNAME"
  ejbcaSecretName: "$SIGNER_SECRET_NAME"
  
  certificateAuthorityName: "$EJBCA_CA_NAME"
  certificateProfileName: "$CERTIFICATE_PROFILE_NAME"
  endEntityProfileName: "$END_ENTITY_PROFILE_NAME"

  endEntityName: ""
EOF


    echo "✅ Issuer resources created successfully"
}

# deletes Issuer and ClusterIssuer custom resources from the Kubernetes cluster
delete_issuers() {
    echo "🗑️ Deleting issuer resources..."

    if cr_exists "$ISSUER_CRD_FQTN" "$ISSUER_NAMESPACE" "$ISSUER_CR_NAME"; then
        echo "Deleting Issuer $ISSUER_CRD_FQTN called $ISSUER_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete "$ISSUER_CRD_FQTN" "$ISSUER_CR_NAME"
    fi
    if cr_exists "$CLUSTER_ISSUER_CRD_FQTN" "$ISSUER_NAMESPACE" "$ISSUER_CR_NAME"; then
        echo "Deleting ClusterIssuer $CLUSTER_ISSUER_CRD_FQTN called $ISSUER_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete "$CLUSTER_ISSUER_CRD_FQTN" "$ISSUER_CR_NAME"
    fi
    if secret_exists "$MANAGER_NAMESPACE" "$SIGNER_SECRET_NAME" ; then
        echo "Deleting authentication secret called $SIGNER_SECRET_NAME"
        kubectl -n "$MANAGER_NAMESPACE" delete secret "$SIGNER_SECRET_NAME"
    fi
    if secret_exists "$MANAGER_NAMESPACE" "$SIGNER_CA_SECRET_NAME" ; then
        echo "Deleting CA secret called $SIGNER_CA_SECRET_NAME"
        kubectl -n "$MANAGER_NAMESPACE" delete secret "$SIGNER_CA_SECRET_NAME"
    fi

    echo "✅ Issuer resources deleted successfully"
}

# creates a Certificate custom resource. this is picked up by cert-manager and converted to a CertificateRequest.
create_certificate() {
    local issuer_type=$1

    echo "Generating a certificate object for issuer type: $issuer_type"

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: $CR_C_NAME
spec:
  secretName: ${CR_C_SECRET_NAME}  # Where the Secret will be created
  commonName: example.com
  usages:
    - signing
    - digital signature
    - server auth
    # 90 days
  duration: 2160h
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    name: $ISSUER_CR_NAME
    group: ejbca-issuer.keyfactor.com
    kind: $issuer_type
EOF
}

# deletes the Certificate custom resource
delete_certificate() {
    echo "🗑️ Deleting certificate..."

    if cr_exists $CERTIFICATE_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_C_NAME"; then
        echo "Deleting Certificate called $CR_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete certificate "$CR_C_NAME"
    else
        echo "⚠️ Certificate $CR_CR_NAME not found in $ISSUER_NAMESPACE"
    fi
}

# deletes the Secret associated with the Certificate resource
delete_certificate_secret() {
    echo "🗑️ Deleting certificate secret $CR_C_SECRET_NAME..."

    if secret_exists "$ISSUER_NAMESPACE" "$CR_C_SECRET_NAME"; then
        kubectl -n "$ISSUER_NAMESPACE" delete secret "$CR_C_SECRET_NAME"
    else
        echo "⚠️ Certificate secret $CR_C_SECRET_NAME not found in $ISSUER_NAMESPACE"
    fi
}

# deletes the CertificateRequest custom resource
delete_certificate_request() {
    echo "🗑️ Deleting certificate request..."

    if cr_exists $CERTIFICATEREQUEST_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_CR_NAME"; then
        echo "Deleting CertificateRequest called $CR_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete certificaterequest "$CR_CR_NAME"
    else
        echo "⚠️ CertificateRequest $CR_CR_NAME not found in $ISSUER_NAMESPACE"
    fi

    echo "✅ Certificate request deleted successfully"
}

regenerate_certificate() {
    local issuer_type=$1
    delete_certificate_secret # delete existing certificate secret so that a new CertificateRequest can be generated
    delete_certificate_request # delete stale CertificateRequest resource
    delete_certificate # delete stale Certificate resource
    create_certificate $issuer_type
}

# cert-manager will take care of generating a CertificateRequest resource from the Certificate resource.
# This does take a few seconds to complete
wait_for_certificate_request() {
    local timeout=30

    echo "🕰️ Waiting for certificate request to exist..."

    local end_time=$(($(date +%s) + timeout))

    while [ $(date +%s) -lt $end_time ]; do
        local cr_count=$(kubectl -n issuer-playground get certificaterequests -o json | \
            jq -r '.items[] | .metadata.name' | wc -l)

        cr_count=$(echo "$cr_count" | tr -d ' ')

        if [ "$cr_count" -gt 0 ]; then
            echo "✅ CertificateRequest created"
            return 0
        fi

        sleep 2
    done

    echo "❌ No CertificateRequest found for Certificate '$CR_C_NAME' within ${timeout}s"
    return 1
}

# approve the CertificateRequest so that the issuer can perform work on the resource
approve_certificate_request() {
    echo "🔍 Approving certificate request..."

    if cr_exists $CERTIFICATEREQUEST_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_CR_NAME"; then
        cmctl -n $ISSUER_NAMESPACE approve $CR_CR_NAME
        echo "Certificate request approved successfully."
    else
        echo "⚠️ CertificateRequest $CR_CR_NAME not found in $ISSUER_NAMESPACE"
    fi
}

# If the issuer issues the certificate, the CertificateRequest resource will have its Ready property set to True
check_certificate_request_status() {
    echo "🔎 Checking certificate request status..."

    if [[ ! $(kubectl wait --for=condition=Ready certificaterequest/$CR_CR_NAME -n $ISSUER_NAMESPACE --timeout=30s) ]]; then
        echo "⚠️  Certificate request did not become ready within the timeout period."
        echo "Check the Issuer / ClusterIssuer logs for errors. Check the configuration of your Issuer or CertificateRequest resources."
        echo "🚫 Test failed"
        exit 1
    fi

    echo "✅ Certificate request was issued successfully."
}

check_for_certificate_secret() {
    echo "🔎 Checking to see if certificate secret was created..."

    if secret_exists "$ISSUER_NAMESPACE" "$CR_C_SECRET_NAME"; then
        echo "✅ Certificate secret $CR_C_SECRET_NAME was found in $ISSUER_NAMESPACE"
        return 0
    fi

    echo "🚫 Certificate secret $CR_C_SECRET_NAME not found in $ISSUER_NAMESPACE. Test failed."
    exit 1
}

annotate_certificate_request() {
    local annotation_key=$1
    local annotation_value=$2

    echo "Annotating certificate request with $annotation_key: $annotation_value"

    kubectl -n "$ISSUER_NAMESPACE" annotate certificaterequest/$CR_CR_NAME "$annotation_key"="$annotation_value" --overwrite

    if [ $? -ne 0 ]; then
        echo "⚠️ Failed to annotate certificate request with $annotation_key"
        return 1
    fi

    echo "✅ Certificate request annotated successfully."
}

regenerate_issuer() {
    echo "🔄 Regenerating issuer..."
    delete_issuers
    create_issuer

    # Run health check on issuer
    echo "🔍 Checking issuer health..."
    kubectl -n ${ISSUER_NAMESPACE} wait --for=condition=Ready $ISSUER_CRD_FQTN/$ISSUER_CR_NAME --timeout=60s
    echo "✅ Issuer is healthy and ready for requests."
}

regenerate_cluster_issuer() {
    echo "🔄 Regenerating cluster issuer..."
    delete_issuers
    create_cluster_issuer

    # Run health check on issuer
    echo "🔍 Checking cluster issuer health..."
    kubectl -n ${ISSUER_NAMESPACE} wait --for=condition=Ready $CLUSTER_ISSUER_CRD_FQTN/$ISSUER_CR_NAME --timeout=60s
    echo "✅ ClusterIssuer is healthy and ready for requests."
}

# ================= BEGIN: Resource Deployment =====================

check_env

# Move the execution environment to the parent directory
cd ../..

echo "⚙️ Local image deployment: ${IS_LOCAL_DEPLOYMENT}"
echo "⚙️ Local Helm chart: ${IS_LOCAL_HELM}"

if ! minikube status &> /dev/null; then
    echo "Error: Minikube is not running. Please start it with 'minikube start'"
    exit 1
fi

kubectl config use-context minikube
echo "Connected to Kubernetes context: $(kubectl config current-context)."

# 1. Connect to minikube Docker env
echo "📡 Connecting to Minikube Docker environment..."
eval $(minikube docker-env)
echo "🚀 Starting deployment to Minikube..."

# 2. Deploy cert-manager Helm chart if not exists
echo "🔐 Checking for cert-manager installation..."
if ! helm_exists $CERT_MANAGER_NAMESPACE cert-manager; then
    install_cert_manager
else
    echo "✅ cert-manager already installed"
fi

# 2a. If cert-manager webhook certificate is out of date, redeploy it to update the certificate.
check_cert_manager_webhook_cert || deploy_cert_manager

# 3. Create ejbca-cert-manager-issuer namespace if it doesn't exist
kubectl create namespace ${MANAGER_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# 4. Build the ejbca-cert-manager-issuer Docker image
# This step is only needed if the image tag is "local"
if [ "$IS_LOCAL_DEPLOYMENT" = "true" ]; then
    echo "🐳 Building ${FULL_IMAGE_NAME} Docker image..."
    docker build -t ${FULL_IMAGE_NAME} .
    echo "✅ Docker image built successfully"

    echo "📦 Listing Docker images..."
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}" | head -5
fi

# 5. Deploy the ejbca-cert-manager-issuer Helm chart if not exists
echo "🎛️  Checking for $IMAGE_NAME installation..."

# Check if the helm release exists. If so, destroy it. This ensures our Helm chart is always up to date.
if helm_exists $MANAGER_NAMESPACE $IMAGE_NAME; then
    echo "💣 Uninstalling $IMAGE_NAME..."
    helm uninstall $IMAGE_NAME -n ${MANAGER_NAMESPACE}
fi

install_cert_manager_issuer
deploy_cert_manager_issuer

# Delete stray CertificateRequest resources from previous runs
delete_certificate_request
echo ""

# Deploy Issuer
echo "🔐 Deploying $ISSUER_NAMESPACE namespace if not exists..."
kubectl create namespace ${ISSUER_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
regenerate_issuer
echo "✅ $ISSUER_NAMESPACE namespace is ready"
echo ""

echo ""
echo "✅ Resource deployment completed. Ready to start running tests!"
# ================= END: Resource Deployment =====================
#
#
#
#
#
#
#
#
# ================= BEGIN: Test Execution ========================
echo "🚀 Running E2E tests..."
echo ""

## ===================  BEGIN: Issuer & ClusterIssuer Tests    ============================

echo "🧪💬 Test 1: A generated certificate request should be successfully issued by Issuer."
regenerate_issuer
regenerate_certificate Issuer
wait_for_certificate_request
approve_certificate_request
check_certificate_request_status
check_for_certificate_secret
echo "🧪✅ Test 1 completed successfully."
echo ""

echo "🧪💬 Test 2: A generated certificate request should be successfully issued by ClusterIssuer."
regenerate_cluster_issuer
regenerate_certificate ClusterIssuer
wait_for_certificate_request
approve_certificate_request
check_certificate_request_status
check_for_certificate_secret
echo "🧪✅ Test 2 completed successfully."
echo ""


# ================= END: Test Execution ========================