/*
Copyright © 2023 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"

	"github.com/Keyfactor/ejbca-issuer/internal/issuer/signer"
	issuerutil "github.com/Keyfactor/ejbca-issuer/internal/issuer/util"
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSignerBuilder  = errors.New("failed to build the signer")
	errSignerSign     = errors.New("failed to sign")
)

type CertificateRequestReconciler struct {
	client.Client
	ConfigClient             issuerutil.ConfigClient
	Scheme                   *runtime.Scheme
	SignerBuilder            signer.EjbcaSignerBuilder
	ClusterResourceNamespace string

	Clock                             clock.Clock
	CheckApprovedCondition            bool
	SecretAccessGrantedAtClusterLevel bool
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile attempts to sign a CertificateRequest given the configuration provided and a configured
// EJBCA signer instance.
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	// Get the CertificateRequest
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequests if issuerRef doesn't match group
	if certificateRequest.Spec.IssuerRef.Group != ejbcaissuer.GroupVersion.Group {
		log.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest is Failed. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied yet. Marking as failed.")

		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
		return ctrl.Result{}, nil
	}

	if r.CheckApprovedCondition {
		// If CertificateRequest has not been approved, exit early.
		if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
			log.Info("CertificateRequest has not been approved yet. Ignoring.")
			return ctrl.Result{}, nil
		}
	}

	// Add a Ready condition if one does not already exist
	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		log.Info("Initializing Ready condition")
		issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Initializing")
		return ctrl.Result{}, nil
	}

	// Ignore but log an error if the issuerRef.Kind is Unrecognized
	issuerGVK := ejbcaissuer.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		err = fmt.Errorf("%w: %v", errIssuerRef, err)
		log.Error(err, "Unrecognized kind. Ignoring.")
		issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}
	var secretNamespace string
	switch t := issuer.(type) {
	case *ejbcaissuer.Issuer:
		issuerName.Namespace = certificateRequest.Namespace
		secretNamespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuerName)
	case *ejbcaissuer.ClusterIssuer:
		secretNamespace = r.ClusterResourceNamespace
		log = log.WithValues("clusterissuer", issuerName)
	default:
		err := fmt.Errorf("unexpected issuer type: %v", t)
		log.Error(err, "The issuerRef referred to a registered Kind which is not yet handled. Ignoring.")
		issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}

	// If SecretAccessGrantedAtClusterLevel is false, we always look for the Secret in the same namespace as the Issuer
	if !r.SecretAccessGrantedAtClusterLevel {
		secretNamespace = r.ClusterResourceNamespace
	}

	// Get the Issuer or ClusterIssuer
	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unable to get the IssuerStatus. Ignoring.")
		issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}

	if !issuerutil.IsReady(issuerStatus) {
		return ctrl.Result{}, errIssuerNotReady
	}

	// Set the context on the config client
	r.ConfigClient.SetContext(ctx)

	// Retrieve the auth secret
	authSecretName := types.NamespacedName{
		Name:      issuerSpec.EjbcaSecretName,
		Namespace: secretNamespace,
	}

	var authSecret corev1.Secret
	if err := r.ConfigClient.GetSecret(authSecretName, &authSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, authSecret name: %s, reason: %v", errGetAuthSecret, authSecretName, err)
	}

	// Retrieve the CA certificate secret
	caSecretName := types.NamespacedName{
		Name:      issuerSpec.CaBundleSecretName,
		Namespace: secretNamespace,
	}

	var caSecret corev1.Secret
	if issuerSpec.CaBundleSecretName != "" {
		// If the CA secret name is not specified, we will not attempt to retrieve it
		err = r.ConfigClient.GetSecret(caSecretName, &caSecret)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetCaSecret, caSecretName, err)
		}
	}

	ejbcaSigner, err := r.SignerBuilder(ctx, issuerSpec, certificateRequest.GetAnnotations(), authSecret.Data, caSecret.Data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	chain, ca, err := ejbcaSigner.Sign(ctx, certificateRequest.Spec.Request)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}
	certificateRequest.Status.Certificate = chain
	certificateRequest.Status.CA = ca

	issuerutil.SetCertificateRequestReadyCondition(ctx, &certificateRequest, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Signed")
	return ctrl.Result{}, nil
}

// SetupWithManager registers the CertificateRequestReconciler with the controller manager.
// It configures controller-runtime to reconcile cert-manager CertificateRequests in the cluster.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
