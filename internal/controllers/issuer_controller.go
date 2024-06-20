/*
Copyright 2023 Keyfactor.

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
	"time"

	"github.com/Keyfactor/ejbca-issuer/internal/ejbca"
	issuerutil "github.com/Keyfactor/ejbca-issuer/internal/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	issuerReadyConditionReason = "ejbca-issuer.IssuerController.Reconcile"
	defaultHealthCheckInterval = time.Minute
)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing credentials")
	errGetCaSecret          = errors.New("caSecretName specified a name, but failed to get Secret containing CA certificate")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	ConfigClient                      issuerutil.ConfigClient
	Kind                              string
	Scheme                            *runtime.Scheme
	ClusterResourceNamespace          string
	HealthCheckerBuilder              ejbca.HealthCheckerBuilder
	SecretAccessGrantedAtClusterLevel bool
}

//+kubebuilder:rbac:groups=ejbca-issuer.keyfactor.com,resources=issuers;clusterissuers,verbs=get;list;watch
//+kubebuilder:rbac:groups=ejbca-issuer.keyfactor.com,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ejbca-issuer.keyfactor.com,resources=issuers/finalizers,verbs=update

// newIssuer returns a new Issuer or ClusterIssuer object
func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := ejbcaissuer.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// Reconcile reconciles and updates the status of an Issuer or ClusterIssuer object
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognized issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %w", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	name, err := issuerutil.GetName(issuer)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			issuerutil.SetIssuerReadyCondition(ctx, name, r.Kind, issuerStatus, ejbcaissuer.ConditionFalse, issuerReadyConditionReason, err.Error())
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := issuerutil.GetReadyCondition(issuerStatus); ready == nil {
		issuerutil.SetIssuerReadyCondition(ctx, name, r.Kind, issuerStatus, ejbcaissuer.ConditionUnknown, issuerReadyConditionReason, "First seen")
		return ctrl.Result{}, nil
	}

	secretName := types.NamespacedName{
		Name: issuerSpec.EjbcaSecretName,
	}

	switch issuer.(type) {
	case *ejbcaissuer.Issuer:
		secretName.Namespace = req.Namespace
	case *ejbcaissuer.ClusterIssuer:
		secretName.Namespace = r.ClusterResourceNamespace
	default:
		log.Error(fmt.Errorf("unexpected issuer type: %t", issuer), "Not retrying.")
		return ctrl.Result{}, nil
	}

	// If SecretAccessGrantedAtClusterLevel is false, we always look for the Secret in the same namespace as the Issuer
	if !r.SecretAccessGrantedAtClusterLevel {
		secretName.Namespace = r.ClusterResourceNamespace
	}

	// Set the context on the config client
	r.ConfigClient.SetContext(ctx)

	// Retrieve the CA certificate secret
	caSecretName := types.NamespacedName{
		Name:      issuerSpec.CaBundleSecretName,
		Namespace: secretName.Namespace,
	}

	var caSecret corev1.Secret
	if issuerSpec.CaBundleSecretName != "" {
		// If the CA secret name is not specified, we will not attempt to retrieve it
		err = r.ConfigClient.GetSecret(caSecretName, &caSecret)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %w", errGetCaSecret, caSecretName, err)
		}
	}

	var authSecret corev1.Secret
	if err := r.ConfigClient.GetSecret(secretName, &authSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %w", errGetAuthSecret, secretName, err)
	}

	var authOpt ejbca.Option
	switch {
	case authSecret.Type == corev1.SecretTypeTLS:
		cert, ok := authSecret.Data[corev1.TLSCertKey]
		if !ok {
			return ctrl.Result{}, fmt.Errorf("%w: %v", errGetAuthSecret, "found TLS secret with no certificate")
		}
		key, ok := authSecret.Data[corev1.TLSPrivateKeyKey]
		if !ok {
			return ctrl.Result{}, fmt.Errorf("%w: %v", errGetAuthSecret, "found TLS secret with no private key")
		}
		authOpt = ejbca.WithClientCert(&ejbca.CertAuth{
			ClientCert: cert,
			ClientKey:  key,
		})
	case authSecret.Type == corev1.SecretTypeOpaque:
		// We expect auth credentials for a client credential OAuth2.0 flow if the secret type is opaque
		tokenURL, ok := authSecret.Data["tokenUrl"]
		if !ok {
			return ctrl.Result{}, fmt.Errorf("%w: %v", errGetAuthSecret, "found secret with no tokenUrl")
		}
		clientID, ok := authSecret.Data["clientId"]
		if !ok {
			return ctrl.Result{}, fmt.Errorf("%w: %v", errGetAuthSecret, "found secret with no clientId")
		}
		clientSecret, ok := authSecret.Data["clientSecret"]
		if !ok {
			return ctrl.Result{}, fmt.Errorf("%w: %v", errGetAuthSecret, "found secret with no clientSecret")
		}
		oauth := &ejbca.OAuth{
			TokenURL:     string(tokenURL),
			ClientID:     string(clientID),
			ClientSecret: string(clientSecret),
		}
		scopes, ok := authSecret.Data["scopes"]
		if ok {
			oauth.Scopes = string(scopes)
		}
		audience, ok := authSecret.Data["audience"]
		if ok {
			oauth.Audience = string(audience)
		}
		authOpt = ejbca.WithOAuth(oauth)
	default:
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetAuthSecret, "found secret with unsupported type")
	}

	var caCertBytes []byte
	// There is no requirement that the CA certificate is stored under a specific
	// key in the secret, so we can just iterate over the map and effectively select
	// the last value in the map
	for _, bytes := range caSecret.Data {
		caCertBytes = bytes
	}

	checker, err := r.HealthCheckerBuilder(ctx,
		ejbca.WithHostname(issuerSpec.Hostname),
		ejbca.WithCACerts(caCertBytes),
		authOpt,
		ejbca.WithEndEntityProfileName(issuerSpec.EndEntityProfileName),
		ejbca.WithCertificateProfileName(issuerSpec.CertificateProfileName),
		ejbca.WithCertificateAuthority(issuerSpec.CertificateAuthorityName),
		ejbca.WithEndEntityName(issuerSpec.EndEntityName),
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerBuilder, err)
	}

	if err := checker.Check(); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerCheck, err)
	}

	issuerutil.SetIssuerReadyCondition(ctx, name, r.Kind, issuerStatus, ejbcaissuer.ConditionTrue, issuerReadyConditionReason, "Success")
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// SetupWithManager registers the IssuerReconciler with the controller manager.
// It configures controller-runtime to reconcile Keyfactor EJBCA Issuers/ClusterIssuers in the cluster.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}
