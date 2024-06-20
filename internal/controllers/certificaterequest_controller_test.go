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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
	"github.com/Keyfactor/ejbca-issuer/internal/ejbca"
)

var (
	fixedClock = clock.RealClock{}
)

type fakeSigner struct {
	errSign error
}

func (o *fakeSigner) Sign(context.Context, []byte) ([]byte, []byte, error) {
	return []byte("fake signed certificate"), []byte("fake chain"), o.errSign
}

var newFakeSignerBuilder = func(builderErr error, signerErr error) func(context.Context, ...ejbca.Option) (ejbca.Signer, error) {
	return func(context.Context, ...ejbca.Option) (ejbca.Signer, error) {
		return &fakeSigner{
			errSign: signerErr,
		}, builderErr
	}
}

func TestCertificateRequestReconcile(t *testing.T) {
	caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	// caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	// serverCert, _ := issueTestCertificate(t, "Server", caCert, rootKey)
	// serverCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	// caChain := append(serverCertPem, caCertPem...)

	authCert, authKey := issueTestCertificate(t, "Auth", caCert, rootKey)
	keyByte, err := x509.MarshalECPrivateKey(authKey)
	require.NoError(t, err)
	authCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authCert.Raw})
	authKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyByte})

	type testCase struct {
		name          types.NamespacedName
		signerBuilder ejbca.SignerBuilder

		// Configuration
		objects                  []client.Object
		clusterResourceNamespace string

		// Expected
		expectedResult               ctrl.Result
		expectedErrorMessagePrefix   string
		expectedReadyConditionStatus cmmeta.ConditionStatus
		expectedReadyConditionReason string
		expectedCertificate          []byte
	}
	tests := map[string]testCase{
		"success-issuer-mtls": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.TLSCertKey:       authCertPem,
						corev1.TLSPrivateKeyKey: authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(nil, nil),
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"success-cluster-issuer-mtls": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "clusterissuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clusterissuer1-credentials",
						Namespace: "kube-system",
					},
					Data: map[string][]byte{
						corev1.TLSCertKey:       authCertPem,
						corev1.TLSPrivateKeyKey: authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(nil, nil),
			clusterResourceNamespace:     "kube-system",
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"success-issuer-oauth": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"tokenUrl":     authCertPem,
						"clientId":     authKeyPem,
						"clientSecret": authKeyPem,
						"scopes":       authKeyPem,
						"audience":     authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(nil, nil),
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"success-cluster-issuer-oauth": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "clusterissuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clusterissuer1-credentials",
						Namespace: "kube-system",
					},
					Data: map[string][]byte{
						"tokenUrl":     authCertPem,
						"clientId":     authKeyPem,
						"clientSecret": authKeyPem,
						"scopes":       authKeyPem,
						"audience":     authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(nil, nil),
			clusterResourceNamespace:     "kube-system",
			expectedReadyConditionStatus: cmmeta.ConditionTrue,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonIssued,
			expectedCertificate:          []byte("fake signed certificate"),
		},
		"certificaterequest-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
		},
		"issuer-ref-foreign-group": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: "foreign-issuer.example.com",
					}),
				),
			},
		},
		"certificaterequest-already-ready": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
		},
		"certificaterequest-missing-ready-condition": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
				),
			},
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-ref-unknown-kind": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "ForeignKind",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonFailed,
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedErrorMessagePrefix:   errGetIssuer.Error(),
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"clusterissuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "clusterissuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "ClusterIssuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
			},
			expectedErrorMessagePrefix:   errGetIssuer.Error(),
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-not-ready": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionFalse,
							},
						},
					},
				},
			},
			expectedErrorMessagePrefix:   errIssuerNotReady.Error(),
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"issuer-secret-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
			},
			expectedErrorMessagePrefix:   errGetAuthSecret.Error(),
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-builder-error": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.TLSCertKey:       authCertPem,
						corev1.TLSPrivateKeyKey: authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(errors.New("simulated signer builder error"), nil),
			expectedErrorMessagePrefix:   errSignerBuilder.Error(),
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"signer-error": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionApproved,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.TLSCertKey:       authCertPem,
						corev1.TLSPrivateKeyKey: authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(nil, errors.New("simulated sign error")),
			expectedErrorMessagePrefix:   errSignerSign.Error(),
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonPending,
		},
		"request-not-approved": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.TLSCertKey:       authCertPem,
						corev1.TLSPrivateKeyKey: authKeyPem,
					},
				},
			},
			signerBuilder:       newFakeSignerBuilder(nil, nil),
			expectedCertificate: nil,
		},
		"request-denied": {
			name: types.NamespacedName{Namespace: "ns1", Name: "cr1"},
			objects: []client.Object{
				cmgen.CertificateRequest(
					"cr1",
					cmgen.SetCertificateRequestNamespace("ns1"),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "issuer1",
						Group: ejbcaissuer.GroupVersion.Group,
						Kind:  "Issuer",
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionDenied,
						Status: cmmeta.ConditionTrue,
					}),
					cmgen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:   cmapi.CertificateRequestConditionReady,
						Status: cmmeta.ConditionUnknown,
					}),
				),
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuer.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuer.IssuerStatus{
						Conditions: []ejbcaissuer.IssuerCondition{
							{
								Type:   ejbcaissuer.IssuerConditionReady,
								Status: ejbcaissuer.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.TLSCertKey:       authCertPem,
						corev1.TLSPrivateKeyKey: authKeyPem,
					},
				},
			},
			signerBuilder:                newFakeSignerBuilder(nil, nil),
			expectedCertificate:          nil,
			expectedReadyConditionStatus: cmmeta.ConditionFalse,
			expectedReadyConditionReason: cmapi.CertificateRequestReasonDenied,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ejbcaissuer.AddToScheme(scheme))
	require.NoError(t, cmapi.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				WithStatusSubresource(tc.objects...).
				Build()
			controller := CertificateRequestReconciler{
				Client:                            fakeClient,
				ConfigClient:                      NewFakeConfigClient(fakeClient),
				Scheme:                            scheme,
				ClusterResourceNamespace:          tc.clusterResourceNamespace,
				SignerBuilder:                     tc.signerBuilder,
				CheckApprovedCondition:            true,
				Clock:                             fixedClock,
				SecretAccessGrantedAtClusterLevel: true,
			}
			if tc.expectedErrorMessagePrefix != "" {
				t.Logf("test %s - expected error: %s", name, tc.expectedErrorMessagePrefix)
			} else {
				t.Logf("test %s - expected error: nil", name)
			}
			result, err := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t)),
				reconcile.Request{NamespacedName: tc.name},
			)
			if tc.expectedErrorMessagePrefix != "" {
				require.True(t, strings.HasPrefix(err.Error(), tc.expectedErrorMessagePrefix))
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			var cr cmapi.CertificateRequest
			err = fakeClient.Get(context.TODO(), tc.name, &cr)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
			if err == nil {
				if tc.expectedReadyConditionStatus != "" {
					assertCertificateRequestHasReadyCondition(t, tc.expectedReadyConditionStatus, tc.expectedReadyConditionReason, &cr)
				}
				assert.Equal(t, tc.expectedCertificate, cr.Status.Certificate)
			}
		})
	}
}

func assertErrorIs(t *testing.T, expectedError, actualError error) {
	if !assert.Error(t, actualError) {
		return
	}
	assert.Truef(t, errors.Is(actualError, expectedError), "unexpected error type. expected: %v, got: %v", expectedError, actualError)
}

func assertCertificateRequestHasReadyCondition(t *testing.T, status cmmeta.ConditionStatus, reason string, cr *cmapi.CertificateRequest) {
	condition := cmutil.GetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady)
	if !assert.NotNil(t, condition, "Ready condition not found") {
		return
	}
	assert.Equal(t, status, condition.Status, "unexpected condition status")
	validReasons := sets.NewString(
		cmapi.CertificateRequestReasonPending,
		cmapi.CertificateRequestReasonFailed,
		cmapi.CertificateRequestReasonIssued,
		cmapi.CertificateRequestReasonDenied,
	)
	assert.Contains(t, validReasons, reason, "unexpected condition reason")
	assert.Equal(t, reason, condition.Reason, "unexpected condition reason")
}

func issueTestCertificate(t *testing.T, cn string, parent *x509.Certificate, signingKey any) (*x509.Certificate, *ecdsa.PrivateKey) {
	var err error
	var key *ecdsa.PrivateKey
	now := time.Now()

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey := &key.PublicKey
	signerPrivateKey := key
	if signingKey != nil {
		signerPrivateKey = signingKey.(*ecdsa.PrivateKey)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1337))
	certTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		SerialNumber:          serial,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
	}

	if parent == nil {
		parent = certTemplate
	}

	certData, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, publicKey, signerPrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certData)
	require.NoError(t, err)

	return cert, key
}
