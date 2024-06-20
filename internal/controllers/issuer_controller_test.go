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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/Keyfactor/ejbca-issuer/internal/ejbca"
	issuerutil "github.com/Keyfactor/ejbca-issuer/internal/util"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
)

type fakeHealthChecker struct {
	errCheck error
}

func (o *fakeHealthChecker) Check() error {
	return o.errCheck
}

var newFakeHealthCheckerBuilder = func(builderErr error, checkerErr error) func(context.Context, ...ejbca.Option) (ejbca.HealthChecker, error) {
	return func(context.Context, ...ejbca.Option) (ejbca.HealthChecker, error) {
		return &fakeHealthChecker{
			errCheck: checkerErr,
		}, builderErr
	}
}

func TestIssuerReconcile(t *testing.T) {
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
		kind                         string
		name                         types.NamespacedName
		objects                      []client.Object
		healthCheckerBuilder         ejbca.HealthCheckerBuilder
		clusterResourceNamespace     string
		expectedResult               ctrl.Result
		expectedError                error
		expectedReadyConditionStatus ejbcaissuer.ConditionStatus
	}

	tests := map[string]testCase{
		"success-issuer": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
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
								Status: ejbcaissuer.ConditionUnknown,
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
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, nil),
			expectedReadyConditionStatus: ejbcaissuer.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"success-clusterissuer": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
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
								Status: ejbcaissuer.ConditionUnknown,
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
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, nil),
			clusterResourceNamespace:     "kube-system",
			expectedReadyConditionStatus: ejbcaissuer.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-kind-Unrecognized": {
			kind: "UnrecognizedType",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-missing-ready-condition": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&ejbcaissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
				},
			},
			expectedReadyConditionStatus: ejbcaissuer.ConditionUnknown,
		},
		"issuer-missing-secret": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
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
								Status: ejbcaissuer.ConditionUnknown,
							},
						},
					},
				},
			},
			expectedError:                errGetAuthSecret,
			expectedReadyConditionStatus: ejbcaissuer.ConditionFalse,
		},
		"issuer-failing-healthchecker-builder": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
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
								Status: ejbcaissuer.ConditionUnknown,
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
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(errors.New("simulated health checker builder error"), nil),
			expectedError:                errHealthCheckerBuilder,
			expectedReadyConditionStatus: ejbcaissuer.ConditionFalse,
		},
		"issuer-failing-healthchecker-check": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
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
								Status: ejbcaissuer.ConditionUnknown,
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
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, errors.New("simulated health check error")),
			expectedError:                errHealthCheckerCheck,
			expectedReadyConditionStatus: ejbcaissuer.ConditionFalse,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ejbcaissuer.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				WithStatusSubresource(tc.objects...).
				Build()
			if tc.kind == "" {
				tc.kind = "Issuer"
			}
			controller := IssuerReconciler{
				Kind:                              tc.kind,
				Client:                            fakeClient,
				ConfigClient:                      NewFakeConfigClient(fakeClient),
				Scheme:                            scheme,
				HealthCheckerBuilder:              tc.healthCheckerBuilder,
				ClusterResourceNamespace:          tc.clusterResourceNamespace,
				SecretAccessGrantedAtClusterLevel: true,
			}
			result, err := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t)),
				reconcile.Request{NamespacedName: tc.name},
			)
			if tc.expectedError != nil {
				assertErrorIs(t, tc.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			if tc.expectedReadyConditionStatus != "" {
				issuer, err := controller.newIssuer()
				require.NoError(t, err)
				require.NoError(t, fakeClient.Get(context.TODO(), tc.name, issuer))
				_, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
				require.NoError(t, err)
				assertIssuerHasReadyCondition(t, tc.expectedReadyConditionStatus, issuerStatus)
			}
		})
	}
}

func assertIssuerHasReadyCondition(t *testing.T, status ejbcaissuer.ConditionStatus, issuerStatus *ejbcaissuer.IssuerStatus) {
	condition := issuerutil.GetReadyCondition(issuerStatus)
	if !assert.NotNil(t, condition, "Ready condition not found") {
		return
	}
	assert.Equal(t, issuerReadyConditionReason, condition.Reason, "unexpected condition reason")
	assert.Equal(t, status, condition.Status, "unexpected condition status")
}
