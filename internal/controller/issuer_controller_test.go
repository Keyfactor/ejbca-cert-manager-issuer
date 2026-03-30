/*
Copyright © 2026 Keyfactor

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

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	ejbcaissuerv1alpha1 "github.com/Keyfactor/ejbca-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/ejbca-cert-manager-issuer/internal/ejbca"
	issuerutil "github.com/Keyfactor/ejbca-cert-manager-issuer/internal/util"
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
		expectedReadyConditionStatus ejbcaissuerv1alpha1.ConditionStatus
	}

	tests := map[string]testCase{
		"success-issuer": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{
							{
								Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
								Status: ejbcaissuerv1alpha1.ConditionUnknown,
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
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-cabundle-secret": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer-secret"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer-secret",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName:    "issuer1-credentials",
						CaBundleSecretName: "cabundle-secret",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{{
							Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
							Status: ejbcaissuerv1alpha1.ConditionUnknown,
						}},
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
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cabundle-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"ca.crt": authCertPem,
					},
				},
			},
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, nil),
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-cabundle-configmap": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer-configmap"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer-configmap",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName:       "issuer1-credentials",
						CaBundleConfigMapName: "cabundle-configmap",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{{
							Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
							Status: ejbcaissuerv1alpha1.ConditionUnknown,
						}},
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
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cabundle-configmap",
						Namespace: "ns1",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(authCertPem),
					},
				},
			},
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, nil),
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-cabundle-both": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer-both"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer-both",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName:       "issuer1-credentials",
						CaBundleSecretName:    "cabundle-secret",
						CaBundleConfigMapName: "cabundle-configmap",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{{
							Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
							Status: ejbcaissuerv1alpha1.ConditionUnknown,
						}},
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
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cabundle-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"ca.crt": authCertPem,
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cabundle-configmap",
						Namespace: "ns1",
					},
					Data: map[string]string{
						"ca-bundle.crt": string(authCertPem),
					},
				},
			},
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, nil),
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"success-clusterissuer": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName: "clusterissuer1-credentials",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{
							{
								Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
								Status: ejbcaissuerv1alpha1.ConditionUnknown,
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
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"success-issuer-opaque": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{
							{
								Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
								Status: ejbcaissuerv1alpha1.ConditionUnknown,
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
						"tokenUrl":     []byte("https://example.com/token"),
						"clientId":     []byte("client-id"),
						"clientSecret": []byte("client-secret"),
					},
				},
			},
			healthCheckerBuilder:         newFakeHealthCheckerBuilder(nil, nil),
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionTrue,
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
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
				},
			},
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionUnknown,
		},
		"issuer-missing-secret": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{
							{
								Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
								Status: ejbcaissuerv1alpha1.ConditionUnknown,
							},
						},
					},
				},
			},
			expectedError:                errGetAuthSecret,
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionFalse,
		},
		"issuer-failing-healthchecker-builder": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{
							{
								Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
								Status: ejbcaissuerv1alpha1.ConditionUnknown,
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
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionFalse,
		},
		"issuer-failing-healthchecker-check": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&ejbcaissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: ejbcaissuerv1alpha1.IssuerSpec{
						EjbcaSecretName: "issuer1-credentials",
					},
					Status: ejbcaissuerv1alpha1.IssuerStatus{
						Conditions: []ejbcaissuerv1alpha1.IssuerCondition{
							{
								Type:   ejbcaissuerv1alpha1.IssuerConditionReady,
								Status: ejbcaissuerv1alpha1.ConditionUnknown,
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
			expectedReadyConditionStatus: ejbcaissuerv1alpha1.ConditionFalse,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ejbcaissuerv1alpha1.AddToScheme(scheme))
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

func TestFetchAuthOptions(t *testing.T) {
	caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	authCert, authKey := issueTestCertificate(t, "Auth", caCert, rootKey)
	keyBytes, err := x509.MarshalECPrivateKey(authKey)
	require.NoError(t, err)
	authCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authCert.Raw})
	authKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	const namespace = "ns1"
	secretName := types.NamespacedName{Name: "auth-secret", Namespace: namespace}

	tests := map[string]struct {
		secret        *corev1.Secret
		expectNilOpt  bool
		expectErrType error
	}{
		"tls-success": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data: map[string][]byte{
					corev1.TLSCertKey:       authCertPem,
					corev1.TLSPrivateKeyKey: authKeyPem,
				},
			},
		},
		"tls-missing-cert": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data:       map[string][]byte{corev1.TLSPrivateKeyKey: authKeyPem},
			},
			expectErrType: errGetAuthSecret,
		},
		"tls-missing-key": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data:       map[string][]byte{corev1.TLSCertKey: authCertPem},
			},
			expectErrType: errGetAuthSecret,
		},
		"oauth-success": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data: map[string][]byte{
					"tokenUrl":     []byte("https://example.com/token"),
					"clientId":     []byte("client-id"),
					"clientSecret": []byte("client-secret"),
				},
			},
		},
		"oauth-success-with-optional-fields": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data: map[string][]byte{
					"tokenUrl":     []byte("https://example.com/token"),
					"clientId":     []byte("client-id"),
					"clientSecret": []byte("client-secret"),
					"scopes":       []byte("openid profile"),
					"audience":     []byte("https://api.example.com"),
				},
			},
		},
		"oauth-missing-token-url": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data: map[string][]byte{
					"clientId":     []byte("client-id"),
					"clientSecret": []byte("client-secret"),
				},
			},
			expectErrType: errGetAuthSecret,
		},
		"oauth-missing-client-id": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data: map[string][]byte{
					"tokenUrl":     []byte("https://example.com/token"),
					"clientSecret": []byte("client-secret"),
				},
			},
			expectErrType: errGetAuthSecret,
		},
		"oauth-missing-client-secret": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data: map[string][]byte{
					"tokenUrl": []byte("https://example.com/token"),
					"clientId": []byte("client-id"),
				},
			},
			expectErrType: errGetAuthSecret,
		},
		"unsupported-secret-type": {
			secret: &corev1.Secret{
				Type:       corev1.SecretTypeSSHAuth,
				ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: namespace},
				Data:       map[string][]byte{"ssh-privatekey": []byte("key")},
			},
			expectErrType: errGetAuthSecret,
		},
		"secret-not-found": {
			expectErrType: errGetAuthSecret,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ejbcaissuerv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			objects := []client.Object{}
			if tc.secret != nil {
				objects = append(objects, tc.secret)
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()
			configClient := NewFakeConfigClient(fakeClient)
			ctx := ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t))
			configClient.SetContext(ctx)

			opt, err := fetchAuthOptions(ctx, configClient, secretName)

			if tc.expectErrType != nil {
				assertErrorIs(t, tc.expectErrType, err)
				assert.Nil(t, opt)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, opt)
			}
		})
	}
}

func TestFetchCACertBytes(t *testing.T) {
	caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	leafCert, _ := issueTestCertificate(t, "Leaf", caCert, rootKey)
	leafCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	const namespace = "ns1"

	tests := map[string]struct {
		objects       []client.Object
		issuerSpec    ejbcaissuerv1alpha1.IssuerSpec
		expectBytes   []byte
		expectErrType error
	}{
		"no-ca-bundle": {
			issuerSpec:  ejbcaissuerv1alpha1.IssuerSpec{},
			expectBytes: nil,
		},
		"configmap-present": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{CaBundleConfigMapName: "ca-cm"},
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cm", Namespace: namespace},
					Data:       map[string]string{"ca-bundle.crt": string(leafCertPem)},
				},
			},
			expectBytes: leafCertPem,
		},
		"configmap-key-specified": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{CaBundleConfigMapName: "ca-cm", CaBundleKey: "test.crt"},
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cm", Namespace: namespace},
					Data:       map[string]string{"aaa.crt": "data", "test.crt": string(leafCertPem), "zzz.crt": "data"},
				},
			},
			expectBytes: leafCertPem,
		},
		"configmap-key-specified-missing": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{CaBundleConfigMapName: "ca-cm", CaBundleKey: "test.crt"},
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cm", Namespace: namespace},
					Data:       map[string]string{"wrong-key": "data"},
				},
			},
			expectErrType: errGetCaConfigKey,
		},
		"configmap-not-found": {
			issuerSpec:    ejbcaissuerv1alpha1.IssuerSpec{CaBundleConfigMapName: "ca-cm"},
			expectErrType: errGetCaConfigMap,
		},
		"secret-present": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{CaBundleSecretName: "ca-secret"},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-secret", Namespace: namespace},
					Data:       map[string][]byte{"ca.crt": leafCertPem},
				},
			},
			expectBytes: leafCertPem,
		},
		"secret-key-specified": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{CaBundleSecretName: "ca-secret", CaBundleKey: "test.crt"},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-secret", Namespace: namespace},
					Data:       map[string][]byte{"aaa.crt": []byte("data"), "test.crt": leafCertPem, "zzz.crt": []byte("data")},
				},
			},
			expectBytes: leafCertPem,
		},
		"secret-key-specified-missing": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{CaBundleSecretName: "ca-secret", CaBundleKey: "test.crt"},
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-secret", Namespace: namespace},
					Data:       map[string][]byte{"aaa.crt": []byte("data")},
				},
			},
			expectErrType: errGetCaConfigKey,
		},
		"secret-not-found": {
			issuerSpec:    ejbcaissuerv1alpha1.IssuerSpec{CaBundleSecretName: "ca-secret"},
			expectErrType: errGetCaSecret,
		},
		"configmap-takes-precedence-over-secret": {
			issuerSpec: ejbcaissuerv1alpha1.IssuerSpec{
				CaBundleConfigMapName: "ca-cm",
				CaBundleSecretName:    "ca-secret",
			},
			objects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-cm", Namespace: namespace},
					Data:       map[string]string{"ca-bundle.crt": string(leafCertPem)},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ca-secret", Namespace: namespace},
					Data:       map[string][]byte{"ca.crt": []byte("should-not-be-used")},
				},
			},
			expectBytes: leafCertPem,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, ejbcaissuerv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				Build()
			configClient := NewFakeConfigClient(fakeClient)
			ctx := ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t))
			configClient.SetContext(ctx)

			got, err := fetchCACertBytes(ctx, &tc.issuerSpec, configClient, namespace)

			if tc.expectErrType != nil {
				assertErrorIs(t, tc.expectErrType, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectBytes, got)
			}
		})
	}
}

func assertIssuerHasReadyCondition(t *testing.T, status ejbcaissuerv1alpha1.ConditionStatus, issuerStatus *ejbcaissuerv1alpha1.IssuerStatus) {
	condition := issuerutil.GetReadyCondition(issuerStatus)
	if !assert.NotNil(t, condition, "Ready condition not found") {
		return
	}
	assert.Equal(t, issuerReadyConditionReason, condition.Reason, "unexpected condition reason")
	assert.Equal(t, status, condition.Status, "unexpected condition status")
}
