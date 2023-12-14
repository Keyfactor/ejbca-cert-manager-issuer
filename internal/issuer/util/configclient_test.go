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

package util

import (
	"context"
	logrtesting "github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ctrl "sigs.k8s.io/controller-runtime"
	"testing"
)

func TestConfigClient(t *testing.T) {
	var err error

	// Define namespaced names for test objects
	configMapName := types.NamespacedName{Name: "test-configmap", Namespace: "default"}
	secretName := types.NamespacedName{Name: "test-secret", Namespace: "default"}

	// Create and inject fake ConfigMap
	testConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: configMapName.Name, Namespace: configMapName.Namespace},
	}

	// Create and inject fake Secret
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName.Name, Namespace: secretName.Namespace},
	}

	// Create a fake clientset with the test objects
	clientset := fake.NewSimpleClientset([]runtime.Object{
		testConfigMap,
		testSecret,
	}...)

	// We can't test NewConfigClient unless we can mock ctrl.GetConfigOrDie() and kubernetes.NewForConfig()
	// So we'll just test the methods that use the clientset

	// Create a ConfigClient
	client := &configClient{
		client:      clientset,
		accessCache: make(map[string]bool),
	}

	// The fake client doesn't implement authorization.k8s.io/v1 SelfSubjectAccessReview
	// So we'll mock the verifyAccessFunc
	client.verifyAccessFunc = func(apiResource string, resource types.NamespacedName) error {
		return nil
	}

	// Setup logging for test environment by setting the context
	client.SetContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

	t.Run("GetConfigMap", func(t *testing.T) {
		// Test GetConfigMap
		var out corev1.ConfigMap
		err = client.GetConfigMap(configMapName, &out)
		assert.NoError(t, err)
		assert.Equal(t, testConfigMap, &out)
	})

	t.Run("GetSecret", func(t *testing.T) {
		// Test GetSecret
		var out corev1.Secret
		err = client.GetSecret(secretName, &out)
		assert.NoError(t, err)
		assert.Equal(t, testSecret, &out)
	})
}
