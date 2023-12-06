/*
Copyright 2023 The Keyfactor Command Authors.

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
	"fmt"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

type ConfigClient interface {
	SetContext(ctx context.Context)
	GetConfigMap(name types.NamespacedName, out *corev1.ConfigMap) error
	GetSecret(name types.NamespacedName, out *corev1.Secret) error
}

type configClient struct {
	ctx         context.Context
	logger      klog.Logger
	client      kubernetes.Interface
	accessCache map[string]bool

	verifyAccessFunc func(apiResource string, resource types.NamespacedName) error
}

func NewConfigClient(ctx context.Context) (ConfigClient, error) {
	config := ctrl.GetConfigOrDie()

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	client := &configClient{
		client:      clientset,
		accessCache: make(map[string]bool),
		ctx:         ctx,
		logger:      klog.NewKlogr(),
	}

	client.verifyAccessFunc = client.verifyAccessToResource

	return client, nil
}

func (c *configClient) SetContext(ctx context.Context) {
	c.ctx = ctx
	c.logger = klog.FromContext(ctx)
}

func (c *configClient) verifyAccessToResource(apiResource string, resource types.NamespacedName) error {
	verbs := []string{"get", "list", "watch"}

	for _, verb := range verbs {
		ssar := &authv1.SelfSubjectAccessReview{
			Spec: authv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authv1.ResourceAttributes{
					Name:      resource.Name,
					Namespace: resource.Namespace,

					Group:    "",
					Resource: apiResource,
					Verb:     verb,
				},
			},
		}

		ssar, err := c.client.AuthorizationV1().SelfSubjectAccessReviews().Create(c.ctx, ssar, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create SelfSubjectAccessReview to check access to %s for verb %q: %w", apiResource, verb, err)
		}

		if !ssar.Status.Allowed {
			return fmt.Errorf("client does not have access to %s called %q for verb %q, reason: %v", apiResource, resource.String(), verb, ssar.Status.String())
		}
	}

	c.logger.Info(fmt.Sprintf("Client has access to %s called %q", apiResource, resource.String()))

	return nil
}

func (c *configClient) GetConfigMap(name types.NamespacedName, out *corev1.ConfigMap) error {
	if c == nil {
		return fmt.Errorf("config client is nil")
	}

	// Check if the client has access to the configmap resource
	if ok, _ := c.accessCache[name.String()]; !ok {
		err := c.verifyAccessFunc("configmaps", name)
		if err != nil {
			return err
		}
		c.accessCache[name.String()] = true
	}

	// Get the configmap
	configmap, err := c.client.CoreV1().ConfigMaps(name.Namespace).Get(c.ctx, name.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// Copy the configmap into the out parameter
	configmap.DeepCopyInto(out)
	return nil
}

func (c *configClient) GetSecret(name types.NamespacedName, out *corev1.Secret) error {
	if c == nil {
		return fmt.Errorf("config client is nil")
	}

	// Check if the client has access to the secret resource
	if ok, _ := c.accessCache[name.String()]; !ok {
		err := c.verifyAccessFunc("secrets", name)
		if err != nil {
			return err
		}
		c.accessCache[name.String()] = true
	}

	// Get the secret
	secret, err := c.client.CoreV1().Secrets(name.Namespace).Get(c.ctx, name.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// Copy the secret into the out parameter
	secret.DeepCopyInto(out)
	return nil
}
