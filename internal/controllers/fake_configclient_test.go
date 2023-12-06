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

package controllers

import (
	"context"
	"github.com/Keyfactor/ejbca-issuer/internal/issuer/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FakeConfigClient is a fake implementation of the util.ConfigClient interface
// It forwards requests destined for the Kubernetes API server implemented by
// the util.ConfigClient interface to a fake Kubernetes API server implemented
// by the client.Client interface.

// Force the compiler to check that FakeConfigClient implements the util.ConfigClient interface
var _ util.ConfigClient = &FakeConfigClient{}

type FakeConfigClient struct {
	client client.Client
	ctx    context.Context
}

// NewFakeConfigClient uses the
func NewFakeConfigClient(fakeControllerRuntimeClient client.Client) util.ConfigClient {
	return &FakeConfigClient{
		client: fakeControllerRuntimeClient,
	}
}

func (f *FakeConfigClient) SetContext(ctx context.Context) {
	f.ctx = ctx
}

func (f *FakeConfigClient) GetConfigMap(name types.NamespacedName, out *corev1.ConfigMap) error {
	return f.client.Get(f.ctx, name, out)
}

func (f *FakeConfigClient) GetSecret(name types.NamespacedName, out *corev1.Secret) error {
	return f.client.Get(f.ctx, name, out)
}
