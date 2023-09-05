/*
Copyright 2020 The cert-manager Authors

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
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ejbcaissuer "github.com/Keyfactor/ejbca-issuer/api/v1alpha1"
)

func GetCertificateRequestAnnotations(issuer client.Object) (map[string]string, error) {
	switch t := issuer.(type) {
	case *ejbcaissuer.Issuer:
		return t.GetAnnotations(), nil
	case *ejbcaissuer.ClusterIssuer:
		return t.GetAnnotations(), nil
	default:
		return nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func GetName(issuer client.Object) (string, error) {
	switch t := issuer.(type) {
	case *ejbcaissuer.Issuer:
		return t.GetName(), nil
	case *ejbcaissuer.ClusterIssuer:
		return t.GetName(), nil
	default:
		return "", fmt.Errorf("not an issuer type: %t", t)
	}
}

func GetSpecAndStatus(issuer client.Object) (*ejbcaissuer.IssuerSpec, *ejbcaissuer.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *ejbcaissuer.Issuer:
		return &t.Spec, &t.Status, nil
	case *ejbcaissuer.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetCertificateRequestReadyCondition(ctx context.Context, csr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string) {
	log := ctrl.LoggerFrom(ctx)

	if len(csr.Status.Conditions) > 0 && csr.Status.Conditions[0].Status != status {
		log.Info(fmt.Sprintf("Found status change for CertificateRequest %q: %q -> %q; Reason: %q Message: %q", csr.Name, csr.Status.Conditions[0].Status, status, reason, message))
	}

	cmutil.SetCertificateRequestCondition(
		csr,
		cmapi.CertificateRequestConditionReady,
		status,
		reason,
		message,
	)
}

func SetIssuerReadyCondition(ctx context.Context, name, kind string, status *ejbcaissuer.IssuerStatus, conditionStatus ejbcaissuer.ConditionStatus, reason, message string) {
	log := ctrl.LoggerFrom(ctx)

	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &ejbcaissuer.IssuerCondition{
			Type: ejbcaissuer.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		log.Info(fmt.Sprintf("Found status change for %s %q: %q -> %q; %q", kind, name, ready.Status, conditionStatus, message))

		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == ejbcaissuer.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *ejbcaissuer.IssuerStatus) *ejbcaissuer.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == ejbcaissuer.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *ejbcaissuer.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == ejbcaissuer.ConditionTrue
	}
	return false
}
