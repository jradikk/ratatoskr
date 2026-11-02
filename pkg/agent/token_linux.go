//go:build linux

package agent

import (
	"context"
	"errors"

	"github.com/skaldhall/ratatoskr/pkg/registration"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TokenIssuer is the narrow Kubernetes serviceaccounts/token API surface.
type TokenIssuer interface {
	CreateToken(context.Context, string, string, *authv1.TokenRequest, metav1.CreateOptions) (*authv1.TokenRequest, error)
}

func podBoundToken(ctx context.Context, issuer TokenIssuer, pod *corev1.Pod) (string, error) {
	if issuer == nil || pod.UID == "" || pod.Spec.ServiceAccountName == "" || pod.Namespace == "" || pod.Name == "" {
		return "", errors.New("pod-bound token identity unavailable")
	}
	request := &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{Audiences: []string{registration.Audience}, BoundObjectRef: &authv1.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: pod.Name, UID: pod.UID}}}
	result, err := issuer.CreateToken(ctx, pod.Namespace, pod.Spec.ServiceAccountName, request, metav1.CreateOptions{})
	if err != nil {
		return "", errors.New("pod-bound TokenRequest failed")
	}
	if result == nil || result.Status.Token == "" {
		return "", errors.New("empty Pod-bound token")
	}
	return result.Status.Token, nil
}

// KubernetesTokenIssuer calls only the TokenRequest subresource.
type KubernetesTokenIssuer struct{ Client kubernetes.Interface }

func (k *KubernetesTokenIssuer) CreateToken(ctx context.Context, namespace, name string, req *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
	return k.Client.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, req, opts)
}
