package webhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestBootstrapTLS(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mutate"}, Webhooks: []admissionv1.MutatingWebhook{{Name: "mutate.test"}}}, &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "validate"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "validate.test"}}})
	dir := t.TempDir()
	bootstrap := func() error {
		return BootstrapTLS(ctx, client, "system", "ratatoskr-webhook", "cluster.local", "webhook-tls", "mutate", "validate", dir)
	}
	if err := bootstrap(); err != nil {
		t.Fatal(err)
	}
	secret, err := client.CoreV1().Secrets("system").Get(ctx, "webhook-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	originalCA := bytes.Clone(secret.Data["ca.crt"])
	if err := checkIdentity(secret.Data["ca.crt"], secret.Data["tls.crt"], secret.Data["tls.key"], "ratatoskr-webhook.system.svc.cluster.local"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %v", name, info.Mode())
		}
	}
	m, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "mutate", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Webhooks[0].ClientConfig.CABundle, originalCA) {
		t.Fatal("mutating CA bundle differs")
	}
	v, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "validate", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.Webhooks[0].ClientConfig.CABundle, originalCA) {
		t.Fatal("validating CA bundle differs")
	}
	if err := bootstrap(); err != nil {
		t.Fatal(err)
	}
	secret, err = client.CoreV1().Secrets("system").Get(ctx, "webhook-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalCA, secret.Data["ca.crt"]) {
		t.Fatal("bootstrap rotated CA on restart")
	}
	secret.Data["tls.key"] = []byte("intentionally-invalid-secret-material")
	if _, err = client.CoreV1().Secrets("system").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	err = bootstrap()
	if err == nil {
		t.Fatal("invalid existing Secret silently rotated")
	}
	if strings.Contains(err.Error(), "intentionally-invalid-secret-material") {
		t.Fatal("bootstrap leaked private material")
	}
}

func TestBootstrapRenewsLeafWithoutChangingCA(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mutate"}, Webhooks: []admissionv1.MutatingWebhook{{Name: "m"}}}, &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "validate"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "v"}}})
	dir := t.TempDir()
	bootstrap := func() error {
		return BootstrapTLS(ctx, client, "system", "webhook", "cluster.local", "tls", "mutate", "validate", dir)
	}
	if err := bootstrap(); err != nil {
		t.Fatal(err)
	}
	secret, err := client.CoreV1().Secrets("system").Get(ctx, "tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca := bytes.Clone(secret.Data["ca.crt"])
	caBlock, _ := pem.Decode(ca)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(secret.Data["ca.key"])
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1234), DNSNames: []string{"webhook.system.svc.cluster.local"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(15 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &oldKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	oldKeyDER, err := x509.MarshalECPrivateKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	secret.Data["tls.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	secret.Data["tls.key"] = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: oldKeyDER})
	if _, err = client.CoreV1().Secrets("system").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = bootstrap(); err != nil {
		t.Fatal(err)
	}
	updated, err := client.CoreV1().Secrets("system").Get(ctx, "tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, updated.Data["ca.crt"]) {
		t.Fatal("renewal changed CA")
	}
	if bytes.Equal(updated.Data["tls.crt"], secret.Data["tls.crt"]) {
		t.Fatal("leaf was not renewed")
	}
	if err = checkIdentity(updated.Data["ca.crt"], updated.Data["tls.crt"], updated.Data["tls.key"], "webhook.system.svc.cluster.local"); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapWaitsForAdmissionConfigurations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := fake.NewSimpleClientset()
	mutatingGet := make(chan struct{})
	validatingGet := make(chan struct{})
	var mutatingOnce, validatingOnce sync.Once
	client.PrependReactor("get", "mutatingwebhookconfigurations", func(_ ktesting.Action) (bool, runtime.Object, error) {
		mutatingOnce.Do(func() { close(mutatingGet) })
		return false, nil, nil
	})
	client.PrependReactor("get", "validatingwebhookconfigurations", func(_ ktesting.Action) (bool, runtime.Object, error) {
		validatingOnce.Do(func() { close(validatingGet) })
		return false, nil, nil
	})
	dir := t.TempDir()
	result := make(chan error, 1)
	go func() {
		result <- BootstrapTLS(ctx, client, "system", "webhook", "cluster.local", "tls", "mutate", "validate", dir)
	}()
	select {
	case <-mutatingGet:
	case <-ctx.Done():
		t.Fatal("mutating GET never reached", ctx.Err())
	}
	if _, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mutate"}, Webhooks: []admissionv1.MutatingWebhook{{Name: "m"}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-validatingGet:
	case <-ctx.Done():
		t.Fatal("validating GET never reached", ctx.Err())
	}
	if _, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "validate"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "v"}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("bootstrap missed admission resources", ctx.Err())
	}
	secret, err := client.CoreV1().Secrets("system").Get(ctx, "tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, "mutate", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, "validate", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Webhooks[0].ClientConfig.CABundle, secret.Data["ca.crt"]) || !bytes.Equal(v.Webhooks[0].ClientConfig.CABundle, secret.Data["ca.crt"]) {
		t.Fatal("CA bundle not patched on delayed resources")
	}
}
func TestBootstrapAdmissionRetryDeadlineAndForbidden(t *testing.T) {
	run := func(ctx context.Context, client *fake.Clientset) error {
		return BootstrapTLS(ctx, client, "system", "webhook", "cluster.local", "tls", "mutate", "validate", t.TempDir())
	}
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
		defer cancel()
		client := fake.NewSimpleClientset()
		start := time.Now()
		err := run(ctx, client)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline error, got %v", err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("retry exceeded caller deadline")
		}
		secret, getErr := client.CoreV1().Secrets("system").Get(context.Background(), "tls", metav1.GetOptions{})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if strings.Contains(err.Error(), string(secret.Data["tls.key"])) || strings.Contains(err.Error(), string(secret.Data["ca.key"])) {
			t.Fatal("retry error leaked private key")
		}
	})
	t.Run("forbidden", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		var attempts int
		client.PrependReactor("get", "mutatingwebhookconfigurations", func(_ ktesting.Action) (bool, runtime.Object, error) {
			attempts++
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "mutatingwebhookconfigurations"}, "mutate", errors.New("permission denied"))
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := run(ctx, client)
		if !apierrors.IsForbidden(err) {
			t.Fatalf("expected forbidden error, got %v", err)
		}
		if attempts != 1 {
			t.Fatalf("forbidden error was retried %d times", attempts)
		}
	})
}
func TestBootstrapRetriesAdmissionUpdateConflict(t *testing.T) {
	client := fake.NewSimpleClientset(&admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "mutate"}, Webhooks: []admissionv1.MutatingWebhook{{Name: "m"}}}, &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "validate"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "v"}}})
	var attempts int
	client.PrependReactor("update", "mutatingwebhookconfigurations", func(_ ktesting.Action) (bool, runtime.Object, error) {
		attempts++
		if attempts == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "mutatingwebhookconfigurations"}, "mutate", errors.New("test conflict"))
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := BootstrapTLS(ctx, client, "system", "webhook", "cluster.local", "tls", "mutate", "validate", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("expected exactly two updates, got %d", attempts)
	}
}
