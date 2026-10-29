package webhook

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// BootstrapTLS persists a CA and serving identity. Near-expiry leaf certificates
// can be renewed under the same CA without invalidating existing serving pods;
// the CA is never automatically rotated.
func BootstrapTLS(ctx context.Context, k kubernetes.Interface, namespace, service, domain, secretName, mutatingName, validatingName, dir string) error {
	if namespace == "" || service == "" || domain == "" || secretName == "" || mutatingName == "" || validatingName == "" || dir == "" {
		return errors.New("TLS bootstrap requires NAMESPACE, SERVICE_NAME, CLUSTER_DOMAIN, TLS_SECRET_NAME, MUTATING_WEBHOOK_NAME, VALIDATING_WEBHOOK_NAME and tls-dir")
	}
	dns := service + "." + namespace + ".svc"
	fqdn := dns + "." + domain
	secrets := k.CoreV1().Secrets(namespace)
	secret, err := secrets.Get(ctx, secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		ca, caKey, cert, key, genErr := newIdentity(dns, fqdn)
		if genErr != nil {
			return fmt.Errorf("generate webhook identity: %w", genErr)
		}
		secret, err = secrets.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"ca.crt": ca, "ca.key": caKey, "tls.crt": cert, "tls.key": key}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			secret, err = secrets.Get(ctx, secretName, metav1.GetOptions{})
		}
	}
	if err != nil {
		return fmt.Errorf("get/create webhook TLS Secret: %w", err)
	}
	ca, cert, key := secret.Data["ca.crt"], secret.Data["tls.crt"], secret.Data["tls.key"]
	if err = checkIdentity(ca, cert, key, fqdn); err != nil {
		return fmt.Errorf("existing TLS Secret must be repaired manually (no unsafe CA rotation): %w", err)
	}
	leafBlock, _ := pem.Decode(cert)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return errors.New("serving certificate invalid")
	}
	if time.Until(leaf.NotAfter) < 30*24*time.Hour {
		caBlock, _ := pem.Decode(ca)
		caCert, err := x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return errors.New("CA certificate invalid")
		}
		if time.Until(caCert.NotAfter) < 365*24*time.Hour {
			return errors.New("CA expires within a year; coordinate CA rotation before renewing the serving certificate")
		}
		keyBlock, _ := pem.Decode(secret.Data["ca.key"])
		if keyBlock == nil {
			return errors.New("CA key missing; cannot renew serving identity without CA rotation")
		}
		caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return errors.New("CA key invalid")
		}
		if !caKey.PublicKey.Equal(caCert.PublicKey) {
			return errors.New("CA key does not match certificate")
		}
		cert, key, err = newServingIdentity(caCert, caKey, dns, fqdn)
		if err != nil {
			return fmt.Errorf("renew serving certificate: %w", err)
		}
		secret.Data["tls.crt"], secret.Data["tls.key"] = cert, key
		secret, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) {
			// Another bootstrapper won; consume its identity instead of overwriting it.
			secret, err = secrets.Get(ctx, secretName, metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("persist renewed serving identity: %w", err)
		}
		ca, cert, key = secret.Data["ca.crt"], secret.Data["tls.crt"], secret.Data["tls.key"]
		if err = checkIdentity(ca, cert, key, fqdn); err != nil {
			return fmt.Errorf("renewed serving identity invalid: %w", err)
		}
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("prepare TLS directory: %w", err)
	}
	if err = os.Chmod(dir, 0700); err != nil { // #nosec G302 -- private TLS directory must be traversable by its owner only.
		return fmt.Errorf("secure TLS directory: %w", err)
	}
	if err = writePrivate(dir, "tls.crt", cert); err != nil {
		return err
	}
	if err = writePrivate(dir, "tls.key", key); err != nil {
		return err
	}
	if err = writePrivate(dir, "ca.crt", ca); err != nil {
		return err
	}
	// Deployments can start before Helm creates admission configurations. Only
	// absence and update conflicts are transient; forbidden and malformed objects
	// fail immediately. One deadline bounds both patches, including caller waits.
	patchCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := retryAdmissionConfig(patchCtx, "mutating", func(ctx context.Context) error {
		m, err := k.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, mutatingName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if len(m.Webhooks) == 0 {
			return errors.New("mutating webhook configuration has no webhooks")
		}
		for i := range m.Webhooks {
			m.Webhooks[i].ClientConfig.CABundle = ca
		}
		_, err = k.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(ctx, m, metav1.UpdateOptions{})
		return err
	}); err != nil {
		return err
	}
	return retryAdmissionConfig(patchCtx, "validating", func(ctx context.Context) error {
		v, err := k.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, validatingName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if len(v.Webhooks) == 0 {
			return errors.New("validating webhook configuration has no webhooks")
		}
		for i := range v.Webhooks {
			v.Webhooks[i].ClientConfig.CABundle = ca
		}
		_, err = k.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, v, metav1.UpdateOptions{})
		return err
	})
}

func retryAdmissionConfig(ctx context.Context, kind string, patch func(context.Context) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("patch %s admission CA: %w", kind, err)
		}
		err := patch(ctx)
		if err == nil {
			return nil
		}
		if !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return fmt.Errorf("patch %s admission CA: %w", kind, err)
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("patch %s admission CA: %w", kind, ctx.Err())
		case <-timer.C:
		}
	}
}
func writePrivate(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	// Never follow a symlink in a shared volume.
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("TLS path %s is not a regular file", name)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304 -- dir is the private bootstrapped TLS directory; name is one of three fixed filenames.
	if err != nil {
		return fmt.Errorf("write TLS file %s: %w", name, err)
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write TLS file %s: %w", name, err)
	}
	return closeErr
}
func checkIdentity(caPEM, certPEM, keyPEM []byte, dns string) error {
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return errors.New("CA certificate missing")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA: %w", err)
	}
	if !ca.IsCA {
		return errors.New("certificate is not a CA")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("serving certificate/key invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse serving certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: dns, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return fmt.Errorf("verify serving peer identity: %w", err)
	}
	return nil
}
func newIdentity(dns, fqdn string) ([]byte, []byte, []byte, []byte, error) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caT := &x509.Certificate{SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "ratatoskr-webhook CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, key, err := newServingIdentity(caT, caKey, dns, fqdn)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER}), cert, key, nil
}
func newServingIdentity(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns, fqdn string) ([]byte, []byte, error) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certT := &x509.Certificate{SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{dns, fqdn}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, certT, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}
