package webhook

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"

	"github.com/skaldhall/ratatoskr/api/v1alpha1"
)

// validateWireGuardEndpoint accepts only authenticated controller-published
// public status material. Never return PEM or key contents in errors.
func validateWireGuardEndpoint(endpoint *v1alpha1.GatewayEndpoint) error {
	key, err := wgtypes.ParseKey(endpoint.WireguardPublicKey)
	if err != nil || key == (wgtypes.Key{}) {
		return fmt.Errorf("healthy WireGuard endpoint has no valid public key")
	}
	if len(endpoint.RegistrationCACert) == 0 || len(endpoint.RegistrationCACert) >= 4096 {
		return fmt.Errorf("healthy WireGuard endpoint has no valid registration CA")
	}
	block, rest := pem.Decode([]byte(endpoint.RegistrationCACert))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || len(block.Headers) != 0 {
		return fmt.Errorf("healthy WireGuard endpoint has no valid registration CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return fmt.Errorf("healthy WireGuard endpoint has no valid registration CA certificate")
	}
	if err = cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("healthy WireGuard endpoint registration CA is not self-signed")
	}
	return nil
}
func injectWireGuardToken(pod *corev1.Pod) {
	lifetime := int64(600)
	// Distroless init runs as a non-root UID. 0444 grants read access without
	// changing the workload's fsGroup; only the dedicated init mounts this volume.
	mode := int32(0444)
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: wgTokenVolume, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: &mode, Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: wgTokenAudience, ExpirationSeconds: &lifetime, Path: "token"}}}}}})
	pod.Spec.InitContainers[0].VolumeMounts = append(pod.Spec.InitContainers[0].VolumeMounts, corev1.VolumeMount{Name: wgTokenVolume, MountPath: wgTokenMount, ReadOnly: true})
}
func validateWireGuardToken(pod *corev1.Pod) error {
	if len(pod.Spec.InitContainers) == 0 || len(pod.Spec.InitContainers[0].VolumeMounts) != 2 {
		return fmt.Errorf("WireGuard init requires a dedicated projected token mount")
	}
	mount := pod.Spec.InitContainers[0].VolumeMounts[1]
	if mount.Name != wgTokenVolume || mount.MountPath != wgTokenMount || !mount.ReadOnly || mount.SubPath != "" {
		return fmt.Errorf("WireGuard init token mount is invalid")
	}
	found := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name != wgTokenVolume {
			continue
		}
		if found || volume.Projected == nil || volume.Projected.DefaultMode == nil || *volume.Projected.DefaultMode != 0444 || len(volume.Projected.Sources) != 1 {
			return fmt.Errorf("duplicate or invalid WireGuard token projection or file mode")
		}
		projection := volume.Projected.Sources[0].ServiceAccountToken
		if projection == nil || projection.Audience != wgTokenAudience || projection.ExpirationSeconds == nil || *projection.ExpirationSeconds != 600 || projection.Path != "token" {
			return fmt.Errorf("WireGuard projected token audience or lifetime is invalid")
		}
		found = true
	}
	if !found {
		return fmt.Errorf("WireGuard projected token volume missing")
	}
	for _, container := range pod.Spec.Containers {
		for _, m := range container.VolumeMounts {
			if m.Name == wgTokenVolume || m.MountPath == wgTokenMount {
				return fmt.Errorf("WireGuard token must not be mounted in workload containers")
			}
		}
	}
	for _, container := range pod.Spec.EphemeralContainers {
		for _, m := range container.VolumeMounts {
			if m.Name == wgTokenVolume || m.MountPath == wgTokenMount {
				return fmt.Errorf("WireGuard token must not be mounted in ephemeral containers")
			}
		}
	}
	for _, container := range pod.Spec.InitContainers[1:] {
		for _, m := range container.VolumeMounts {
			if m.Name == wgTokenVolume || m.MountPath == wgTokenMount {
				return fmt.Errorf("WireGuard token must not be mounted in other init containers")
			}
		}
	}
	return nil
}
