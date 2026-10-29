package webhook

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

const (
	agentShadowVolume  = "ratatoskr-agent-api-shadow"
	defaultSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount" // #nosec G101 -- public Kubernetes API-token mount path, never credential bytes.
)

// agentWaitInit is a deliberately capability-free barrier. The node agent,
// not this workload, programs netns routes and installs rtk-ready last.
func agentWaitInit(image string) corev1.Container {
	nonRoot := true
	uid := int64(65532)
	noEscalation := false
	return corev1.Container{
		Name: initName, Image: image, Args: []string{"-wait-agent"},
		// Kubernetes ServiceAccount admission skips its API token when this
		// path is already mounted. EmptyDir isolates the waiter without changing
		// the app's ordinary service-account token behavior.
		VolumeMounts: []corev1.VolumeMount{{Name: agentShadowVolume, MountPath: defaultSATokenPath, ReadOnly: true}},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot: &nonRoot, RunAsUser: &uid, AllowPrivilegeEscalation: &noEscalation,
			Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
	}
}
func validateAgentWaitInit(pod *corev1.Pod, image string) error {
	init := pod.Spec.InitContainers[0]
	if init.Name != initName || init.Image != image || len(init.Command) != 0 || len(init.Args) != 1 || init.Args[0] != "-wait-agent" || len(init.Env) != 0 || len(init.VolumeMounts) != 1 || init.VolumeMounts[0].Name != agentShadowVolume || init.VolumeMounts[0].MountPath != defaultSATokenPath || !init.VolumeMounts[0].ReadOnly || init.VolumeMounts[0].SubPath != "" || len(init.VolumeDevices) != 0 {
		return fmt.Errorf("agent driver requires the capability-free Ratatoskr wait-init")
	}
	sc := init.SecurityContext
	if sc == nil || sc.Privileged != nil && *sc.Privileged || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.RunAsUser == nil || *sc.RunAsUser != 65532 || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		return fmt.Errorf("agent wait-init must meet restricted Pod Security requirements without capabilities")
	}
	found := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name != agentShadowVolume {
			continue
		}
		if found || volume.EmptyDir == nil {
			return fmt.Errorf("agent API-token shadow volume must be a unique emptyDir")
		}
		found = true
	}
	if !found {
		return fmt.Errorf("agent API-token shadow volume missing")
	}
	for _, container := range pod.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			if mount.Name == agentShadowVolume {
				return fmt.Errorf("agent API-token shadow must not be mounted in workload containers")
			}
		}
	}
	for _, container := range pod.Spec.InitContainers[1:] {
		for _, mount := range container.VolumeMounts {
			if mount.Name == agentShadowVolume {
				return fmt.Errorf("agent API-token shadow must not be mounted in other init containers")
			}
		}
	}
	for _, container := range pod.Spec.EphemeralContainers {
		for _, mount := range container.VolumeMounts {
			if mount.Name == agentShadowVolume {
				return fmt.Errorf("agent API-token shadow must not be mounted in ephemeral containers")
			}
		}
	}
	return nil
}
