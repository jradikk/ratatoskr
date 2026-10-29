package controller

import (
	"encoding/json"
	"fmt"
	"net/netip"

	api "github.com/skaldhall/ratatoskr/api/v1alpha1"
	"github.com/skaldhall/ratatoskr/pkg/datapath"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ptrInt32(value int32) *int32 { return &value }

func (r *GatewayReconciler) render(gw *api.EgressGateway, ips []netip.Addr) ([]client.Object, error) {
	if gw.Spec.Upstream.SecretRef.Name == "" {
		return nil, fmt.Errorf("upstream secretRef.name required")
	}
	if gw.Spec.Exclusions.AutoDetect != nil && !*gw.Spec.Exclusions.AutoDetect {
		return nil, fmt.Errorf("disabled automatic exclusions are not supported in M2")
	}
	// No POD_IP is serialized; every replica uses its own downward-API POD_IP.
	config := datapath.GatewayConfig{GatewayID: gw.Status.GatewayID, Clients: ips, MTU: 1400, Encryption: "none"}
	if config.Clients == nil {
		config.Clients = []netip.Addr{}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	selector := map[string]string{IdentityLabel: gw.Name, ownerUIDLabel: string(gw.UID)}
	owner := []metav1.OwnerReference{*metav1.NewControllerRef(gw, api.SchemeGroupVersion.WithKind("EgressGateway"))}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: owner}, Data: map[string]string{"gateway.json": string(data)}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: owner}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: selector, Ports: []corev1.ServicePort{{Name: "geneve", Port: datapath.GenevePort, TargetPort: intstr.FromInt32(datapath.GenevePort), Protocol: corev1.ProtocolUDP}}}}
	replicas := int32(1)
	pull := corev1.PullIfNotPresent
	if r.Options.ImagePullPolicy != "" {
		pull = corev1.PullPolicy(r.Options.ImagePullPolicy)
	}
	priv := false
	root := int64(0)
	pod := corev1.PodSpec{AutomountServiceAccountToken: &priv, Volumes: []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: gw.Name}}}},
		{Name: "upstream", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: gw.Spec.Upstream.SecretRef.Name, DefaultMode: ptrInt32(0400)}}},
		{Name: "run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
		{Name: "dev-net", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}, Containers: []corev1.Container{
		{Name: "gateway", Image: r.Options.GatewayImage, ImagePullPolicy: pull, Command: []string{"/ratatoskr", "-config", "/config/gateway.json"}, Env: []corev1.EnvVar{{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}}}, Ports: []corev1.ContainerPort{{Name: "geneve", ContainerPort: datapath.GenevePort, Protocol: corev1.ProtocolUDP}, {Name: "health", ContainerPort: 9900}}, VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/config", ReadOnly: true}}, SecurityContext: &corev1.SecurityContext{RunAsUser: &root, AllowPrivilegeEscalation: &priv, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}, Drop: []corev1.Capability{"ALL"}}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(9900)}}, PeriodSeconds: 5}},
		{Name: "upstream", Image: r.Options.OpenVPNImage, ImagePullPolicy: pull, VolumeMounts: []corev1.VolumeMount{{Name: "upstream", MountPath: "/etc/ratatoskr/upstream", ReadOnly: true}, {Name: "run", MountPath: "/run/ratatoskr"}, {Name: "dev-net", MountPath: "/dev/net"}}, SecurityContext: &corev1.SecurityContext{RunAsUser: &root, AllowPrivilegeEscalation: &priv, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "MKNOD"}, Drop: []corev1.Capability{"ALL"}}}},
	}}
	for k, v := range gw.Spec.NodeSelector {
		if pod.NodeSelector == nil {
			pod.NodeSelector = map[string]string{}
		}
		pod.NodeSelector[k] = v
	}
	for _, t := range gw.Spec.Tolerations {
		tol := corev1.Toleration{Key: t.Key, Operator: corev1.TolerationOperator(t.Operator), Value: t.Value, Effect: corev1.TaintEffect(t.Effect), TolerationSeconds: t.TolerationSeconds}
		pod.Tolerations = append(pod.Tolerations, tol)
	}
	c := &pod.Containers[0]
	c.Resources = corev1.ResourceRequirements{Limits: corev1.ResourceList{}, Requests: corev1.ResourceList{}}
	for k, v := range gw.Spec.Resources.Gateway.Limits {
		c.Resources.Limits[corev1.ResourceName(k)] = resource.MustParse(v.String())
	}
	for k, v := range gw.Spec.Resources.Gateway.Requests {
		c.Resources.Requests[corev1.ResourceName(k)] = resource.MustParse(v.String())
	}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace, OwnerReferences: owner}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: selector}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: selector}, Spec: pod}}}
	return []client.Object{cm, svc, dep}, nil
}
