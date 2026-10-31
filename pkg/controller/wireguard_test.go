package controller

import (
	"encoding/json"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/skaldhall/ratatoskr/pkg/datapath"
	"github.com/skaldhall/ratatoskr/pkg/registration"
)

func TestPublishedWireGuardIdentityValidation(t *testing.T) {
	cert, err := registration.NewCertificates("10.42.2.4")
	if err != nil {
		t.Fatal(err)
	}
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	public := private.PublicKey().String()
	if !validPublishedIdentity(string(cert.PublicCert()), public) {
		t.Fatal("valid public gateway identity rejected")
	}
	if validPublishedIdentity(string(cert.PublicCert()), "bad-key") {
		t.Fatal("malformed public key accepted")
	}
	if validPublishedIdentity("not-a-certificate", public) {
		t.Fatal("malformed gateway CA accepted")
	}
}

func TestRenderWireGuardIdentityAndIngress(t *testing.T) {
	r, gw := fixture(t)
	gw.Status.GatewayID = 7
	gw.Spec.Encryption = "wireguard"
	gw.Spec.AllowedNamespaces.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "red"}}
	objects, err := r.render(gw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg datapath.GatewayConfig
	if err := json.Unmarshal([]byte(objects[0].(*corev1.ConfigMap).Data["gateway.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Encryption != "wireguard" || cfg.WireGuardPort != 0 {
		t.Fatal("wireguard config drift")
	}
	deployment := objects[2].(*appsv1.Deployment)
	if deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatal("gateway identity rotation must withdraw old Pod before replacement")
	}
	pod := deployment.Spec.Template.Spec
	if pod.ServiceAccountName != "ratatoskr-gateway" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("gateway ServiceAccount leak")
	}
	volume := false
	for _, v := range pod.Volumes {
		if v.Name == "gateway-api" {
			volume = true
			if v.Projected == nil || len(v.Projected.Sources) != 3 || v.Projected.Sources[0].ServiceAccountToken == nil || v.Projected.Sources[0].ServiceAccountToken.Path != "token" {
				t.Fatal("missing private gateway-only API projection")
			}
		}
	}
	if !volume {
		t.Fatal("gateway API trust root volume missing")
	}
	mount := false
	for _, m := range pod.Containers[0].VolumeMounts {
		if m.Name == "gateway-api" && m.ReadOnly {
			mount = true
		}
	}
	if !mount {
		t.Fatal("gateway container missing private API projection")
	}
	for _, m := range pod.Containers[1].VolumeMounts {
		if m.Name == "gateway-api" {
			t.Fatal("upstream sidecar can read gateway API token")
		}
	}
	vars := map[string]bool{}
	for _, v := range pod.Containers[0].Env {
		vars[v.Name] = true
	}
	for _, name := range []string{"GATEWAY_NAME", "POD_NAMESPACE", "POD_NAME", "POD_UID", "POD_IP"} {
		if !vars[name] {
			t.Fatalf("missing gateway identity %s", name)
		}
	}
	uidCount := 0
	for _, env := range pod.Containers[0].Env {
		if env.Name == "POD_UID" {
			uidCount++
		}
	}
	if uidCount != 1 {
		t.Fatalf("encrypted gateway must not receive duplicate POD_UID env: %d", uidCount)
	}
	policy := objects[len(objects)-1].(*networkingv1.NetworkPolicy)
	ports := map[int32]bool{}
	for _, rule := range policy.Spec.Ingress {
		for _, p := range rule.Ports {
			if p.Port != nil {
				ports[p.Port.IntVal] = true
			}
		}
	}
	if ports[datapath.GenevePort] || !ports[int32(datapath.WireGuardPortDefault)] || !ports[9443] || !ports[9900] {
		t.Fatal("encrypted ingress includes plain GENEVE or omits required authenticated ports")
	}
	gw.Namespace = "other"
	if _, err := r.render(gw, nil); err == nil {
		t.Fatal("cross-namespace M4 gateway accepted without scoped RBAC")
	}
}
