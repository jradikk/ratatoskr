package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=egw
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// EgressGateway describes a pool of VPN egress endpoints.
type EgressGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EgressGatewaySpec   `json:"spec"`
	Status            EgressGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type EgressGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressGateway `json:"items"`
}

type EgressGatewaySpec struct {
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	Replicas int32 `json:"replicas,omitempty"`
	// +kubebuilder:validation:Enum=none;wireguard
	// +kubebuilder:default=none
	Encryption string `json:"encryption,omitempty"`
	// +kubebuilder:validation:Enum=per-pod
	// +kubebuilder:default=per-pod
	Affinity string       `json:"affinity,omitempty"`
	Upstream UpstreamSpec `json:"upstream"`
	DNS      DNSConfig    `json:"dns,omitempty"`
	// v1 intentionally never falls back to an unprotected path.
	// +kubebuilder:validation:Enum=closed
	// +kubebuilder:default=closed
	FailMode          string                `json:"failMode,omitempty"`
	AllowedNamespaces AllowedNamespacesSpec `json:"allowedNamespaces,omitempty"`
	Exclusions        ExclusionsSpec        `json:"exclusions,omitempty"`
	Resources         GatewayResources      `json:"resources,omitempty"`
	// +kubebuilder:validation:MaxProperties=64
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	Tolerations []GatewayToleration `json:"tolerations,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.type != 'custom' || has(self.image)",message="image is required for a custom upstream"
type UpstreamSpec struct {
	// All values are part of the API, even when the corresponding plugin is not yet shipped.
	// +kubebuilder:validation:Enum=openvpn;wireguard;amneziawg;strongswan;custom
	Type string `json:"type"`
	// Legacy single-profile Secret in this Gateway namespace. Omit when profiles are set.
	SecretRef SecretReference `json:"secretRef,omitempty"`
	// Profiles create one independent gateway Pod/Deployment per Secret. Names
	// are unique DNS labels; profiles and legacy secretRef are mutually exclusive.
	// +kubebuilder:validation:MaxItems=8
	Profiles []UpstreamProfile `json:"profiles,omitempty"`
	// Image is mandatory for custom, optional override for built-in types.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Image string `json:"image,omitempty"`
}

// UpstreamProfile is an independent OpenVPN credential/exit profile. Secret
// contents remain in the Gateway namespace and never appear in API status.
type UpstreamProfile struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name      string          `json:"name"`
	SecretRef SecretReference `json:"secretRef"`
}

type SecretReference struct {
	// Secret in the gateway's namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

type DNSConfig struct {
	// +kubebuilder:validation:Enum=cluster;gateway
	// +kubebuilder:default=cluster
	Mode string `json:"mode,omitempty"`
}

type AllowedNamespacesSpec struct {
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

type ExclusionsSpec struct {
	// +kubebuilder:default=true
	AutoDetect *bool `json:"autoDetect,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.all(c, isCIDR(c))",message="each exclusion must be a valid CIDR"
	ExtraCIDRs []string `json:"extraCIDRs,omitempty"`
	// False blocks the metadata IP, true allows direct access. It is never sent via VPN.
	// +kubebuilder:default=false
	AllowCloudMetadata bool `json:"allowCloudMetadata,omitempty"`
}

// GatewayResources uses Kubernetes resource quantities without storing Kubernetes internal resource types.
type GatewayResources struct {
	Gateway ContainerResources `json:"gateway,omitempty"`
}

type ContainerResources struct {
	// +kubebuilder:validation:MaxProperties=32
	Limits map[string]resource.Quantity `json:"limits,omitempty"`
	// +kubebuilder:validation:MaxProperties=32
	Requests map[string]resource.Quantity `json:"requests,omitempty"`
}

type GatewayToleration struct {
	Key string `json:"key,omitempty"`
	// +kubebuilder:validation:Enum=Exists;Equal
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	// +kubebuilder:validation:Enum=NoSchedule;PreferNoSchedule;NoExecute
	Effect string `json:"effect,omitempty"`
	// +kubebuilder:validation:Minimum=0
	TolerationSeconds *int64 `json:"tolerationSeconds,omitempty"`
}

type EgressGatewayStatus struct {
	Phase              string `json:"phase,omitempty"`
	ReadyReplicas      int32  `json:"readyReplicas,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	// GatewayID is the controller-allocated stable GENEVE VNI, never user-settable.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=16777215
	GatewayID uint32 `json:"gatewayID,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	Endpoints []GatewayEndpoint `json:"endpoints,omitempty"`
	// +kubebuilder:validation:MaxItems=256
	EffectiveExclusions []EffectiveExclusion `json:"effectiveExclusions,omitempty"`
	MTU                 GatewayMTUStatus     `json:"mtu,omitempty"`
}

type GatewayEndpoint struct {
	PodName string `json:"podName,omitempty"`
	PodIP   string `json:"podIP"`
	// PodUID binds the applied configuration acknowledgment to this Pod instance,
	// not a replacement that reuses its name or IP.
	// +kubebuilder:validation:MaxLength=253
	PodUID string `json:"podUID,omitempty"`
	// AppliedClientConfigHash is the lowercase SHA-256 of the exact gateway.json
	// ConfigMap bytes consumed by this Pod after successful datapath application.
	// It proves the applied config without publishing the client IP list in status.
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=^[a-f0-9]{64}$
	AppliedClientConfigHash string `json:"appliedClientConfigHash,omitempty"`
	UpstreamExitIP          string `json:"upstreamExitIP,omitempty"`
	UpstreamHealthy         bool   `json:"upstreamHealthy"`
	WireguardPublicKey      string `json:"wireguardPublicKey,omitempty"`
	// RegistrationCACert is the PEM-encoded public, ephemeral CA certificate for
	// authenticated peer registration on this endpoint. Never publish a private key.
	// PEM is ASCII, so MaxLength also bounds the encoded value to 4096 bytes.
	// +kubebuilder:validation:MaxLength=4096
	// +kubebuilder:validation:Pattern=^-----BEGIN CERTIFICATE-----[[:space:]]+[A-Za-z0-9+/=[:space:]]+-----END CERTIFICATE-----[[:space:]]*$
	RegistrationCACert string `json:"registrationCACert,omitempty"`
}

type EffectiveExclusion struct {
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="must be a valid CIDR"
	CIDR string `json:"cidr"`
	// +kubebuilder:validation:Enum=podCIDR;serviceCIDR;node;apiserver;dns;linkLocal;extra
	Source string `json:"source"`
}

type GatewayMTUStatus struct {
	GeneveMTU    int32 `json:"geneveMTU,omitempty"`
	WireguardMTU int32 `json:"wireguardMTU,omitempty"`
	EffectiveMTU int32 `json:"effectiveMTU,omitempty"`
	MSS          int32 `json:"mss,omitempty"`
	// PerMode records the effective MTU for each supported datapath/encryption mode.
	PerMode map[string]int32 `json:"perMode,omitempty"`
}
