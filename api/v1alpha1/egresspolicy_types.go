package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=epol
// EgressPolicy selects workloads and destinations in its namespace.
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EgressPolicySpec   `json:"spec"`
	Status            EgressPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressPolicy `json:"items"`
}

type EgressPolicySpec struct {
	GatewayRef       GatewayReference     `json:"gatewayRef"`
	WorkloadSelector metav1.LabelSelector `json:"workloadSelector"`
	// +kubebuilder:validation:Enum=include;exclude
	Mode string `json:"mode"`
	// An empty include rules list selects no destinations; an empty exclude rules list selects all.
	// +kubebuilder:validation:MaxItems=64
	Rules []EgressRule `json:"rules,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.all(c, isCIDR(c))",message="each exclusion must be a valid CIDR"
	ExcludeCIDRs []string `json:"excludeCIDRs,omitempty"`
}

type GatewayReference struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// If omitted, controllers resolve the gateway in the operator namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace,omitempty"`
}

type EgressRule struct {
	// Empty CIDRs matches any destination only when Domains is also empty.
	// A domain-only rule remains unresolved/closed until trusted DNS answers
	// are learned by the agent; CIDRs and domains are OR alternatives and the
	// same ports apply to both alternatives.
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.all(c, isCIDR(c))",message="each destination must be a valid CIDR"
	CIDRs []string `json:"cidrs,omitempty"`
	// Domains may be used only by agent driver with gateway DNS mode. DNS names
	// are canonical lowercase ASCII with no trailing dot; a leading '*.'
	// matches one or more subdomain labels but never the suffix apex.
	// +kubebuilder:validation:MaxItems=64
	Domains []DomainSelector `json:"domains,omitempty"`
	// +kubebuilder:validation:MaxItems=64
	Ports []EgressPort `json:"ports,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="has(self.matchName) != has(self.matchPattern)",message="exactly one of matchName or matchPattern is required"
// +kubebuilder:validation:XValidation:rule="!has(self.matchName) || self.matchName.split('.').all(label, size(label) <= 63)",message="DNS labels must be at most 63 characters"
// +kubebuilder:validation:XValidation:rule="!has(self.matchPattern) || self.matchPattern.substring(2).split('.').all(label, size(label) <= 63)",message="wildcard suffix labels must be at most 63 characters"
type DomainSelector struct {
	// Exact DNS name; canonical lowercase ASCII without a trailing dot.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern="^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
	MatchName string `json:"matchName,omitempty"`
	// Only '*.example.com' suffix wildcards, with at least two suffix labels.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern="^\\*\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
	MatchPattern string `json:"matchPattern,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.endPort) || self.endPort >= self.port",message="endPort must be at least port"
type EgressPort struct {
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	EndPort *int32 `json:"endPort,omitempty"`
}

type EgressPolicyStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
