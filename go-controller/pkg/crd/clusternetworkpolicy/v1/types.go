package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	api "k8s.io/kubernetes/pkg/apis/core"
)

// +genclient
// +resource:path=clusternetworkpolicy
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="ClusterNetworkPolicy Status",type=string,JSONPath=".status.status"
// ClusterNetworkPolicy is a cluster scoped resource targeted for use by cluster admins (in 
// contrast with the NetworkPolicy resource which is namespace scoped and typically targeted for 
// use by application developers/ devops teams. ClusterNetworkPolicy takes precedence over 
// NetworkPolicy in the networking data plane


type ClusterNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of the ClusterNetworkPolicy 
	Spec ClusterNetworkPolicySpec `json:"spec"`
	// Observed status of ClusterNetworkPolicy 
	// +optional
	Status ClusterNetworkPolicyStatus `json:"status,omitempty"`
}

type ClusterNetworkPolicyStatus struct {
	Status string `json:"status,omitempty"`
}

// ClusterNetworkPolicySpec is a desired state description of ClusterNetworkPolicy.
// For now, simply make identical to NetworkPolicySpec from the core networking api
type NetworkPolicySpec ClusterNetworkPolicySpec 


// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterNetworkPolicyList is a list of ClusterNetworkPolicy objects.
type ClusterNetworkPolicyList struct {
	metav1.TypeMeta
	// +optional
	metav1.ListMeta

	Items []ClusterNetworkPolicy
}

