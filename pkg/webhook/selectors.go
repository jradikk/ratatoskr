package webhook

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// selectorsOverlap checks whether two Kubernetes LabelSelectors can both match
// any pod, including a pod that does not exist yet. LabelSelector requirements
// constrain keys independently; for each key it suffices to try absence, each
// literal mentioned by either selector, and one value not mentioned by either.
func selectorsOverlap(a, b *metav1.LabelSelector) (bool, error) {
	left, err := metav1.LabelSelectorAsSelector(a)
	if err != nil {
		return false, fmt.Errorf("first workload selector: %w", err)
	}
	right, err := metav1.LabelSelectorAsSelector(b)
	if err != nil {
		return false, fmt.Errorf("second workload selector: %w", err)
	}
	lr, ok := left.Requirements()
	if !ok {
		return false, nil
	}
	rr, ok := right.Requirements()
	if !ok {
		return false, nil
	}
	byKey := map[string][]labels.Requirement{}
	for _, r := range append(lr, rr...) {
		byKey[r.Key()] = append(byKey[r.Key()], r)
	}
	for key, requirements := range byKey {
		literals := map[string]bool{}
		for _, r := range requirements {
			for _, v := range r.Values().List() {
				literals[v] = true
			}
		}
		sentinel := "ratatoskr-other"
		for literals[sentinel] {
			sentinel += "-other"
		}
		candidates := []labels.Set{{}, {key: sentinel}}
		for v := range literals {
			candidates = append(candidates, labels.Set{key: v})
		}
		compatible := false
		for _, candidate := range candidates {
			all := true
			for _, r := range requirements {
				if !r.Matches(candidate) {
					all = false
					break
				}
			}
			if all {
				compatible = true
				break
			}
		}
		if !compatible {
			return false, nil
		}
	}
	return true, nil
}
