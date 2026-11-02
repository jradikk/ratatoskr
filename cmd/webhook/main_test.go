package main

import "testing"

func TestOperatorNamespaceOverride(t *testing.T) {
	t.Setenv("NAMESPACE", "webhook-service")
	t.Setenv("OPERATOR_NAMESPACE", "egress-operator")
	if got := operatorNamespace(); got != "egress-operator" {
		t.Fatalf("operator namespace override: %q", got)
	}
	t.Setenv("OPERATOR_NAMESPACE", "")
	if got := operatorNamespace(); got != "webhook-service" {
		t.Fatalf("namespace fallback: %q", got)
	}
}
