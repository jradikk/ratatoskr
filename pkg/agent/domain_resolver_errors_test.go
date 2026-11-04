//go:build linux

package agent

import (
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestResolverServiceAPIFailuresAreActionableAndRedacted(t *testing.T) {
	resource := schema.GroupResource{Resource: "services"}
	for _, tc := range []struct {
		name     string
		err      error
		category string
	}{
		{"forbidden", apierrors.NewForbidden(resource, "berlin-dns", nil), "permission-denied"},
		{"missing", apierrors.NewNotFound(resource, "berlin-dns"), "service-not-found"},
		{"unauthorized", apierrors.NewUnauthorized("private-token"), "permission-denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := domainStartupFailure("resolver-service", tc.err)
			if !strings.Contains(got.Error(), tc.category) || strings.Contains(got.Error(), "private-token") || strings.Contains(got.Error(), "berlin-dns") {
				t.Fatalf("unsafe/unhelpful diagnostic: %v", got)
			}
		})
	}
}
