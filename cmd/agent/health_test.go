package main

import "testing"

func TestAgentHealthAddress(t *testing.T) {
	for _, tc := range []struct {
		port, want string
		invalid    bool
	}{
		{"", "0.0.0.0:19903", false},
		{"19904", "0.0.0.0:19904", false},
		{"0", "", true}, {"65536", "", true}, {"localhost:8081", "", true},
	} {
		t.Run(tc.port, func(t *testing.T) {
			t.Setenv("HEALTH_PORT", tc.port)
			got, err := agentHealthAddress()
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("address=%q error=%v", got, err)
			}
		})
	}
}
