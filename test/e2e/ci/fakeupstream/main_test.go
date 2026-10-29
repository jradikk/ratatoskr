package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestEcho(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/echo", nil)
	r.RemoteAddr = "198.19.0.2:12345"
	w := httptest.NewRecorder()
	echo(w, r)
	var result struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.IP != exitIP {
		t.Fatal("echo did not return caller address")
	}
}
func TestRejectInvalidRemoteConfig(t *testing.T) {
	mux := remoteMux(netip.MustParseAddr("10.42.2.4"))
	for _, tc := range []struct {
		method, body string
		code         int
	}{{http.MethodGet, "", 405}, {http.MethodPost, "not-json", 400}, {http.MethodPost, `{"unknown":"value"}`, 400}, {http.MethodPost, `{"gatewayIP":"2001:db8::1"}`, 500}} {
		r := httptest.NewRequest(tc.method, "/configure", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("status=%d want %d", w.Code, tc.code)
		}
	}
}
