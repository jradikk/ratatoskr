package observability

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// MetricsEnabled defaults to true; only the exact literal "false" turns off
// a component's metrics listener. Invalid values never silently disable it.
func MetricsEnabled(value string) (bool, error) {
	switch value {
	case "", "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("METRICS_ENABLED must be true or false")
	}
}

// MetricsBindAddress validates a literal IPv4 listen address without DNS,
// shell expansion or Unix sockets. Empty uses the component's fixed default.
// A disabled listener is controlled separately by METRICS_ENABLED=false.
func MetricsBindAddress(value, fallback string) (string, error) {
	if value == "" {
		value = fallback
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.Contains(host, "%") {
		return "", errors.New("metrics bind must be literal IPv4 host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || ip.String() != host {
		return "", errors.New("metrics bind must be literal IPv4 host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", errors.New("metrics port must be decimal in 1..65535")
	}
	return net.JoinHostPort(host, port), nil
}

// ManagerMetricsBindAddress returns the controller-runtime metrics bind address.
// Controller-runtime uses "0" to disable its metrics server entirely.
func ManagerMetricsBindAddress(enabledValue, addressValue, fallback string) (string, error) {
	enabled, err := MetricsEnabled(enabledValue)
	if err != nil {
		return "", err
	}
	if !enabled {
		return "0", nil
	}
	return MetricsBindAddress(addressValue, fallback)
}
