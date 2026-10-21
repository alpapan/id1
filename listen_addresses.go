package id1

import (
	"fmt"
	"net"
	"strings"
)

// ListenAddresses turns the BIND_ADDR value into the "host:port" strings id1 listens on,
// one per comma-separated entry. It has no default: an empty or blank value is an error,
// so a deployment that does not name an address cannot start a listener on every
// interface. An entry still holding "$" is an unresolved Kubernetes variable reference
// (for example "$(POD_IP)" in a pod that never declared POD_IP) and is refused for the
// same reason. A wildcard an operator wrote on purpose (the annot8r_id1 host daemon's
// env file) is passed through unchanged: refusing it here would break that deployment,
// and its own installer decides whether the address is acceptable.
func ListenAddresses(bindAddr, port string) ([]string, error) {
	if strings.TrimSpace(bindAddr) == "" {
		return nil, fmt.Errorf("BIND_ADDR is unset or empty: id1 listens only on the addresses its deployment names and has no default")
	}
	var addrs []string
	for _, part := range strings.Split(bindAddr, ",") {
		host := strings.TrimSpace(part)
		if host == "" {
			return nil, fmt.Errorf("BIND_ADDR %q has an empty entry", bindAddr)
		}
		if strings.Contains(host, "$") {
			return nil, fmt.Errorf("BIND_ADDR entry %q holds an unresolved reference: the deployment must define the variable it names", host)
		}
		addrs = append(addrs, net.JoinHostPort(host, port))
	}
	return addrs, nil
}
