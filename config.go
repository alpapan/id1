package id1

// ResolveConfig resolves id1's bind port, bind address, KV store path, and optional
// Nextcloud proxy URL from the environment. getenv is injected (os.Getenv in main) so
// resolution is unit-testable. Values are read via getenv, so a .env entry (main calls
// godotenv.Load, which populates the process env - without overwriting real variables -
// before this runs) and a real environment variable both take effect.
//
// Bind-port precedence: PORT, then a numeric ID1_AUTH_PORT (the Kubernetes id1
// Deployment sets this to the container port), then 8080. DBPATH falls back to
// /mnt/id1db (the Kubernetes PVC mount).
//
// BIND_ADDR falls back to the wildcard "0.0.0.0". This is a deliberate default,
// not an oversight: inside a Kubernetes pod's network namespace there are only two
// interfaces (loopback and the pod's own CNI-assigned address), the pod's own
// address is not known to this process (no downward-API POD_IP is wired into the
// id1 Deployment today), and every in-cluster caller - including the backend pod
// reaching id1 over the CNI bridge, and kubelet's liveness/readiness probes -
// connects to that address, not to loopback. A bind narrowed to loopback would
// silently break all of that. BIND_ADDR exists so a HOST deployment outside
// Kubernetes (e.g. annot8r_id1 run directly on a machine with a public NIC) can
// override it to a specific, non-public interface; narrowing the in-cluster
// default is future work gated on wiring POD_IP into the Deployment.
func ResolveConfig(getenv func(string) string) (port, dbpath, nextcloudURL, bindAddr string) {
	port = getenv("PORT")
	if port == "" {
		// Accept ID1_AUTH_PORT only as a bare numeric port. Kubernetes injects a
		// Docker-link-style "<SVC>_PORT=tcp://IP:port" var for a Service whose name maps
		// to ID1_AUTH; that value is not a bindable port, so ignore it and fall through.
		if v := getenv("ID1_AUTH_PORT"); isNumericPort(v) {
			port = v
		}
	}
	if port == "" {
		port = "8080"
	}
	dbpath = getenv("DBPATH")
	if dbpath == "" {
		dbpath = "/mnt/id1db"
	}
	nextcloudURL = getenv("NEXTCLOUD_URL")
	bindAddr = getenv("BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	return port, dbpath, nextcloudURL, bindAddr
}

// isNumericPort reports whether s is a non-empty run of ASCII digits.
func isNumericPort(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
