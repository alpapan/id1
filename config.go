package id1

// ResolveConfig resolves id1's bind port, KV store path, and optional Nextcloud proxy
// URL from the environment. getenv is injected (os.Getenv in main) so resolution is
// unit-testable. Values are read via getenv, so a .env entry (main calls
// godotenv.Load, which populates the process env - without overwriting real variables -
// before this runs) and a real environment variable both take effect.
//
// Bind-port precedence: PORT, then a numeric ID1_AUTH_PORT (the Kubernetes id1
// Deployment sets this to the container port), then 8080. DBPATH falls back to
// /mnt/id1db (the Kubernetes PVC mount).
func ResolveConfig(getenv func(string) string) (port, dbpath, nextcloudURL string) {
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
	return port, dbpath, nextcloudURL
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
