package id1

import "testing"

// ResolveConfig reads PORT/DBPATH/NEXTCLOUD_URL/BIND_ADDR from the injected env lookup,
// so values supplied by a .env file (godotenv populates the process env) or by real
// environment variables take effect. These cases pin that precedence, the numeric
// ID1_AUTH_PORT guard, and BIND_ADDR's wildcard default.
func TestResolveConfig(t *testing.T) {
	tests := []struct {
		name         string
		env          map[string]string
		wantPort     string
		wantDBPath   string
		wantNCURL    string
		wantBindAddr string
	}{
		{
			name:         "PORT from env is honoured",
			env:          map[string]string{"PORT": "8081"},
			wantPort:     "8081",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "DBPATH from env is honoured",
			env:          map[string]string{"DBPATH": "/var/lib/annot8r-id1"},
			wantPort:     "8080",
			wantDBPath:   "/var/lib/annot8r-id1",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "empty env falls back to the code defaults",
			env:          map[string]string{},
			wantPort:     "8080",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "PORT wins over ID1_AUTH_PORT",
			env:          map[string]string{"PORT": "9000", "ID1_AUTH_PORT": "8080"},
			wantPort:     "9000",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "numeric ID1_AUTH_PORT used when PORT unset (Kubernetes)",
			env:          map[string]string{"ID1_AUTH_PORT": "8080"},
			wantPort:     "8080",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "0.0.0.0",
		},
		{
			name: "non-numeric ID1_AUTH_PORT is ignored (Kubernetes Docker-link var)",
			env:  map[string]string{"ID1_AUTH_PORT": "tcp://10.0.0.1:8080"},
			// A "<SVC>_PORT=tcp://IP:port" link var is not a bindable port; fall to default.
			wantPort:     "8080",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "NEXTCLOUD_URL passes through",
			env:          map[string]string{"NEXTCLOUD_URL": "http://nextcloud:80"},
			wantPort:     "8080",
			wantDBPath:   "/mnt/id1db",
			wantNCURL:    "http://nextcloud:80",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "BIND_ADDR from env is honoured",
			env:          map[string]string{"BIND_ADDR": "127.0.0.1"},
			wantPort:     "8080",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "127.0.0.1",
		},
		{
			name:         "empty BIND_ADDR falls back to the wildcard default",
			env:          map[string]string{"BIND_ADDR": ""},
			wantPort:     "8080",
			wantDBPath:   "/mnt/id1db",
			wantBindAddr: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string { return tt.env[k] }
			port, dbpath, ncURL, bindAddr := ResolveConfig(getenv)
			if port != tt.wantPort {
				t.Errorf("port = %q, want %q", port, tt.wantPort)
			}
			if dbpath != tt.wantDBPath {
				t.Errorf("dbpath = %q, want %q", dbpath, tt.wantDBPath)
			}
			if ncURL != tt.wantNCURL {
				t.Errorf("nextcloudURL = %q, want %q", ncURL, tt.wantNCURL)
			}
			if bindAddr != tt.wantBindAddr {
				t.Errorf("bindAddr = %q, want %q", bindAddr, tt.wantBindAddr)
			}
		})
	}
}
