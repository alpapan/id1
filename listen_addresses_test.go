package id1

import (
	"reflect"
	"strings"
	"testing"
)

func TestListenAddresses(t *testing.T) {
	tests := []struct {
		name      string
		bindAddr  string
		port      string
		want      []string
		wantError string
	}{
		{
			name:     "one address",
			bindAddr: "10.42.0.7",
			port:     "8080",
			want:     []string{"10.42.0.7:8080"},
		},
		{
			name:     "pod address and loopback",
			bindAddr: "10.42.0.7,127.0.0.1",
			port:     "8080",
			want:     []string{"10.42.0.7:8080", "127.0.0.1:8080"},
		},
		{
			name:     "spaces around entries are trimmed",
			bindAddr: " 10.42.0.7 , 127.0.0.1 ",
			port:     "9000",
			want:     []string{"10.42.0.7:9000", "127.0.0.1:9000"},
		},
		{
			name:     "an ipv6 address is bracketed",
			bindAddr: "::1",
			port:     "8080",
			want:     []string{"[::1]:8080"},
		},
		{
			name:     "a host-daemon wildcard an operator wrote is passed through, not refused",
			bindAddr: "0.0.0.0",
			port:     "8080",
			want:     []string{"0.0.0.0:8080"},
		},
		{
			name:      "empty is refused",
			bindAddr:  "",
			port:      "8080",
			wantError: "BIND_ADDR is unset or empty",
		},
		{
			name:      "blank is refused",
			bindAddr:  "   ",
			port:      "8080",
			wantError: "BIND_ADDR is unset or empty",
		},
		{
			name:      "an empty entry is refused",
			bindAddr:  "10.42.0.7,,127.0.0.1",
			port:      "8080",
			wantError: "empty entry",
		},
		{
			name:      "a trailing comma is refused",
			bindAddr:  "10.42.0.7,",
			port:      "8080",
			wantError: "empty entry",
		},
		{
			name:      "an unresolved kubernetes reference is refused",
			bindAddr:  "$(POD_IP),127.0.0.1",
			port:      "8080",
			wantError: "unresolved reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ListenAddresses(tt.bindAddr, tt.port)
			if tt.wantError != "" {
				if err == nil {
					t.Fatalf("ListenAddresses(%q, %q) = %v, want an error containing %q", tt.bindAddr, tt.port, got, tt.wantError)
				}
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListenAddresses(%q, %q) returned error: %v", tt.bindAddr, tt.port, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ListenAddresses(%q, %q) = %v, want %v", tt.bindAddr, tt.port, got, tt.want)
			}
		})
	}
}
