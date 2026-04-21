package id1

import (
	"bytes"
	"testing"
)

func TestHandshakeEOFFilter(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		shouldWrite   bool
		expectedWrite string
	}{
		{
			name:        "drops TLS handshake EOF with LF",
			input:       "2026/04/22 10:00:00 http: TLS handshake error from 10.42.0.11:54321: EOF\n",
			shouldWrite: false,
		},
		{
			name:          "passes through non-EOF TLS error",
			input:         "2026/04/22 10:00:00 http: TLS handshake error from 1.2.3.4:54321: tls: first record does not look like a TLS handshake\n",
			shouldWrite:   true,
			expectedWrite: "2026/04/22 10:00:00 http: TLS handshake error from 1.2.3.4:54321: tls: first record does not look like a TLS handshake\n",
		},
		{
			name:          "passes through unrelated line",
			input:         "2026/04/22 10:00:00 something unrelated\n",
			shouldWrite:   true,
			expectedWrite: "2026/04/22 10:00:00 something unrelated\n",
		},
		{
			name:          "passes through empty input",
			input:         "",
			shouldWrite:   true,
			expectedWrite: "",
		},
		{
			name:        "drops TLS handshake EOF with CRLF",
			input:       "2026/04/22 10:00:00 http: TLS handshake error from 10.42.0.11:54321: EOF\r\n",
			shouldWrite: false,
		},
		{
			name:        "drops TLS handshake EOF without newline",
			input:       "2026/04/22 10:00:00 http: TLS handshake error from 10.42.0.11:54321: EOF",
			shouldWrite: false,
		},
		{
			name:          "passes through TLS error with non-EOF suffix",
			input:         "2026/04/22 10:00:00 http: TLS handshake error from 1.2.3.4:54321: read: connection reset\n",
			shouldWrite:   true,
			expectedWrite: "2026/04/22 10:00:00 http: TLS handshake error from 1.2.3.4:54321: read: connection reset\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			filter := NewHandshakeEOFFilter(buf)

			p := []byte(tt.input)
			n, err := filter.Write(p)

			if err != nil {
				t.Fatalf("Write returned error: %v", err)
			}

			if n != len(p) {
				t.Fatalf("Write returned %d, expected %d", n, len(p))
			}

			if tt.shouldWrite {
				if buf.String() != tt.expectedWrite {
					t.Fatalf("inner.Write called with %q, expected %q", buf.String(), tt.expectedWrite)
				}
			} else {
				if buf.String() != "" {
					t.Fatalf("inner.Write should not be called, but was called with %q", buf.String())
				}
			}
		})
	}
}
