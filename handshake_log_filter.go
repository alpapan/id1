package id1

import (
	"bytes"
	"io"
)

// NewHandshakeEOFFilter returns an io.Writer that filters out TLS handshake EOF errors.
func NewHandshakeEOFFilter(inner io.Writer) io.Writer {
	return &handshakeEOFFilter{inner: inner}
}

type handshakeEOFFilter struct {
	inner io.Writer
}

func (f *handshakeEOFFilter) Write(p []byte) (int, error) {
	trimmed := bytes.TrimRight(p, " \t\r\n")
	if bytes.Contains(p, []byte("TLS handshake error")) && bytes.HasSuffix(trimmed, []byte(": EOF")) {
		return len(p), nil
	}
	return f.inner.Write(p)
}
