// apps/backend/containers/id1/sync_proxy.go
//
// group: middleware
// tags: websocket, proxy, automerge, sync
// summary: WebSocket proxy for real-time collaborative sync server.
// Relays bidirectional frames between browser and Automerge sync backend.
//
//

package id1

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
)

// SyncProxy creates a WebSocket reverse proxy for Automerge sync requests.
// target is host:port, e.g. "automerge-sync-server:8100".
// The /sync path prefix is stripped so the sync server receives connections at /.
//
// Uses gorilla/websocket on both sides for proper bidirectional frame relay,
// rather than httputil.ReverseProxy which doesn't handle WebSocket streaming.
func SyncProxy(target string) (http.HandlerFunc, error) {
	scheme := "ws"
	var tlsConfig *tls.Config

	transport, err := BuildTLSTransport()
	if err != nil {
		return nil, fmt.Errorf("sync proxy TLS transport: %w", err)
	}
	if transport != nil {
		scheme = "wss"
		tlsConfig = transport.TLSClientConfig
	}

	backendURL, err := url.Parse(scheme + "://" + target)
	if err != nil {
		return nil, fmt.Errorf("invalid AUTOMERGE_SYNC_SERVER: %w", err)
	}

	clientUpgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Upgrade the inbound (browser → id1) connection
		clientConn, err := clientUpgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[sync-proxy] client upgrade failed: %v", err)
			return
		}
		defer clientConn.Close()

		// Dial the backend (id1 → automerge-sync-server)
		dialer := websocket.Dialer{}
		if tlsConfig != nil {
			dialer.TLSClientConfig = tlsConfig
		}
		backendConn, resp, err := dialer.Dial(backendURL.String()+"/", nil)
		if err != nil {
			if resp != nil {
				log.Printf("[sync-proxy] backend dial failed (HTTP %d): %v", resp.StatusCode, err)
			} else {
				log.Printf("[sync-proxy] backend dial failed: %v", err)
			}
			return
		}
		defer backendConn.Close()

		log.Printf("[sync-proxy] connected %s -> %s", r.RemoteAddr, backendURL.Host)

		errc := make(chan error, 2)

		// client → backend
		go func() {
			errc <- pumpFrames(clientConn, backendConn)
		}()

		// backend → client
		go func() {
			errc <- pumpFrames(backendConn, clientConn)
		}()

		// Wait for either direction to close
		<-errc
	}, nil
}

// pumpFrames copies WebSocket frames from src to dst until an error or close.
func pumpFrames(src, dst *websocket.Conn) error {
	for {
		msgType, reader, err := src.NextReader()
		if err != nil {
			return err
		}
		writer, err := dst.NextWriter(msgType)
		if err != nil {
			return err
		}
		if _, err := io.Copy(writer, reader); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
	}
}

// __END_OF_FILE_MARKER__
