// apps/id1/ws_origin.go
//
// group: server
// tags: websocket, origin, security
// summary: The single Origin check every production WebSocket upgrader uses.
//
//

package id1

import "net/http"

// checkBrowserOrigin is the CheckOrigin function of every production
// websocket.Upgrader. A browser always sends Origin on a WebSocket handshake,
// so a request with no Origin header is a non-browser client and passes; a
// request with an Origin header passes only when it carries exactly one value
// and that value is the configured browser origin byte for byte (no prefix
// match, no case folding, no trailing-slash tolerance; "null" and an empty
// value are refused).
func checkBrowserOrigin(r *http.Request) bool {
	values := r.Header["Origin"]
	if len(values) == 0 {
		return true
	}
	return len(values) == 1 && values[0] == browserOrigin()
}
