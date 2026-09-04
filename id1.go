// apps/backend/containers/id1/id1.go
//
// group: server
// tags: http, server, websocket, pubsub
// summary: Main HTTP server and WebSocket listener for id1 router.
// Initializes pub/sub system, sets up HTTP handlers, and manages server lifecycle.
//
//

package id1

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var pubsub = NewPubSub()
var dbpath = "/mnt/id1db"
var version = "latest"

func Handle(path string, ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	dbpath = path

	go func() {
		for {
			select {
			case <-time.After(time.Second * 10):
				dotAfter(dbpath)
			case <-ctx.Done():
				return
			}
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			ok200(w, []byte{})
			return
		}

		req := NewRequestProps(r)

		// A path K() refused is a malformed request, not an authorisation
		// failure: answer 400 and stop here, so no operation ever sees a key
		// that could not be constructed.
		if req.KeyErr != nil {
			err400(w, "invalid key")
			return
		}

		if req.Id == "" {
			err404(w, "")
			return
		}

		id := ""
		if claims, _ := validateToken(req.Token, ""); len(claims.Subject) > 0 {
			id = claims.Subject
			if secret, err := generateSecret(id); err != nil {
				log.Printf("generateSecret failed for id %q: %v", id, err)
				id = ""
			} else if _, err := validateToken(req.Token, secret); err != nil {
				id = ""
			}
		}
		req.Cmd.Args["x-id"] = id

		authOk := auth(id, req.Cmd, r.Header.Get("X-ID1-Internal-Secret"))

		// A WebSocket session binds an identity for the whole life of the
		// connection and authorises every later frame as that identity, so a
		// public-read grant is not sufficient to open one: reading {id}/pub/... is
		// public, but acting AS {id} is not. Clearing authOk here routes an
		// unauthenticated upgrade into the branch below, which answers it with the
		// same 401 and encrypted challenge the ordinary HTTP path uses, so a
		// client can complete the handshake and dial again with a token.
		if req.IsWebSocket && id == "" {
			authOk = false
		}

		if !authOk {
			if len(id) > 0 {
				err403(w, "")
			} else {
				deviceId := r.URL.Query().Get("device")
				if deviceId == "" {
					deviceId = "default"
				}
				if !devicePattern.MatchString(deviceId) {
					err404(w, "")
					return
				}
				deviceKey, keyErr := KK(req.Id, "pub", "keys", deviceId)
				if keyErr != nil {
					err404(w, keyErr.Error())
					return
				}
				if pubKey, err := CmdGet(deviceKey).Exec(); err == nil {
					if challenge, err := generateChallenge(req.Id, string(pubKey)); err == nil {
						err401(w, challenge)
					} else {
						err500(w, err.Error())
					}
				} else {
					if !errors.Is(err, ErrNotFound) {
						log.Printf("device key lookup failed for id %q device %q: %v", req.Id, deviceId, err)
					}
					err404(w, "")
				}
			}
			return
		}

		if req.IsWebSocket {
			upgrader := websocket.Upgrader{}
			upgrader.CheckOrigin = func(r *http.Request) bool { return true }
			wsHandler := webSocketHandler{
				upgrader: upgrader,
			}
			wsHandler.Handle(w, r, id)
		} else if data, err := req.Cmd.Exec(); err == nil {
			ok200(w, data)
		} else if errors.Is(err, ErrForbidden) {
			err403(w, "")
		} else if errors.Is(err, ErrNotFound) {
			err404(w, "")
		} else if errors.Is(err, ErrLimitExceeded) {
			err413(w, "")
		} else {
			err400(w, err.Error())
		}
	}
}

// __END_OF_FILE_MARKER__
