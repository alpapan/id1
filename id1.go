// apps/id1/id1.go
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
			ok200(w, r, []byte{})
			return
		}

		req := NewRequestProps(r)

		// A body past the cap is refused before anything else is decided, so the
		// answer does not depend on who is asking.
		if req.BodyTooLarge {
			err413(w, r, "")
			return
		}

		// A path K() refused is a malformed request, not an authorisation
		// failure: answer 400 and stop here, so no operation ever sees a key
		// that could not be constructed.
		if req.KeyErr != nil {
			err400(w, r, "invalid key")
			return
		}

		if req.Id == "" {
			err404(w, r, "")
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

		// A WebSocket session binds an identity for the whole life of the
		// connection and authorises every later frame as that identity, so a
		// public-read grant is not sufficient to open one: reading {id}/pub/... is
		// public, but acting AS {id} is not. An unauthenticated upgrade is
		// answered with the same 401 and encrypted challenge the ordinary HTTP
		// path uses, so a client can complete the handshake and dial again with a
		// token.
		if req.IsWebSocket {
			if !mayOpenSession(id, req.Cmd, r.Header.Get("X-ID1-Internal-Secret")) {
				refuseUnauthorised(w, r, id, req.Id)
				return
			}
			upgrader := websocket.Upgrader{}
			upgrader.CheckOrigin = checkBrowserOrigin
			wsHandler := webSocketHandler{
				upgrader: upgrader,
			}
			wsHandler.Handle(w, r, id)
			return
		}

		// ExecAs authorises the command itself; an authorisation refusal comes
		// back as ErrUnauthorised and is answered like an unauthenticated request.
		if data, err := req.Cmd.ExecAs(id, r.Header.Get("X-ID1-Internal-Secret")); err == nil {
			ok200(w, r, data)
		} else if errors.Is(err, ErrUnauthorised) {
			refuseUnauthorised(w, r, id, req.Id)
		} else if errors.Is(err, ErrForbidden) {
			err403(w, r, "")
		} else if errors.Is(err, ErrNotFound) {
			err404(w, r, "")
		} else if errors.Is(err, ErrLimitExceeded) {
			err413(w, r, "")
		} else {
			err400(w, r, err.Error())
		}
	}
}

// mayOpenSession reports whether the caller may open a WebSocket session: it
// must be identified and authorised for the command the upgrade request names.
func mayOpenSession(id string, cmd Command, internalSecretHeader string) bool {
	return id != "" && auth(id, cmd, internalSecretHeader)
}

// refuseUnauthorised answers a request whose caller may not run its command:
// 403 when the caller is identified, otherwise the 401 and encrypted challenge
// for the targeted account's device key, or 404 when there is no such key.
func refuseUnauthorised(w http.ResponseWriter, r *http.Request, callerId string, targetId string) {
	if len(callerId) > 0 {
		err403(w, r, "")
		return
	}
	deviceId := r.URL.Query().Get("device")
	if deviceId == "" {
		deviceId = "default"
	}
	if !validDeviceID(deviceId) {
		err404(w, r, "")
		return
	}
	deviceKey, keyErr := KK(targetId, "pub", "keys", deviceId)
	if keyErr != nil {
		err404(w, r, "")
		return
	}
	if pubKey, err := CmdGet(deviceKey).execUnauthorised(); err == nil {
		if challenge, err := generateChallenge(targetId, string(pubKey)); err == nil {
			err401(w, r, challenge)
		} else {
			err500(w, r, err.Error())
		}
	} else {
		if !errors.Is(err, ErrNotFound) {
			log.Printf("device key lookup failed for id %q device %q: %v", targetId, deviceId, err)
		}
		err404(w, r, "")
	}
}

// __END_OF_FILE_MARKER__
