// apps/backend/containers/id1/ws_handler.go
//
// group: server
// tags: websocket, pubsub, events
// summary: WebSocket handler for pub/sub command notifications.
// Manages subscriptions and broadcasts changes to connected clients.
//
//

package id1

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type webSocketHandler struct {
	upgrader websocket.Upgrader
}

// Handle upgrades a request to a WebSocket session. id is the authenticated
// subject of the caller's verified Bearer token, established by Handle in
// id1.go - NEVER the first segment of the request path. A path-derived identity
// let an unauthenticated caller upgrade on {victim}/pub/... (which auth grants
// as a public read) and then hold owner rights over the victim for the life of
// the connection.
//
// Because the path no longer decides anything, it is not parsed here at all: a
// malformed path cannot influence a session it has no say in.
func (t webSocketHandler) Handle(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		// id1.go refuses an unauthenticated upgrade before reaching this point.
		// This is the second layer: a session with no proven identity is never
		// opened, whatever routed us here. This cannot reproduce the ordinary
		// HTTP path's encrypted challenge - by the time id is empty here, the
		// caller's claimed account and its public key are no longer available -
		// so it refuses bare.
		log.Printf("websocket handle: refusing an unauthenticated upgrade for %q", r.URL.Path)
		err401(w, "")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmdIn := make(chan (Command))

	if conn, err := t.upgrader.Upgrade(w, r, nil); err != nil {
		log.Printf("error upgrading to websocket. %s", err)
	} else {
		session := Session{
			Id:     id,
			Conn:   conn,
			CmdOut: pubsub.Subscribe(id),
			CmdIn:  cmdIn,
			Ctx:    ctx,
			Cancel: cancel,
		}
		defer session.Disconnect()
		session.OnConnect()
	}
	<-ctx.Done()
	cancel()
}

type Session struct {
	Id     string
	Conn   *websocket.Conn
	CmdIn  chan Command
	CmdOut chan Command
	Ctx    context.Context
	Cancel func()
}

func (t *Session) OnConnect() {
	go t.handleCommands()
	go t.readCommands()
	go t.writeCommands()
	go t.ping()

	log.Printf("connected: %s", t.Id)
	if onlineKey, err := KK(t.Id, ".online"); err != nil {
		log.Printf("onconnect: skipping online marker for %s: %v", t.Id, err)
	} else if _, err := CmdSet(onlineKey, map[string]string{}, []byte{}).Exec(); err != nil {
		log.Printf("cmd set error: %s", err)
	}
	t.CmdOut = pubsub.Subscribe(t.Id)
}

func (t *Session) Disconnect() {
	if onlineKey, err := KK(t.Id, ".online"); err != nil {
		log.Printf("disconnect: skipping online marker cleanup for %s: %v", t.Id, err)
	} else {
		CmdDel(onlineKey).Exec()
	}
	pubsub.Unsubscribe(t.Id, t.CmdOut)
	t.Conn.Close()
	log.Printf("disconnected: %s", t.Id)
}

func (t *Session) ping() {
	for {
		select {
		case <-time.After(time.Second * 120):
			if pingKey, err := KK(t.Id, ".ping"); err != nil {
				log.Printf("ping: skipping ping for %s: %v", t.Id, err)
			} else {
				t.CmdOut <- CmdGet(pingKey)
			}
		case <-t.Ctx.Done():
			return
		}
	}
}

func (t *Session) readCommands() {
	for {
		if _, data, err := t.Conn.ReadMessage(); err != nil {
			t.Conn.Close()
			t.Cancel()
			return
		} else if cmd, err := ParseCommand(data); err != nil {
			log.Printf("error parsing websocket message: %s", err)
		} else {
			t.CmdIn <- cmd
		}
	}
}

func (t *Session) writeCommands() {
	for {
		select {
		case cmd := <-t.CmdOut:
			if err := t.Conn.WriteMessage(websocket.BinaryMessage, cmd.Bytes()); err != nil {
				log.Println("write err", err)
				t.Cancel()
				return
			}
		case <-t.Ctx.Done():
			return
		}
	}
}

func (t *Session) handleCommands() {
	timeout := time.Second * 600
	for {
		select {
		case cmd := <-t.CmdIn:
			if cmd.Op == Get && cmd.Key.String() == fmt.Sprintf("%s/.ping", t.Id) {
				continue
			}

			cmd.Args["x-id"] = t.Id

			// No per-message header exists on a WebSocket-framed command (the header
			// was only present on the original HTTP upgrade request, already
			// authorized by id1.go's Handle before the connection was upgraded), so
			// the internal-secret new-id bootstrap exemption is never available here.
			authOk := auth(t.Id, cmd, "")

			if !authOk {
				// Use "default" device for WebSocket challenge-response
				defaultKeyKey, keyErr := KK(t.Id, "pub", "keys", "default")
				if keyErr != nil {
					log.Println(keyErr)
					continue
				}
				if pubKey, err := CmdGet(defaultKeyKey).Exec(); err == nil {
					if challenge, err := generateChallenge(t.Id, string(pubKey)); err == nil {
						if authKey, err := KK(t.Id, "auth"); err != nil {
							log.Println(err)
						} else {
							t.CmdOut <- CmdSet(authKey, map[string]string{}, []byte(challenge))
						}
					} else {
						log.Println(err)
					}
				} else {
					log.Println(err)
				}
				continue
			}

			if data, err := cmd.Exec(); err == nil {
				t.CmdOut <- CmdSet(cmd.Key, map[string]string{}, data)
			} else if errors.Is(ErrNotFound, err) {
				t.CmdOut <- CmdDel(cmd.Key)
			} else {
				log.Printf("error executing command: %s", err)
			}
		case <-time.After(timeout):
			//log.Printf("no commands, disconnecting...")
			t.Cancel()
			return
		case <-t.Ctx.Done():
			return
		}
	}
}
