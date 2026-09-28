// apps/backend/containers/id1/pub_sub.go
//
// group: utils
// tags: pubsub, events, channels
// summary: Publish-subscribe system for command change notifications.
// Manages subscriptions and broadcasts command events to registered listeners.
//
//

package id1

import (
	"slices"
	"sync"
)

type PubSub struct {
	mu   sync.Mutex
	subs map[string][]chan Command
}

func NewPubSub() PubSub {
	return PubSub{
		subs: make(map[string][]chan Command),
	}
}

func (t *PubSub) Publish(cmd *Command) {
	t.mu.Lock()
	subs := make([]chan Command, len(t.subs[cmd.Key.Id]))
	copy(subs, t.subs[cmd.Key.Id])
	t.mu.Unlock()
	for _, ch := range subs {
		// A best-effort, non-blocking send. ch is never closed (see
		// Unsubscribe), so this can never panic on a closed channel; the
		// default case is what keeps a departed or slow subscriber from
		// blocking every Set/Del on the server - Publish runs on the calling
		// goroutine of every write, including the TTL sweeper.
		select {
		case ch <- *cmd:
		default:
		}
	}
}

func (t *PubSub) Subscribe(id string) chan Command {
	ch := make(chan Command, 32)
	t.mu.Lock()
	t.subs[id] = append(t.subs[id], ch)
	t.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from id's subscriber list. It never closes ch: a
// concurrent Publish may already have copied ch out of the list and be about
// to send on it (see Publish), and closing here would turn that send into a
// panic. An unsubscribed, unclosed channel is simply never read again and is
// garbage-collected once its last reference (this list, and the session that
// held it) is gone.
func (t *PubSub) Unsubscribe(id string, ch chan Command) {
	t.mu.Lock()
	defer t.mu.Unlock()
	chIndex := slices.Index(t.subs[id], ch)
	if chIndex < 0 {
		return
	}
	t.subs[id] = slices.Delete(t.subs[id], chIndex, chIndex+1)
}

func (t *PubSub) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ch := range t.subs {
		for _, sub := range ch {
			close(sub)
		}
	}
}
