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
	for _, ch := range t.subs[cmd.Key.Id] {
		ch <- *cmd
	}
}

func (t *PubSub) Subscribe(id string) chan Command {
	ch := make(chan Command, 32)
	t.mu.Lock()
	t.subs[id] = append(t.subs[id], ch)
	t.mu.Unlock()
	return ch
}

func (t *PubSub) Unsubscribe(id string, ch chan Command) {
	t.mu.Lock()
	chIndex := slices.Index(t.subs[id], ch)
	if chIndex < 0 {
		return
	}
	t.subs[id] = slices.Delete(t.subs[id], chIndex, chIndex+1)
	close(ch)
	t.mu.Unlock()
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
