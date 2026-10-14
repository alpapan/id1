// apps/id1/pub_sub_close_test.go
//
// group: utils
// tags: pubsub, channels, testing
// summary: Tests that the pub/sub hub never closes a subscriber's channel.
//
//

package id1

import (
	"sync"
	"testing"
	"time"
)

// channelIsOpenAndEmpty reports whether ch is still open with nothing waiting.
// A closed channel makes the receive succeed at once with ok == false, and a
// channel holding a message makes it succeed with ok == true; only an open,
// empty channel falls through to default.
func channelIsOpenAndEmpty(ch chan Command) bool {
	select {
	case _, ok := <-ch:
		_ = ok
		return false
	default:
		return true
	}
}

func TestPubSubCloseLeavesSubscriberChannelsOpen(t *testing.T) {
	hub := NewPubSub()
	ch := hub.Subscribe("alice")

	hub.Close()

	select {
	case _, open := <-ch:
		if !open {
			t.Fatalf("Close closed a subscriber channel; only the sending side may close")
		}
		t.Fatalf("Close delivered an unexpected message")
	default:
	}
}

func TestPubSubPublishAfterCloseDoesNotPanicAndDeliversNothing(t *testing.T) {
	hub := NewPubSub()
	ch := hub.Subscribe("alice")
	hub.Close()

	cmd := CmdSet(mustK(t, "alice/note"), map[string]string{}, []byte("x"))
	hub.Publish(&cmd)

	if !channelIsOpenAndEmpty(ch) {
		t.Errorf("a hub that has been closed must forget its subscribers: the channel was closed or received a message")
	}
}

func TestPubSubSubscribeAfterCloseStillWorks(t *testing.T) {
	hub := NewPubSub()
	hub.Close()

	ch := hub.Subscribe("alice")
	cmd := CmdSet(mustK(t, "alice/note"), map[string]string{}, []byte("x"))
	hub.Publish(&cmd)

	select {
	case got := <-ch:
		if got.Key.String() != "alice/note" {
			t.Errorf("got key %q, want %q", got.Key.String(), "alice/note")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("a subscriber added after Close received nothing")
	}
}

func TestPubSubUnsubscribeLeavesTheChannelOpen(t *testing.T) {
	hub := NewPubSub()
	ch := hub.Subscribe("alice")

	hub.Unsubscribe("alice", ch)

	if !channelIsOpenAndEmpty(ch) {
		t.Errorf("Unsubscribe must not close the channel it removes")
	}
}

// TestPubSubCloseRacingPublishDoesNotPanic runs Close against Publish and
// Subscribe in parallel. Before Close stopped closing channels, a Publish that
// had copied a channel out of the list could send on it after Close closed it,
// which panics. Run it under the race task as well as the plain one.
func TestPubSubCloseRacingPublishDoesNotPanic(t *testing.T) {
	hub := NewPubSub()
	cmd := CmdSet(mustK(t, "alice/note"), map[string]string{}, []byte("x"))

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					hub.Publish(&cmd)
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				hub.Subscribe("alice")
				hub.Close()
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
