package id1

import (
	"fmt"
	"sync"
	"testing"
)

// TestPubSubBasicRouting verifies a single message is routed from publisher to subscriber.
func TestPubSubBasicRouting(t *testing.T) {
	pubsub := NewPubSub()
	ch := pubsub.Subscribe("test-sub")
	defer pubsub.Unsubscribe("test-sub", ch)

	key := KK("test-sub", 0)
	cmd := CmdSet(key, map[string]string{}, []byte{})

	var received Command
	done := make(chan struct{})

	go func() {
		received = <-ch
		close(done)
	}()

	pubsub.Publish(&cmd)

	<-done

	if received.Op != Set {
		t.Errorf("expected Op to be Set, got %v", received.Op)
	}
	if received.Key.Id != "test-sub" {
		t.Errorf("expected key ID to be 'test-sub', got %q", received.Key.Id)
	}
}

// TestPubSubMultipleSubscribers verifies all subscribers receive the published message.
func TestPubSubMultipleSubscribers(t *testing.T) {
	pubsub := NewPubSub()
	subCount := 5
	channels := make([]chan Command, subCount)
	var wg sync.WaitGroup

	// Create subscribers
	for i := range subCount {
		subID := fmt.Sprintf("subscriber%d", i)
		ch := pubsub.Subscribe(subID)
		channels[i] = ch
		defer pubsub.Unsubscribe(subID, ch)
	}

	// Track received messages
	received := make(map[int]bool)
	var mu sync.Mutex

	// Start goroutines to receive messages
	for i := range subCount {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cmd := <-channels[idx]
			mu.Lock()
			received[idx] = true
			mu.Unlock()

			if cmd.Op != Set {
				t.Errorf("subscriber %d: expected Op to be Set, got %v", idx, cmd.Op)
			}
			if cmd.Key.Id != fmt.Sprintf("subscriber%d", idx) {
				t.Errorf("subscriber %d: expected key ID to be 'subscriber%d', got %q", idx, idx, cmd.Key.Id)
			}
		}(i)
	}

	// Publish single message to each subscriber
	for i := range subCount {
		subID := fmt.Sprintf("subscriber%d", i)
		key := KK(subID, 0)
		cmd := CmdSet(key, map[string]string{}, []byte{})
		pubsub.Publish(&cmd)
	}

	// Wait for all subscribers to receive
	wg.Wait()

	// Verify all received
	if len(received) != subCount {
		t.Errorf("expected all %d subscribers to receive message, got %d", subCount, len(received))
	}
	for i := range subCount {
		if !received[i] {
			t.Errorf("subscriber %d did not receive message", i)
		}
	}
}

// TestPubSubMultiplePublishers verifies multiple publishers can send to multiple subscribers.
func TestPubSubMultiplePublishers(t *testing.T) {
	pubsub := NewPubSub()
	pubCount := 3
	subCount := 3
	var wg sync.WaitGroup

	// Track messages received per subscriber
	receivedCounts := make(map[int]int)
	var mu sync.Mutex

	// Create subscribers
	channels := make([]chan Command, subCount)
	for i := range subCount {
		subID := fmt.Sprintf("subscriber%d", i)
		ch := pubsub.Subscribe(subID)
		channels[i] = ch
		defer pubsub.Unsubscribe(subID, ch)

		// Each subscriber will receive pubCount messages
		for j := range pubCount {
			wg.Add(1)
			go func(subIdx, pubIdx int) {
				defer wg.Done()
				cmd := <-channels[subIdx]

				mu.Lock()
				receivedCounts[subIdx]++
				mu.Unlock()

				if cmd.Op != Set {
					t.Errorf("subscriber %d from publisher %d: expected Op to be Set, got %v", subIdx, pubIdx, cmd.Op)
				}
			}(i, j)
		}
	}

	// Multiple publishers publish to all subscribers
	for pub := range pubCount {
		for sub := range subCount {
			subID := fmt.Sprintf("subscriber%d", sub)
			key := KK(subID, pub)
			cmd := CmdSet(key, map[string]string{}, []byte{})
			pubsub.Publish(&cmd)
		}
	}

	// Wait for all goroutines
	wg.Wait()

	// Verify counts
	expectedCount := pubCount
	for i := range subCount {
		if receivedCounts[i] != expectedCount {
			t.Errorf("subscriber %d: expected to receive %d messages, got %d", i, expectedCount, receivedCounts[i])
		}
	}
}
