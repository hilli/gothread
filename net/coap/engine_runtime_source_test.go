package coap

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

type runtimeFaultReader struct {
	remaining int
	cause     error
}

func (reader *runtimeFaultReader) Read(value []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, reader.cause
	}
	n := min(len(value), reader.remaining)
	clear(value[:n])
	reader.remaining -= n
	if n < len(value) {
		return n, reader.cause
	}
	return n, nil
}

func TestOwnerCoapInitializationAndJitterFailBeforeTransaction(t *testing.T) {
	fault := errors.New("qualified entropy fault")
	now := func() time.Time { return time.Unix(1, 0) }
	scheduled := 0
	schedule := func(time.Duration, func()) func() { scheduled++; return func() {} }
	sends := 0
	sender := func([]byte, MessageInfo) error { sends++; return nil }
	if engine, err := NewEngineWithScheduler(sender, &runtimeFaultReader{cause: fault}, now, schedule); engine != nil || !errors.Is(err, fault) {
		t.Fatal("MID initialization ignored original entropy error")
	}
	engine, err := NewEngineWithScheduler(sender, &runtimeFaultReader{remaining: 2, cause: fault}, now, schedule)
	if err != nil {
		t.Fatal(err)
	}
	request := NewMessage(TypeConfirmable, CodePost, 123)
	if err := request.SetToken([]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), request.GetBytes()...)
	if err := engine.SendMessage(request, MessageInfo{}, nil, func(*Message, MessageInfo, error) {}); !errors.Is(err, fault) {
		t.Fatal("jitter failure did not propagate")
	}
	if sends != 0 || scheduled != 0 || len(engine.pending) != 0 || !bytes.Equal(before, request.GetBytes()) {
		t.Fatal("entropy failure consumed MID/state/timer/transmission")
	}
}

func TestOwnerCoapRetransmissionRunsOnlyOnProvidedScheduler(t *testing.T) {
	now := time.Unix(1, 0)
	var fire func()
	var delay time.Duration
	canceled := 0
	schedule := func(next time.Duration, callback func()) func() {
		delay, fire = next, callback
		return func() { canceled++; fire = nil }
	}
	// All zero entropy is a deterministic test reader, never a native provider.
	reader := io.LimitReader(bytes.NewReader(make([]byte, 128)), 128)
	sends := 0
	engine, err := NewEngineWithScheduler(func([]byte, MessageInfo) error { sends++; return nil }, reader, func() time.Time { return now }, schedule)
	if err != nil {
		t.Fatal(err)
	}
	request := NewMessage(TypeConfirmable, CodePost, 0)
	if err := engine.SendMessage(request, MessageInfo{}, nil, func(*Message, MessageInfo, error) {}); err != nil {
		t.Fatal(err)
	}
	if sends != 1 || fire == nil || engine.retxTimer != nil {
		t.Fatal("owner engine used a host/background timer")
	}
	now = now.Add(delay)
	callback := fire
	callback()
	if sends != 2 || fire == nil {
		t.Fatal("owner callback did not drive actual retransmission")
	}
	engine.ClearAllRequestsAndResponses()
	if fire != nil || canceled == 0 || len(engine.pending) != 0 {
		t.Fatal("clear retained owner callbacks/transaction")
	}
}
