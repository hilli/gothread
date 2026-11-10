package coap

import (
	"errors"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

func TestCoapSeparateAckDeadlineDoesNotExtend(t *testing.T) {
	now := time.Now()
	engine := NewEngine(func([]byte, MessageInfo) error { return nil })
	engine.nowFunc = func() time.Time { return now }
	defer engine.ClearAllRequestsAndResponses()
	peer := MessageInfo{PeerPort: 61631, PeerAddr: [16]byte{0xfd, 15: 1}}
	request := NewMessage(TypeConfirmable, CodePost, 0)
	done := false
	if err := engine.SendMessage(request, peer, nil, func(_ *Message, _ MessageInfo, err error) {
		done = true
		if !errors.Is(err, goterrors.ErrResponseTimeout) {
			t.Errorf("separate response deadline cause: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	engine.Receive(NewMessage(TypeAck, CodeEmpty, request.GetMessageID()).GetBytes(), peer)
	now = now.Add(DefaultTxParameters().CalculateExchangeLifetime() + time.Second)
	engine.handleRetransmissionTimer()
	if !done || len(engine.pending) != 0 {
		t.Fatal("empty separate ACK retained request forever")
	}
}
