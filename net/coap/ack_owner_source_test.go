package coap

import (
	"bytes"
	"errors"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

func TestOwnerAckOnlyAndSeparateResponseShareOneEngine(t *testing.T) {
	now := time.Unix(1, 0)
	sender := func([]byte, MessageInfo) error { return nil }
	engine, err := NewEngineWithScheduler(sender, bytes.NewReader(make([]byte, 256)), func() time.Time { return now },
		func(time.Duration, func()) func() { return func() {} })
	if err != nil {
		t.Fatal(err)
	}
	peer := MessageInfo{PeerPort: 61631, PeerAddr: [16]byte{0xfd, 15: 1}, LocalAddr: [16]byte{0xfd, 15: 2}}
	mlrDone, ownDone := false, false
	mlr := NewMessage(TypeConfirmable, CodePost, 0)
	if err := mlr.SetToken([]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	if err := engine.SendMessage(mlr, peer, nil, func(*Message, MessageInfo, error) { mlrDone = true }); err != nil {
		t.Fatal(err)
	}
	own := NewMessage(TypeConfirmable, CodePost, 0)
	if err := own.SetToken([]byte{8, 7, 6, 5, 4, 3, 2, 1}); err != nil {
		t.Fatal(err)
	}
	if err := engine.SendMessageAwaitAck(own, peer, nil, func(message *Message, _ MessageInfo, err error) {
		if err != nil || message == nil || message.GetCode() != CodeEmpty {
			t.Error("not an actual transport ACK")
		}
		ownDone = true
	}); err != nil {
		t.Fatal(err)
	}
	engine.Receive(NewMessage(TypeAck, CodeEmpty, mlr.GetMessageID()).GetBytes(), peer)
	if mlrDone || len(engine.pending) != 2 {
		t.Fatal("empty MLR ACK became semantic registration success")
	}
	firstDeadline := engine.pending[0].timerFire
	now = now.Add(time.Second)
	engine.Receive(NewMessage(TypeAck, CodeEmpty, mlr.GetMessageID()).GetBytes(), peer)
	if !engine.pending[0].timerFire.Equal(firstDeadline) {
		t.Fatal("duplicate ACK extended response ownership")
	}
	foreign := peer
	foreign.PeerAddr[15]++
	engine.Receive(NewMessage(TypeAck, CodeEmpty, own.GetMessageID()).GetBytes(), foreign)
	engine.Receive(NewMessage(TypeAck, CodeChanged, own.GetMessageID()).GetBytes(), peer)
	response := NewMessage(TypeNonConfirmable, CodeChanged, own.GetMessageID())
	if err := response.SetToken(own.GetToken()); err != nil {
		t.Fatal(err)
	}
	engine.Receive(response.GetBytes(), peer)
	if ownDone || len(engine.pending) != 2 {
		t.Fatal("foreign or semantic response completed an ACK-only exchange")
	}
	engine.Receive(NewMessage(TypeAck, CodeEmpty, own.GetMessageID()).GetBytes(), peer)
	if !ownDone || mlrDone || len(engine.pending) != 1 {
		t.Fatal("own notification ACK erased/shared the wrong transaction")
	}

	if err := engine.AbortRequest(mlr.GetToken(), peer); err != nil {
		t.Fatal(err)
	}
	if !mlrDone || len(engine.pending) != 0 {
		t.Fatal("exact abort did not retire remaining owner")
	}
	if err := engine.AbortRequest(own.GetToken(), peer); !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatal("completed token found another transaction")
	}
}

func TestOwnerMessageIDsWrapWithoutReusingAnActiveMID(t *testing.T) {
	engine := NewEngine(func([]byte, MessageInfo) error { return nil })
	engine.messageID = 0xffff
	engine.pending = []*pendingRequest{{messageID: 0xffff}, {messageID: 0}}
	mid, err := engine.allocateMessageIDLocked()
	if err != nil || mid != 1 {
		t.Fatal("active MID reused at wrap")
	}
	engine.pending = nil
	engine.messageID = 0xffff
	mid, err = engine.allocateMessageIDLocked()
	if err != nil || mid != 0xffff {
		t.Fatal("MID space became permanently exhausted")
	}
}
