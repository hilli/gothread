// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dnsdso

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// TLV encode / decode
// ---------------------------------------------------------------------------

func TestEncodeTLV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tlvType uint16
		value   []byte
		wantLen int
	}{
		{"empty value", TypeKeepAlive, nil, 4},
		{"with value", TypeRetryDelay, []byte{0x00, 0x00, 0x27, 0x10}, 8},
		{"padding", TypeEncryptionPadding, make([]byte, 16), 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := EncodeTLV(tt.tlvType, tt.value)
			if len(got) != tt.wantLen {
				t.Errorf("EncodeTLV length = %d, want %d", len(got), tt.wantLen)
			}
			if binary.BigEndian.Uint16(got[0:2]) != tt.tlvType {
				t.Errorf("type = %d, want %d", binary.BigEndian.Uint16(got[0:2]), tt.tlvType)
			}
			valLen := binary.BigEndian.Uint16(got[2:4])
			if int(valLen) != len(tt.value) {
				t.Errorf("length field = %d, want %d", valLen, len(tt.value))
			}
		})
	}
}

func TestDecodeTLV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		wantType uint16
		wantLen  uint16
		wantN    int
		wantErr  bool
	}{
		{
			"valid keepalive",
			EncodeTLV(TypeKeepAlive, []byte{0, 0, 0, 1, 0, 0, 0, 2}),
			TypeKeepAlive, 8, 12, false,
		},
		{
			"empty value",
			EncodeTLV(TypeEncryptionPadding, nil),
			TypeEncryptionPadding, 0, 4, false,
		},
		{"too short", []byte{0x00, 0x01}, 0, 0, 0, true},
		{"truncated value", []byte{0x00, 0x01, 0x00, 0x08, 0x01}, 0, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tlv, n, err := DecodeTLV(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeTLV err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tlv.Type != tt.wantType {
				t.Errorf("Type = %d, want %d", tlv.Type, tt.wantType)
			}
			if tlv.Length != tt.wantLen {
				t.Errorf("Length = %d, want %d", tlv.Length, tt.wantLen)
			}
			if n != tt.wantN {
				t.Errorf("consumed = %d, want %d", n, tt.wantN)
			}
		})
	}
}

func TestTLVRoundTrip(t *testing.T) {
	t.Parallel()

	value := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encoded := EncodeTLV(TypeSubscribe, value)
	tlv, n, err := DecodeTLV(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if n != len(encoded) {
		t.Errorf("consumed %d, want %d", n, len(encoded))
	}
	if tlv.Type != TypeSubscribe {
		t.Errorf("type = %d, want %d", tlv.Type, TypeSubscribe)
	}
	if len(tlv.Value) != len(value) {
		t.Fatalf("value len = %d, want %d", len(tlv.Value), len(value))
	}
	for i, b := range value {
		if tlv.Value[i] != b {
			t.Errorf("value[%d] = %02x, want %02x", i, tlv.Value[i], b)
		}
	}
}

// ---------------------------------------------------------------------------
// Message encode / decode
// ---------------------------------------------------------------------------

func TestMessageEncodeDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  Message
	}{
		{
			"request with primary TLV",
			Message{
				ID: 1, QR: false, RCode: 0,
				PrimaryTLV: &TLV{Type: TypeKeepAlive, Length: 8,
					Value: []byte{0, 0, 0x3A, 0x98, 0, 0, 0x27, 0x10}},
			},
		},
		{
			"response no TLV",
			Message{ID: 42, QR: true, RCode: 0},
		},
		{
			"response with error",
			Message{ID: 7, QR: true, RCode: 5},
		},
		{
			"request with additional TLVs",
			Message{
				ID: 3, QR: false, RCode: 0,
				PrimaryTLV: &TLV{Type: TypeSubscribe, Length: 2, Value: []byte{0x01, 0x02}},
				AdditionalTLVs: []TLV{
					{Type: TypeEncryptionPadding, Length: 4, Value: []byte{0, 0, 0, 0}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded := tt.msg.Encode()
			var decoded Message
			if err := decoded.Decode(encoded); err != nil {
				t.Fatalf("Decode error: %v", err)
			}

			if decoded.ID != tt.msg.ID {
				t.Errorf("ID = %d, want %d", decoded.ID, tt.msg.ID)
			}
			if decoded.QR != tt.msg.QR {
				t.Errorf("QR = %v, want %v", decoded.QR, tt.msg.QR)
			}
			if decoded.RCode != tt.msg.RCode {
				t.Errorf("RCode = %d, want %d", decoded.RCode, tt.msg.RCode)
			}
			if (tt.msg.PrimaryTLV == nil) != (decoded.PrimaryTLV == nil) {
				t.Fatalf("PrimaryTLV nil mismatch")
			}
			if tt.msg.PrimaryTLV != nil {
				if decoded.PrimaryTLV.Type != tt.msg.PrimaryTLV.Type {
					t.Errorf("PrimaryTLV.Type = %d, want %d",
						decoded.PrimaryTLV.Type, tt.msg.PrimaryTLV.Type)
				}
			}
			if len(decoded.AdditionalTLVs) != len(tt.msg.AdditionalTLVs) {
				t.Errorf("AdditionalTLVs count = %d, want %d",
					len(decoded.AdditionalTLVs), len(tt.msg.AdditionalTLVs))
			}
		})
	}
}

func TestMessageDecodeTooShort(t *testing.T) {
	t.Parallel()

	var m Message
	if err := m.Decode([]byte{0, 1, 2}); err == nil {
		t.Error("expected error for short message")
	}
}

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

func TestConnectionInitialState(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	if c.GetState() != StateDisconnected {
		t.Errorf("initial state = %d, want StateDisconnected", c.GetState())
	}
}

func TestConnectionConnectDisconnect(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)

	if err := c.Connect([16]byte{15: 1}, 853); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if c.GetState() != StateConnectedButSessionless {
		t.Errorf("state after connect = %d, want StateConnectedButSessionless", c.GetState())
	}

	// Double connect should fail.
	if err := c.Connect([16]byte{15: 2}, 853); err == nil {
		t.Error("expected error on double connect")
	}

	c.Disconnect()
	if c.GetState() != StateDisconnected {
		t.Errorf("state after disconnect = %d, want StateDisconnected", c.GetState())
	}
}

func TestConnectionKeepAlive(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	if err := c.SendKeepAlive(15000, 10000); err != nil {
		t.Fatalf("SendKeepAlive: %v", err)
	}
	if c.GetState() != StateEstablishingSession {
		t.Errorf("state = %d, want StateEstablishingSession", c.GetState())
	}
	if c.GetInactivityTimeout() != 15000 {
		t.Errorf("inactivity timeout = %d, want 15000", c.GetInactivityTimeout())
	}
	if c.GetKeepAliveInterval() != 10000 {
		t.Errorf("keepalive interval = %d, want 10000", c.GetKeepAliveInterval())
	}
}

func TestConnectionKeepAliveDisconnectedError(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	if err := c.SendKeepAlive(15000, 10000); err == nil {
		t.Error("expected error when disconnected")
	}
}

func TestConnectionSendRequestMessage(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	id, err := c.SendRequestMessage(TypeSubscribe, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("SendRequestMessage: %v", err)
	}
	if id == 0 {
		t.Error("message ID should not be zero")
	}
	if c.GetState() != StateEstablishingSession {
		t.Errorf("state = %d, want StateEstablishingSession", c.GetState())
	}
}

func TestConnectionSendRequestDisconnectedError(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_, err := c.SendRequestMessage(TypeSubscribe, nil)
	if err == nil {
		t.Error("expected error when disconnected")
	}
}

func TestConnectionSendUnidirectionalRequiresSession(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	if err := c.SendUnidirectionalMessage(TypePush, nil); err == nil {
		t.Error("expected error when session not established")
	}
}

func TestConnectionResponseFlow(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	// Send a request and capture the ID.
	id, err := c.SendRequestMessage(TypeKeepAlive, []byte{0, 0, 0, 1, 0, 0, 0, 2})
	if err != nil {
		t.Fatalf("SendRequestMessage: %v", err)
	}

	var gotID uint16
	var gotRCode uint8
	var gotData []byte
	c.SetResponseCallback(func(messageID uint16, rCode uint8, data []byte) {
		gotID = messageID
		gotRCode = rCode
		gotData = data
	})

	// Build a response message.
	resp := Message{
		ID: id, QR: true, RCode: 0,
		PrimaryTLV: &TLV{Type: TypeKeepAlive, Length: 8,
			Value: []byte{0, 0, 0x3A, 0x98, 0, 0, 0x27, 0x10}},
	}
	c.HandleReceived(resp.Encode())

	if gotID != id {
		t.Errorf("response ID = %d, want %d", gotID, id)
	}
	if gotRCode != 0 {
		t.Errorf("response RCode = %d, want 0", gotRCode)
	}
	if len(gotData) == 0 {
		t.Error("expected non-empty response data")
	}
	if c.GetState() != StateSessionEstablished {
		t.Errorf("state = %d, want StateSessionEstablished", c.GetState())
	}
}

func TestConnectionRequestCallback(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	// Force session established for request handling.
	c.mu.Lock()
	c.state = StateSessionEstablished
	c.mu.Unlock()

	var gotType uint16
	c.SetRequestCallback(func(primaryTlvType uint16, data []byte) ([]byte, uint8) {
		gotType = primaryTlvType
		return []byte{0x01}, 0
	})

	// Build a request message with ID != 0.
	req := Message{
		ID: 99, QR: false, RCode: 0,
		PrimaryTLV: &TLV{Type: TypeSubscribe, Length: 2, Value: []byte{0x0A, 0x0B}},
	}
	c.HandleReceived(req.Encode())

	if gotType != TypeSubscribe {
		t.Errorf("request callback type = %d, want %d", gotType, TypeSubscribe)
	}
}

func TestConnectionRetryDelay(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	id, _ := c.SendRequestMessage(TypeKeepAlive, nil)

	// Build response with RetryDelay TLV.
	delayValue := make([]byte, 4)
	binary.BigEndian.PutUint32(delayValue, 5000)
	resp := Message{
		ID: id, QR: true, RCode: 0,
		PrimaryTLV: &TLV{Type: TypeRetryDelay, Length: 4, Value: delayValue},
	}
	c.HandleReceived(resp.Encode())

	if c.GetRetryDelay() != 5000 {
		t.Errorf("retry delay = %d, want 5000", c.GetRetryDelay())
	}
}

func TestConnectionUnidirectionalAfterSession(t *testing.T) {
	t.Parallel()
	c := NewConnection([16]byte{}, 853)
	_ = c.Connect([16]byte{15: 1}, 853)

	// Force session established.
	c.mu.Lock()
	c.state = StateSessionEstablished
	c.mu.Unlock()

	if err := c.SendUnidirectionalMessage(TypePush, []byte{0x01}); err != nil {
		t.Fatalf("SendUnidirectionalMessage: %v", err)
	}
}

func TestMessageTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value MessageType
		want  uint16
	}{
		{"TypeReserved", TypeReserved, 0x0000},
		{"TypeKeepAlive", TypeKeepAlive, 0x0001},
		{"TypeRetryDelay", TypeRetryDelay, 0x0002},
		{"TypeEncryptionPadding", TypeEncryptionPadding, 0x0003},
		{"TypeSubscribe", TypeSubscribe, 0x0040},
		{"TypePush", TypePush, 0x0041},
		{"TypeReconfirm", TypeReconfirm, 0x0042},
		{"TypeUnsubscribe", TypeUnsubscribe, 0x0043},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.value != tt.want {
				t.Errorf("%s = 0x%04x, want 0x%04x", tt.name, tt.value, tt.want)
			}
		})
	}
}
