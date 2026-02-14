// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coap_test

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/net/coap"
)

// ---------------------------------------------------------------------------
// Test 1: Build and parse a simple GET request
// ---------------------------------------------------------------------------

func TestBuildAndParseGetRequest(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x1234)
	if err := msg.SetToken([]byte{0xAA, 0xBB}); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	if err := msg.AppendURIPathOptions("/test/path"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}
	if err := msg.AppendPayloadMarker(); err != nil {
		t.Fatalf("AppendPayloadMarker: %v", err)
	}
	if err := msg.AppendPayload([]byte("hello")); err != nil {
		t.Fatalf("AppendPayload: %v", err)
	}

	raw := msg.GetBytes()

	// Verify header bytes.
	// Byte 0: ver=1(01) type=CON(00) tkl=2(0010) -> 0b01000010 = 0x42
	if raw[0] != 0x42 {
		t.Errorf("header byte 0 = 0x%02X, want 0x42", raw[0])
	}
	// Byte 1: Code GET = 0x01
	if raw[1] != 0x01 {
		t.Errorf("header byte 1 = 0x%02X, want 0x01", raw[1])
	}
	// Byte 2-3: MessageID = 0x1234
	if raw[2] != 0x12 || raw[3] != 0x34 {
		t.Errorf("message ID bytes = [0x%02X, 0x%02X], want [0x12, 0x34]", raw[2], raw[3])
	}
	// Token
	if !bytes.Equal(raw[4:6], []byte{0xAA, 0xBB}) {
		t.Errorf("token = %X, want AABB", raw[4:6])
	}

	// Uri-Path "test": delta=11, len=4 -> first byte = (11<<4)|4 = 0xB4
	if raw[6] != 0xB4 {
		t.Errorf("first option header = 0x%02X, want 0xB4", raw[6])
	}
	if string(raw[7:11]) != "test" {
		t.Errorf("first option value = %q, want %q", string(raw[7:11]), "test")
	}

	// Uri-Path "path": delta=0 (same option number), len=4 -> 0x04
	if raw[11] != 0x04 {
		t.Errorf("second option header = 0x%02X, want 0x04", raw[11])
	}
	if string(raw[12:16]) != "path" {
		t.Errorf("second option value = %q, want %q", string(raw[12:16]), "path")
	}

	// Payload marker
	if raw[16] != 0xFF {
		t.Errorf("payload marker = 0x%02X, want 0xFF", raw[16])
	}
	// Payload
	if string(raw[17:]) != "hello" {
		t.Errorf("payload = %q, want %q", string(raw[17:]), "hello")
	}

	// Parse back.
	parsed, err := coap.ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if parsed.GetType() != coap.TypeConfirmable {
		t.Errorf("GetType = %d, want %d", parsed.GetType(), coap.TypeConfirmable)
	}
	if parsed.GetCode() != coap.CodeGet {
		t.Errorf("GetCode = 0x%02X, want 0x%02X", parsed.GetCode(), coap.CodeGet)
	}
	if parsed.GetMessageID() != 0x1234 {
		t.Errorf("GetMessageID = 0x%04X, want 0x1234", parsed.GetMessageID())
	}
	if parsed.GetTokenLength() != 2 {
		t.Errorf("GetTokenLength = %d, want 2", parsed.GetTokenLength())
	}
	if !bytes.Equal(parsed.GetToken(), []byte{0xAA, 0xBB}) {
		t.Errorf("GetToken = %X, want AABB", parsed.GetToken())
	}
	if !bytes.Equal(parsed.GetPayload(), []byte("hello")) {
		t.Errorf("GetPayload = %q, want %q", parsed.GetPayload(), "hello")
	}
}

// ---------------------------------------------------------------------------
// Test 2: Code classification
// ---------------------------------------------------------------------------

func TestCodeClassification(t *testing.T) {
	tests := []struct {
		name          string
		code          coap.Code
		class         uint8
		detail        uint8
		str           string
		isRequest     bool
		isResponse    bool
		isEmpty       bool
		isSuccess     bool
		isClientError bool
		isServerError bool
	}{
		{
			name: "Empty", code: coap.CodeEmpty,
			class: 0, detail: 0, str: "0.00",
			isEmpty: true,
		},
		{
			name: "GET", code: coap.CodeGet,
			class: 0, detail: 1, str: "0.01",
			isRequest: true,
		},
		{
			name: "POST", code: coap.CodePost,
			class: 0, detail: 2, str: "0.02",
			isRequest: true,
		},
		{
			name: "DELETE", code: coap.CodeDelete,
			class: 0, detail: 4, str: "0.04",
			isRequest: true,
		},
		{
			name: "Created", code: coap.CodeCreated,
			class: 2, detail: 1, str: "2.01",
			isResponse: true, isSuccess: true,
		},
		{
			name: "Content", code: coap.CodeContent,
			class: 2, detail: 5, str: "2.05",
			isResponse: true, isSuccess: true,
		},
		{
			name: "BadRequest", code: coap.CodeBadRequest,
			class: 4, detail: 0, str: "4.00",
			isResponse: true, isClientError: true,
		},
		{
			name: "NotFound", code: coap.CodeNotFound,
			class: 4, detail: 4, str: "4.04",
			isResponse: true, isClientError: true,
		},
		{
			name: "InternalError", code: coap.CodeInternalError,
			class: 5, detail: 0, str: "5.00",
			isResponse: true, isServerError: true,
		},
		{
			name: "NotImplemented", code: coap.CodeNotImplemented,
			class: 5, detail: 1, str: "5.01",
			isResponse: true, isServerError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.code.GetClass(); got != tt.class {
				t.Errorf("GetClass() = %d, want %d", got, tt.class)
			}
			if got := tt.code.GetDetail(); got != tt.detail {
				t.Errorf("GetDetail() = %d, want %d", got, tt.detail)
			}
			if got := tt.code.ToString(); got != tt.str {
				t.Errorf("ToString() = %q, want %q", got, tt.str)
			}
			if got := tt.code.IsRequest(); got != tt.isRequest {
				t.Errorf("IsRequest() = %v, want %v", got, tt.isRequest)
			}
			if got := tt.code.IsResponse(); got != tt.isResponse {
				t.Errorf("IsResponse() = %v, want %v", got, tt.isResponse)
			}
			if got := tt.code.IsEmpty(); got != tt.isEmpty {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.isEmpty)
			}
			if got := tt.code.IsSuccess(); got != tt.isSuccess {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.isSuccess)
			}
			if got := tt.code.IsClientError(); got != tt.isClientError {
				t.Errorf("IsClientError() = %v, want %v", got, tt.isClientError)
			}
			if got := tt.code.IsServerError(); got != tt.isServerError {
				t.Errorf("IsServerError() = %v, want %v", got, tt.isServerError)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 3: Option delta encoding
// ---------------------------------------------------------------------------

func TestOptionDeltaEncoding(t *testing.T) {
	t.Run("SmallDeltas", func(t *testing.T) {
		// Options at numbers 1, 3, 11, 60 -> deltas: 1, 2, 8, 49
		msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)

		if err := msg.AppendOption(coap.OptionIfMatch, []byte{0x01}); err != nil {
			t.Fatalf("AppendOption(1): %v", err)
		}
		if err := msg.AppendOption(coap.OptionURIHost, []byte{0x02}); err != nil {
			t.Fatalf("AppendOption(3): %v", err)
		}
		if err := msg.AppendOption(coap.OptionURIPath, []byte{0x03}); err != nil {
			t.Fatalf("AppendOption(11): %v", err)
		}
		if err := msg.AppendOption(coap.OptionSize1, []byte{0x04}); err != nil {
			t.Fatalf("AppendOption(60): %v", err)
		}

		raw := msg.GetBytes()
		opts := raw[coap.HeaderSize:] // no token

		// Option 1 (delta=1, len=1): header = (1<<4)|1 = 0x11, value = 0x01
		if opts[0] != 0x11 {
			t.Errorf("opt[0] header = 0x%02X, want 0x11", opts[0])
		}
		if opts[1] != 0x01 {
			t.Errorf("opt[0] value = 0x%02X, want 0x01", opts[1])
		}

		// Option 3 (delta=2, len=1): header = (2<<4)|1 = 0x21, value = 0x02
		if opts[2] != 0x21 {
			t.Errorf("opt[1] header = 0x%02X, want 0x21", opts[2])
		}
		if opts[3] != 0x02 {
			t.Errorf("opt[1] value = 0x%02X, want 0x02", opts[3])
		}

		// Option 11 (delta=8, len=1): header = (8<<4)|1 = 0x81, value = 0x03
		if opts[4] != 0x81 {
			t.Errorf("opt[2] header = 0x%02X, want 0x81", opts[4])
		}
		if opts[5] != 0x03 {
			t.Errorf("opt[2] value = 0x%02X, want 0x03", opts[5])
		}

		// Option 60 (delta=49, len=1): delta=49 >= 13, so nibble=13, ext=49-13=36
		// header = (13<<4)|1 = 0xD1, ext = 36 = 0x24, value = 0x04
		if opts[6] != 0xD1 {
			t.Errorf("opt[3] header = 0x%02X, want 0xD1", opts[6])
		}
		if opts[7] != 0x24 {
			t.Errorf("opt[3] delta ext = 0x%02X, want 0x24 (36)", opts[7])
		}
		if opts[8] != 0x04 {
			t.Errorf("opt[3] value = 0x%02X, want 0x04", opts[8])
		}
	})

	t.Run("ExtendedDelta13", func(t *testing.T) {
		// Single option with number 20: delta=20 >= 13, nibble=13, ext=7
		msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
		if err := msg.AppendOption(coap.OptionLocationQuery, []byte("x")); err != nil {
			t.Fatalf("AppendOption(20): %v", err)
		}
		raw := msg.GetBytes()
		opts := raw[coap.HeaderSize:]

		// delta=20: nibble=13, ext=20-13=7, len=1: nibble=1
		// header = (13<<4)|1 = 0xD1, ext = 7
		if opts[0] != 0xD1 {
			t.Errorf("header = 0x%02X, want 0xD1", opts[0])
		}
		if opts[1] != 0x07 {
			t.Errorf("delta ext = 0x%02X, want 0x07", opts[1])
		}
		if opts[2] != 'x' {
			t.Errorf("value = 0x%02X, want 'x'", opts[2])
		}
	})

	t.Run("ExtendedDelta14TwoBytes", func(t *testing.T) {
		// Option number 300: delta=300 >= 269, nibble=14, ext=300-269=31
		msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
		if err := msg.AppendOption(coap.OptionNumber(300), []byte("y")); err != nil {
			t.Fatalf("AppendOption(300): %v", err)
		}
		raw := msg.GetBytes()
		opts := raw[coap.HeaderSize:]

		// delta=300: nibble=14, ext=31 as big-endian uint16 [0x00, 0x1F], len=1: nibble=1
		// header = (14<<4)|1 = 0xE1
		if opts[0] != 0xE1 {
			t.Errorf("header = 0x%02X, want 0xE1", opts[0])
		}
		if opts[1] != 0x00 || opts[2] != 0x1F {
			t.Errorf("delta ext = [0x%02X, 0x%02X], want [0x00, 0x1F]", opts[1], opts[2])
		}
		if opts[3] != 'y' {
			t.Errorf("value = 0x%02X, want 'y'", opts[3])
		}
	})
}

// ---------------------------------------------------------------------------
// Test 4: Uint option encoding
// ---------------------------------------------------------------------------

func TestUintOptionEncoding(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		want  []byte // expected option value (not including header)
	}{
		{"Zero", 0, nil},
		{"One", 1, []byte{0x01}},
		{"255", 255, []byte{0xFF}},
		{"256", 256, []byte{0x01, 0x00}},
		{"65535", 65535, []byte{0xFF, 0xFF}},
		{"65536", 65536, []byte{0x01, 0x00, 0x00}},
		{"16777215", 16777215, []byte{0xFF, 0xFF, 0xFF}},
		{"16777216", 16777216, []byte{0x01, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
			if err := msg.AppendUintOption(coap.OptionObserve, tt.value); err != nil {
				t.Fatalf("AppendUintOption: %v", err)
			}

			raw := msg.GetBytes()
			opts := raw[coap.HeaderSize:]

			// Skip the option header byte (delta=6, len=len(want))
			// Observe is option 6, delta=6, length = len(tt.want)
			wantLen := len(tt.want)
			// header byte: (6<<4) | wantLen
			expectedHeader := byte(6<<4) | byte(wantLen)
			if opts[0] != expectedHeader {
				t.Errorf("option header = 0x%02X, want 0x%02X", opts[0], expectedHeader)
			}
			value := opts[1 : 1+wantLen]
			if !bytes.Equal(value, tt.want) {
				t.Errorf("option value = %X, want %X", value, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 5: Block option encoding
// ---------------------------------------------------------------------------

func TestBlockOptionEncoding(t *testing.T) {
	tests := []struct {
		name     string
		option   coap.OptionNumber
		blockNum uint32
		more     bool
		szx      uint8
		wantVal  []byte
	}{
		{
			name:     "Block2 num=0 more=true szx=6",
			option:   coap.OptionBlock2,
			blockNum: 0, more: true, szx: 6,
			// (0<<4)|0x08|6 = 0x0E
			wantVal: []byte{0x0E},
		},
		{
			name:     "Block1 num=1 more=false szx=2",
			option:   coap.OptionBlock1,
			blockNum: 1, more: false, szx: 2,
			// (1<<4)|0x00|2 = 0x12
			wantVal: []byte{0x12},
		},
		{
			name:     "Block2 num=256 more=true szx=3",
			option:   coap.OptionBlock2,
			blockNum: 256, more: true, szx: 3,
			// (256<<4)|0x08|3 = 0x100B -> 2 bytes: 0x10, 0x0B
			wantVal: []byte{0x10, 0x0B},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
			if err := msg.AppendBlockOption(tt.option, tt.blockNum, tt.more, tt.szx); err != nil {
				t.Fatalf("AppendBlockOption: %v", err)
			}

			// Extract the option value from raw bytes.
			raw := msg.GetBytes()
			it := parseFirstOptionValue(t, raw)
			if !bytes.Equal(it, tt.wantVal) {
				t.Errorf("block option value = %X, want %X", it, tt.wantVal)
			}
		})
	}
}

// parseFirstOptionValue is a helper that extracts the value of the first
// option from a raw CoAP message (with no token).
func parseFirstOptionValue(t *testing.T, raw []byte) []byte {
	t.Helper()
	parsed, err := coap.ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	iter := parsed.GetOptionIterator()
	_, value, ok := iter.Next()
	if !ok {
		t.Fatal("no options found")
	}
	return value
}

// ---------------------------------------------------------------------------
// Test 6: Parse a known CoAP message byte sequence
// ---------------------------------------------------------------------------

func TestParseKnownMessage(t *testing.T) {
	// Build expected bytes by hand:
	// CON GET with 4-byte token, Uri-Path "test", payload "hello"
	//
	// Header: ver=1(01) type=CON(00) tkl=4(0100) -> 0x44
	//         code=GET -> 0x01
	//         messageID=0x0001
	// Token:  0xDE 0xAD 0xBE 0xEF
	// Option: Uri-Path(11) "test" -> delta=11 len=4 -> (11<<4)|4 = 0xB4
	// Payload marker: 0xFF
	// Payload: "hello"
	raw := []byte{
		0x44, 0x01, 0x00, 0x01, // header
		0xDE, 0xAD, 0xBE, 0xEF, // token
		0xB4, 't', 'e', 's', 't', // Uri-Path "test"
		0xFF,                    // payload marker
		'h', 'e', 'l', 'l', 'o', // payload
	}

	msg, err := coap.ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if msg.GetType() != coap.TypeConfirmable {
		t.Errorf("GetType = %d, want %d", msg.GetType(), coap.TypeConfirmable)
	}
	if msg.GetCode() != coap.CodeGet {
		t.Errorf("GetCode = 0x%02X, want 0x%02X", msg.GetCode(), coap.CodeGet)
	}
	if msg.GetMessageID() != 0x0001 {
		t.Errorf("GetMessageID = 0x%04X, want 0x0001", msg.GetMessageID())
	}
	if msg.GetTokenLength() != 4 {
		t.Errorf("GetTokenLength = %d, want 4", msg.GetTokenLength())
	}
	if !bytes.Equal(msg.GetToken(), []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("GetToken = %X, want DEADBEEF", msg.GetToken())
	}

	// Check options via iterator.
	iter := msg.GetOptionIterator()
	num, val, ok := iter.Next()
	if !ok {
		t.Fatal("expected option, got none")
	}
	if num != coap.OptionURIPath {
		t.Errorf("option number = %d, want %d", num, coap.OptionURIPath)
	}
	if string(val) != "test" {
		t.Errorf("option value = %q, want %q", string(val), "test")
	}
	_, _, ok = iter.Next()
	if ok {
		t.Error("expected no more options")
	}

	// Check payload.
	if !bytes.Equal(msg.GetPayload(), []byte("hello")) {
		t.Errorf("GetPayload = %q, want %q", msg.GetPayload(), "hello")
	}
}

// ---------------------------------------------------------------------------
// Test 7: Option iterator with multiple options
// ---------------------------------------------------------------------------

func TestOptionIterator(t *testing.T) {
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 0x5678)
	if err := msg.SetToken([]byte{0x01}); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	if err := msg.AppendObserveOption(1); err != nil {
		t.Fatalf("AppendObserveOption: %v", err)
	}
	if err := msg.AppendURIPathOptions("/a/b/c"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}
	if err := msg.AppendContentFormatOption(coap.ContentFormatJSON); err != nil {
		t.Fatalf("AppendContentFormatOption: %v", err)
	}
	if err := msg.AppendMaxAgeOption(60); err != nil {
		t.Fatalf("AppendMaxAgeOption: %v", err)
	}
	if err := msg.AppendPayloadMarker(); err != nil {
		t.Fatalf("AppendPayloadMarker: %v", err)
	}
	if err := msg.AppendPayload([]byte("data")); err != nil {
		t.Fatalf("AppendPayload: %v", err)
	}

	// Parse and iterate.
	parsed, err := coap.ParseMessage(msg.GetBytes())
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	type optEntry struct {
		number coap.OptionNumber
		value  string
	}
	var got []optEntry
	iter := parsed.GetOptionIterator()
	for {
		num, val, ok := iter.Next()
		if !ok {
			break
		}
		got = append(got, optEntry{num, string(val)})
	}

	want := []optEntry{
		{coap.OptionObserve, string([]byte{0x01})},
		{coap.OptionURIPath, "a"},
		{coap.OptionURIPath, "b"},
		{coap.OptionURIPath, "c"},
		{coap.OptionContentFormat, string([]byte{50})}, // JSON = 50
		{coap.OptionMaxAge, string([]byte{60})},        // 60
	}

	if len(got) != len(want) {
		t.Fatalf("got %d options, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].number != want[i].number {
			t.Errorf("option[%d] number = %d, want %d", i, got[i].number, want[i].number)
		}
		if got[i].value != want[i].value {
			t.Errorf("option[%d] value = %X, want %X", i, []byte(got[i].value), []byte(want[i].value))
		}
	}

	if !bytes.Equal(parsed.GetPayload(), []byte("data")) {
		t.Errorf("GetPayload = %q, want %q", parsed.GetPayload(), "data")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse validation errors
// ---------------------------------------------------------------------------

func TestParseMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"TooShort", []byte{0x40, 0x01}},
		{"WrongVersion", []byte{0x00, 0x01, 0x00, 0x01}},                 // ver=0
		{"TKLTooLong", []byte{0x49, 0x01, 0x00, 0x01}},                   // tkl=9
		{"TKLExceedsData", []byte{0x44, 0x01, 0x00, 0x01, 0xDE, 0xAD}},   // tkl=4 but only 2 token bytes
		{"PayloadMarkerNoPayload", []byte{0x40, 0x01, 0x00, 0x01, 0xFF}}, // marker without payload
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := coap.ParseMessage(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Message types
// ---------------------------------------------------------------------------

func TestMessageTypes(t *testing.T) {
	tests := []struct {
		name string
		typ  coap.Type
		want uint8
	}{
		{"CON", coap.TypeConfirmable, 0},
		{"NON", coap.TypeNonConfirmable, 1},
		{"ACK", coap.TypeAck, 2},
		{"RST", coap.TypeReset, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := coap.NewMessage(tt.typ, coap.CodeEmpty, 0x0000)
			parsed, err := coap.ParseMessage(msg.GetBytes())
			if err != nil {
				t.Fatalf("ParseMessage: %v", err)
			}
			if uint8(parsed.GetType()) != tt.want {
				t.Errorf("GetType() = %d, want %d", parsed.GetType(), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Token edge cases
// ---------------------------------------------------------------------------

func TestTokenEdgeCases(t *testing.T) {
	t.Run("NoToken", func(t *testing.T) {
		msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
		if msg.GetToken() != nil {
			t.Errorf("GetToken = %X, want nil", msg.GetToken())
		}
		if msg.GetTokenLength() != 0 {
			t.Errorf("GetTokenLength = %d, want 0", msg.GetTokenLength())
		}
	})

	t.Run("MaxToken", func(t *testing.T) {
		token := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
		if err := msg.SetToken(token); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		if !bytes.Equal(msg.GetToken(), token) {
			t.Errorf("GetToken = %X, want %X", msg.GetToken(), token)
		}
		if msg.GetTokenLength() != 8 {
			t.Errorf("GetTokenLength = %d, want 8", msg.GetTokenLength())
		}
	})

	t.Run("TokenTooLong", func(t *testing.T) {
		msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
		err := msg.SetToken([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
		if err == nil {
			t.Error("expected error for 9-byte token")
		}
	})
}

// ---------------------------------------------------------------------------
// Test: No payload
// ---------------------------------------------------------------------------

func TestNoPayload(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendURIPathOptions("/test"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}

	parsed, err := coap.ParseMessage(msg.GetBytes())
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if parsed.GetPayload() != nil {
		t.Errorf("GetPayload = %X, want nil", parsed.GetPayload())
	}
}

// ---------------------------------------------------------------------------
// Test: Uri-Query options
// ---------------------------------------------------------------------------

func TestUriQueryOptions(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendURIPathOptions("/resource"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}
	if err := msg.AppendURIQueryOptions("a=1&b=2"); err != nil {
		t.Fatalf("AppendURIQueryOptions: %v", err)
	}

	parsed, err := coap.ParseMessage(msg.GetBytes())
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	type optEntry struct {
		number coap.OptionNumber
		value  string
	}
	var got []optEntry
	iter := parsed.GetOptionIterator()
	for {
		num, val, ok := iter.Next()
		if !ok {
			break
		}
		got = append(got, optEntry{num, string(val)})
	}

	want := []optEntry{
		{coap.OptionURIPath, "resource"},
		{coap.OptionURIQuery, "a=1"},
		{coap.OptionURIQuery, "b=2"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d options, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].number != want[i].number {
			t.Errorf("option[%d] number = %d, want %d", i, got[i].number, want[i].number)
		}
		if got[i].value != want[i].value {
			t.Errorf("option[%d] value = %q, want %q", i, got[i].value, want[i].value)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Append option ordering error
// ---------------------------------------------------------------------------

func TestAppendOptionOrdering(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendOption(coap.OptionURIPath, []byte("a")); err != nil {
		t.Fatalf("AppendOption(11): %v", err)
	}
	// Appending an option with a lower number should fail.
	err := msg.AppendOption(coap.OptionURIHost, []byte("b"))
	if err == nil {
		t.Error("expected error when appending option with lower number")
	}
}

// ---------------------------------------------------------------------------
// Test: Round-trip build and parse with all message types
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		typ  coap.Type
		code coap.Code
		mid  uint16
	}{
		{"CON GET", coap.TypeConfirmable, coap.CodeGet, 0x0001},
		{"NON POST", coap.TypeNonConfirmable, coap.CodePost, 0x1234},
		{"ACK Content", coap.TypeAck, coap.CodeContent, 0xFFFF},
		{"RST Empty", coap.TypeReset, coap.CodeEmpty, 0x0000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := coap.NewMessage(tt.typ, tt.code, tt.mid)
			parsed, err := coap.ParseMessage(msg.GetBytes())
			if err != nil {
				t.Fatalf("ParseMessage: %v", err)
			}
			if parsed.GetType() != tt.typ {
				t.Errorf("GetType = %d, want %d", parsed.GetType(), tt.typ)
			}
			if parsed.GetCode() != tt.code {
				t.Errorf("GetCode = 0x%02X, want 0x%02X", parsed.GetCode(), tt.code)
			}
			if parsed.GetMessageID() != tt.mid {
				t.Errorf("GetMessageID = 0x%04X, want 0x%04X", parsed.GetMessageID(), tt.mid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: SetToken after options fails
// ---------------------------------------------------------------------------

func TestSetTokenAfterOptions(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendURIPathOptions("/test"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}
	err := msg.SetToken([]byte{0x01})
	if err == nil {
		t.Error("expected error when setting token after options")
	}
}

// ---------------------------------------------------------------------------
// Test: AppendURIPathOptions edge cases
// ---------------------------------------------------------------------------

func TestAppendURIPathOptionsEmpty(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendURIPathOptions(""); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}
	// No options should be appended.
	parsed, _ := coap.ParseMessage(msg.GetBytes())
	iter := parsed.GetOptionIterator()
	_, _, ok := iter.Next()
	if ok {
		t.Error("expected no options for empty path")
	}
}

func TestAppendURIPathOptionsLeadingSlash(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendURIPathOptions("/a/b"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}

	// Same as "a/b".
	msg2 := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg2.AppendURIPathOptions("a/b"); err != nil {
		t.Fatalf("AppendURIPathOptions: %v", err)
	}

	if !bytes.Equal(msg.GetBytes(), msg2.GetBytes()) {
		t.Error("leading slash should not change the encoding")
	}
}

// ---------------------------------------------------------------------------
// Test: AppendURIQueryOptions edge cases
// ---------------------------------------------------------------------------

func TestAppendURIQueryOptionsEmpty(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendURIQueryOptions(""); err != nil {
		t.Fatalf("AppendURIQueryOptions: %v", err)
	}

	parsed, _ := coap.ParseMessage(msg.GetBytes())
	iter := parsed.GetOptionIterator()
	_, _, ok := iter.Next()
	if ok {
		t.Error("expected no options for empty query")
	}
}

func TestAppendURIQueryOptionsSingle(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	_ = msg.AppendURIPathOptions("x")
	if err := msg.AppendURIQueryOptions("key=val"); err != nil {
		t.Fatalf("AppendURIQueryOptions: %v", err)
	}

	parsed, _ := coap.ParseMessage(msg.GetBytes())
	iter := parsed.GetOptionIterator()

	var queries []string
	for {
		num, val, ok := iter.Next()
		if !ok {
			break
		}
		if num == coap.OptionURIQuery {
			queries = append(queries, string(val))
		}
	}
	if len(queries) != 1 || queries[0] != "key=val" {
		t.Errorf("queries = %v, want [key=val]", queries)
	}
}

// ---------------------------------------------------------------------------
// Test: AppendBlockOption invalid szx
// ---------------------------------------------------------------------------

func TestAppendBlockOptionInvalidSzx(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	err := msg.AppendBlockOption(coap.OptionBlock2, 0, false, 7)
	if err == nil {
		t.Error("expected error for szx=7")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse messages with reserved nibble value (15)
// ---------------------------------------------------------------------------

func TestParseMessageReservedNibble(t *testing.T) {
	// Construct a message with delta nibble = 15 (reserved).
	data := []byte{
		0x40, 0x01, 0x00, 0x01, // valid header
		0xF0, // option with delta nibble = 15
	}
	_, err := coap.ParseMessage(data)
	if err == nil {
		t.Error("expected error for reserved delta nibble 15")
	}
}

func TestParseMessageReservedLengthNibble(t *testing.T) {
	// Construct a message with valid delta but length nibble = 15.
	data := []byte{
		0x40, 0x01, 0x00, 0x01, // valid header
		0x1F, // option with delta=1, length nibble=15
	}
	_, err := coap.ParseMessage(data)
	if err == nil {
		t.Error("expected error for reserved length nibble 15")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse message with extended delta/length nibble truncated
// ---------------------------------------------------------------------------

func TestParseMessageTruncatedExtendedDelta13(t *testing.T) {
	// Delta nibble = 13 but no extended byte follows.
	data := []byte{
		0x40, 0x01, 0x00, 0x01,
		0xD0, // delta=13, length=0, but no ext byte
	}
	_, err := coap.ParseMessage(data)
	if err == nil {
		t.Error("expected error for truncated extended delta (nibble=13)")
	}
}

func TestParseMessageTruncatedExtendedDelta14(t *testing.T) {
	// Delta nibble = 14 but only 1 extended byte instead of 2.
	data := []byte{
		0x40, 0x01, 0x00, 0x01,
		0xE0, 0x00, // delta=14, only 1 ext byte, needs 2
	}
	_, err := coap.ParseMessage(data)
	if err == nil {
		t.Error("expected error for truncated extended delta (nibble=14)")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse valid extended delta/length nibble 14
// ---------------------------------------------------------------------------

func TestParseMessageExtendedDelta14Valid(t *testing.T) {
	// Build a message with option number 300 (needs nibble=14 encoding).
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	if err := msg.AppendOption(coap.OptionNumber(300), []byte("v")); err != nil {
		t.Fatalf("AppendOption(300): %v", err)
	}

	parsed, err := coap.ParseMessage(msg.GetBytes())
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	iter := parsed.GetOptionIterator()
	num, val, ok := iter.Next()
	if !ok {
		t.Fatal("expected option")
	}
	if num != 300 {
		t.Errorf("option number = %d, want 300", num)
	}
	if string(val) != "v" {
		t.Errorf("option value = %q, want %q", val, "v")
	}
}

// ---------------------------------------------------------------------------
// Test: GetPayload with malformed option during walk
// ---------------------------------------------------------------------------

func TestGetPayloadNoOptions(t *testing.T) {
	// Header-only message, no options, no payload.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 0x0001)
	parsed, _ := coap.ParseMessage(msg.GetBytes())
	if parsed.GetPayload() != nil {
		t.Errorf("GetPayload = %X, want nil", parsed.GetPayload())
	}
}

// ---------------------------------------------------------------------------
// Fuzz: ParseMessage
// ---------------------------------------------------------------------------

func FuzzParseMessage(f *testing.F) {
	// Seed with valid messages.
	f.Add([]byte{0x40, 0x01, 0x00, 0x01})                                                   // minimal CON GET
	f.Add([]byte{0x42, 0x01, 0x12, 0x34, 0xAA, 0xBB})                                       // CON GET with token
	f.Add([]byte{0x44, 0x01, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0xB4, 't', 'e', 's', 't'}) // with option
	f.Add([]byte{0x40, 0x01, 0x00, 0x01, 0xFF, 0x01})                                       // with payload

	f.Fuzz(func(_ *testing.T, data []byte) {
		msg, err := coap.ParseMessage(data)
		if err != nil {
			return
		}
		_ = msg.GetType()
		_ = msg.GetCode()
		_ = msg.GetMessageID()
		_ = msg.GetTokenLength()
		_ = msg.GetToken()
		_ = msg.GetPayload()
		it := msg.GetOptionIterator()
		for {
			_, _, ok := it.Next()
			if !ok {
				break
			}
		}
	})
}
