// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dtls_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/meshcop/dtls"

	goterrors "github.com/hilli/gothread/errors"
)

// --------------------------------------------------------------------------
// Mock Conn — simulates a DTLS connection for testing
// --------------------------------------------------------------------------

type mockConn struct {
	mu              sync.Mutex
	handshakeErr    error
	handshakeCalled bool
	readData        [][]byte
	readIdx         int
	readErr         error
	written         [][]byte
	closed          bool
	readCh          chan struct{} // signals when data is available
}

func newMockConn() *mockConn {
	return &mockConn{
		readCh: make(chan struct{}, 10),
	}
}

func (m *mockConn) Handshake() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handshakeCalled = true
	return m.handshakeErr
}

func (m *mockConn) Read(buf []byte) (int, error) {
	// Wait for data or close.
	<-m.readCh

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errors.New("connection closed")
	}

	if m.readErr != nil {
		return 0, m.readErr
	}

	if m.readIdx < len(m.readData) {
		n := copy(buf, m.readData[m.readIdx])
		m.readIdx++
		return n, nil
	}

	return 0, errors.New("connection closed")
}

func (m *mockConn) Write(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, errors.New("connection closed")
	}

	d := make([]byte, len(data))
	copy(d, data)
	m.written = append(m.written, d)
	return len(data), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	// Unblock any pending reads.
	select {
	case m.readCh <- struct{}{}:
	default:
	}
	return nil
}

func (m *mockConn) pushReadData(data []byte) {
	m.mu.Lock()
	d := make([]byte, len(data))
	copy(d, data)
	m.readData = append(m.readData, d)
	m.mu.Unlock()
	m.readCh <- struct{}{}
}

// --------------------------------------------------------------------------
// Mock ConnFactory
// --------------------------------------------------------------------------

type mockConnFactory struct {
	dialConn   *mockConn
	dialErr    error
	acceptConn *mockConn
	acceptErr  error
}

func (f *mockConnFactory) Dial(_ dtls.PeerInfo, _ *dtls.Credential) (dtls.Conn, error) {
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	return f.dialConn, nil
}

func (f *mockConnFactory) Accept(_ dtls.PeerInfo, _ *dtls.Credential, _ []byte) (dtls.Conn, error) {
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	return f.acceptConn, nil
}

// --------------------------------------------------------------------------
// Helper
// --------------------------------------------------------------------------

func testPeer(lastByte byte) dtls.PeerInfo {
	var addr [16]byte
	addr[15] = lastByte
	return dtls.PeerInfo{Address: addr, Port: 5684}
}

func testPSKCredential() *dtls.Credential {
	return &dtls.Credential{
		CipherSuite: dtls.CipherSuitePsk,
		PSK:         []byte("password"),
		PSKIdentity: []byte("identity"),
	}
}

func testEcjpakeCredential() *dtls.Credential {
	return &dtls.Credential{
		CipherSuite: dtls.CipherSuiteEcjpake,
		PSK:         []byte("J01NME"),
	}
}

// --------------------------------------------------------------------------
// SessionState tests
// --------------------------------------------------------------------------

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state dtls.SessionState
		want  string
	}{
		{dtls.StateDisconnected, "Disconnected"},
		{dtls.StateInitializing, "Initializing"},
		{dtls.StateConnecting, "Connecting"},
		{dtls.StateConnected, "Connected"},
		{dtls.StateDisconnecting, "Disconnecting"},
		{dtls.SessionState(255), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("SessionState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// ConnectEvent tests
// --------------------------------------------------------------------------

func TestConnectEventString(t *testing.T) {
	tests := []struct {
		event dtls.ConnectEvent
		want  string
	}{
		{dtls.EventConnected, "Connected"},
		{dtls.EventDisconnectedPeerClosed, "PeerClosed"},
		{dtls.EventDisconnectedLocalClosed, "LocalClosed"},
		{dtls.EventDisconnectedMaxAttempts, "MaxAttempts"},
		{dtls.EventDisconnectedError, "Error"},
		{dtls.EventDisconnectedTimeout, "Timeout"},
		{dtls.ConnectEvent(255), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.event.String(); got != tt.want {
			t.Errorf("ConnectEvent(%d).String() = %q, want %q", tt.event, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// CipherSuite tests
// --------------------------------------------------------------------------

func TestCipherSuiteString(t *testing.T) {
	tests := []struct {
		cs   dtls.CipherSuite
		want string
	}{
		{dtls.CipherSuiteEcjpake, "ECJPAKE_WITH_AES_128_CCM_8"},
		{dtls.CipherSuitePsk, "PSK_WITH_AES_128_CCM_8"},
		{dtls.CipherSuiteEcdheEcdsa, "ECDHE_ECDSA_WITH_AES_128_CCM_8"},
		{dtls.CipherSuite(255), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.cs.String(); got != tt.want {
			t.Errorf("CipherSuite(%d).String() = %q, want %q", tt.cs, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Credential tests
// --------------------------------------------------------------------------

func TestCredentialValidate(t *testing.T) {
	t.Run("valid PSK", func(t *testing.T) {
		c := testPSKCredential()
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("PSK missing key", func(t *testing.T) {
		c := &dtls.Credential{CipherSuite: dtls.CipherSuitePsk, PSKIdentity: []byte("id")}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
	})

	t.Run("PSK missing identity", func(t *testing.T) {
		c := &dtls.Credential{CipherSuite: dtls.CipherSuitePsk, PSK: []byte("key")}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
	})

	t.Run("PSK too long", func(t *testing.T) {
		psk := make([]byte, dtls.MaxPSKLength+1)
		c := &dtls.Credential{CipherSuite: dtls.CipherSuitePsk, PSK: psk, PSKIdentity: []byte("id")}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
	})

	t.Run("valid ECJPAKE", func(t *testing.T) {
		c := testEcjpakeCredential()
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("ECJPAKE missing PSK", func(t *testing.T) {
		c := &dtls.Credential{CipherSuite: dtls.CipherSuiteEcjpake}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
	})

	t.Run("ECDHE-ECDSA missing cert", func(t *testing.T) {
		c := &dtls.Credential{CipherSuite: dtls.CipherSuiteEcdheEcdsa}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
	})

	t.Run("unknown cipher suite", func(t *testing.T) {
		c := &dtls.Credential{CipherSuite: dtls.CipherSuite(99)}
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
	})
}

// --------------------------------------------------------------------------
// PeerInfo tests
// --------------------------------------------------------------------------

func TestPeerInfoKey(t *testing.T) {
	p1 := testPeer(1)
	p2 := testPeer(2)
	p1b := testPeer(1)

	k1 := p1.Key()
	k2 := p2.Key()
	k1b := p1b.Key()

	if k1 == k2 {
		t.Error("different peers should have different keys")
	}
	if k1 != k1b {
		t.Error("same peers should have same keys")
	}
}

// --------------------------------------------------------------------------
// Session tests
// --------------------------------------------------------------------------

func TestNewSessionState(t *testing.T) {
	s := dtls.NewSession()
	if s.State() != dtls.StateDisconnected {
		t.Fatalf("new session state = %v, want Disconnected", s.State())
	}
	if s.IsConnected() {
		t.Fatal("new session should not be connected")
	}
	if s.IsConnectionActive() {
		t.Fatal("new session should not be connection active")
	}
}

func TestSessionConnectHandshakeSuccess(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	peer := testPeer(1)

	var gotEvent dtls.ConnectEvent
	eventCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		gotEvent = event
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	err := s.Connect(peer, conn)
	if err != nil {
		t.Fatalf("Connect() = %v, want nil", err)
	}

	// Wait for the handshake goroutine to complete.
	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect event")
	}

	// After handshake, close the conn to end the read loop.
	conn.Close()

	if gotEvent != dtls.EventConnected {
		t.Fatalf("connect event = %v, want Connected", gotEvent)
	}

	if !conn.handshakeCalled {
		t.Fatal("Handshake was not called")
	}

	if s.Peer() != peer {
		t.Fatalf("Peer() = %v, want %v", s.Peer(), peer)
	}

	if s.IsServer() {
		t.Fatal("client session should not be server")
	}
}

func TestSessionConnectHandshakeFailure(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	conn.handshakeErr = errors.New("handshake failed")
	peer := testPeer(1)

	var gotEvent dtls.ConnectEvent
	eventCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		gotEvent = event
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	err := s.Connect(peer, conn)
	if err != nil {
		t.Fatalf("Connect() = %v, want nil (async failure)", err)
	}

	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect event")
	}

	if gotEvent != dtls.EventDisconnectedError {
		t.Fatalf("connect event = %v, want Error", gotEvent)
	}

	if s.State() != dtls.StateDisconnected {
		t.Fatalf("state after failure = %v, want Disconnected", s.State())
	}
}

func TestSessionConnectWhenNotDisconnected(t *testing.T) {
	s := dtls.NewSession()
	conn1 := newMockConn()
	conn2 := newMockConn()
	peer := testPeer(1)

	// First connect — starts handshake asynchronously.
	eventCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(_ dtls.ConnectEvent) {
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	_ = s.Connect(peer, conn1)

	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first connect")
	}

	// Second connect should fail because session is now Connected.
	err := s.Connect(peer, conn2)
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("second Connect() = %v, want ErrInvalidState", err)
	}

	conn1.Close()
}

func TestSessionAccept(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	peer := testPeer(1)

	var gotEvent dtls.ConnectEvent
	eventCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		gotEvent = event
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	err := s.Accept(peer, conn)
	if err != nil {
		t.Fatalf("Accept() = %v, want nil", err)
	}

	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept event")
	}

	conn.Close()

	if gotEvent != dtls.EventConnected {
		t.Fatalf("accept event = %v, want Connected", gotEvent)
	}

	if !s.IsServer() {
		t.Fatal("accepted session should be server")
	}
}

func TestSessionSend(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(_ dtls.ConnectEvent) {
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	_ = s.Connect(peer, conn)

	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect")
	}

	data := []byte("hello, world")
	err := s.Send(data)
	if err != nil {
		t.Fatalf("Send() = %v, want nil", err)
	}

	conn.mu.Lock()
	if len(conn.written) != 1 {
		t.Fatalf("written count = %d, want 1", len(conn.written))
	}
	if string(conn.written[0]) != "hello, world" {
		t.Fatalf("written data = %q, want %q", conn.written[0], data)
	}
	conn.mu.Unlock()

	conn.Close()
}

func TestSessionSendWhenDisconnected(t *testing.T) {
	s := dtls.NewSession()
	err := s.Send([]byte("test"))
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("Send() on disconnected session = %v, want ErrInvalidState", err)
	}
}

func TestSessionReceive(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	peer := testPeer(1)

	connectCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(_ dtls.ConnectEvent) {
		select {
		case connectCh <- struct{}{}:
		default:
		}
	})

	var receivedData []byte
	var receivedPeer dtls.PeerInfo
	receiveCh := make(chan struct{}, 1)
	s.SetReceiveHandler(func(data []byte, p dtls.PeerInfo) {
		receivedData = data
		receivedPeer = p
		select {
		case receiveCh <- struct{}{}:
		default:
		}
	})

	_ = s.Connect(peer, conn)

	select {
	case <-connectCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect")
	}

	// Push data to the mock connection.
	conn.pushReadData([]byte("test data"))

	select {
	case <-receiveCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for receive")
	}

	if string(receivedData) != "test data" {
		t.Fatalf("received data = %q, want %q", receivedData, "test data")
	}
	if receivedPeer != peer {
		t.Fatalf("received peer = %v, want %v", receivedPeer, peer)
	}

	conn.Close()
}

func TestSessionDisconnect(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	peer := testPeer(1)

	events := make([]dtls.ConnectEvent, 0, 2)
	eventCh := make(chan struct{}, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		events = append(events, event)
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	_ = s.Connect(peer, conn)

	// Wait for connect.
	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect")
	}

	s.Disconnect()

	// Wait for disconnect event.
	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for disconnect event")
	}

	if len(events) < 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[1] != dtls.EventDisconnectedLocalClosed {
		t.Fatalf("disconnect event = %v, want LocalClosed", events[1])
	}

	if s.State() != dtls.StateDisconnecting {
		t.Fatalf("state after disconnect = %v, want Disconnecting", s.State())
	}

	// After guard time, should transition to Disconnected.
	time.Sleep(dtls.GuardTimeNewConnection + 100*time.Millisecond)
	if s.State() != dtls.StateDisconnected {
		t.Fatalf("state after guard time = %v, want Disconnected", s.State())
	}
}

func TestSessionMaxAttempts(t *testing.T) {
	s := dtls.NewSession()
	s.SetMaxAttempts(1)

	conn1 := newMockConn()
	conn1.handshakeErr = errors.New("fail")
	peer := testPeer(1)

	eventCh := make(chan struct{}, 2)
	s.SetConnectHandler(func(_ dtls.ConnectEvent) {
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	// First attempt.
	_ = s.Connect(peer, conn1)
	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first attempt")
	}

	// Second attempt should fail due to max attempts.
	conn2 := newMockConn()
	err := s.Connect(peer, conn2)
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("Connect() after max attempts = %v, want ErrInvalidState", err)
	}
}

func TestSessionKEK(t *testing.T) {
	s := dtls.NewSession()

	_, ok := s.KEK()
	if ok {
		t.Fatal("new session should not have KEK")
	}

	var kek [32]byte
	for i := range kek {
		kek[i] = byte(i)
	}
	s.SetKEK(kek)

	got, ok := s.KEK()
	if !ok {
		t.Fatal("KEK() ok = false after SetKEK")
	}
	if got != kek {
		t.Fatal("KEK() value mismatch")
	}
}

func TestSessionReset(t *testing.T) {
	s := dtls.NewSession()
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan struct{}, 1)
	s.SetConnectHandler(func(_ dtls.ConnectEvent) {
		select {
		case eventCh <- struct{}{}:
		default:
		}
	})

	_ = s.Connect(peer, conn)
	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect")
	}

	s.Reset()

	if s.State() != dtls.StateDisconnected {
		t.Fatalf("state after reset = %v, want Disconnected", s.State())
	}
	if s.IsConnectionActive() {
		t.Fatal("should not be connection active after reset")
	}
}

// --------------------------------------------------------------------------
// Transport tests
// --------------------------------------------------------------------------

func TestNewTransport(t *testing.T) {
	factory := &mockConnFactory{}
	cred := testPSKCredential()

	tr, err := dtls.NewTransport(factory, cred)
	if err != nil {
		t.Fatalf("NewTransport() = %v, want nil", err)
	}

	if tr.Port() != dtls.DefaultPort {
		t.Fatalf("Port() = %d, want %d", tr.Port(), dtls.DefaultPort)
	}

	if tr.SessionCount() != 0 {
		t.Fatalf("SessionCount() = %d, want 0", tr.SessionCount())
	}

	if tr.IsClosed() {
		t.Fatal("new transport should not be closed")
	}
}

func TestNewTransportInvalidCredential(t *testing.T) {
	factory := &mockConnFactory{}
	cred := &dtls.Credential{CipherSuite: dtls.CipherSuitePsk} // missing PSK

	_, err := dtls.NewTransport(factory, cred)
	if err == nil {
		t.Fatal("NewTransport() with invalid credential should fail")
	}
}

func TestNewTransportNilCredential(t *testing.T) {
	factory := &mockConnFactory{}

	tr, err := dtls.NewTransport(factory, nil)
	if err != nil {
		t.Fatalf("NewTransport(nil credential) = %v, want nil", err)
	}
	if tr == nil {
		t.Fatal("transport should not be nil")
	}
}

func TestTransportSetPort(t *testing.T) {
	factory := &mockConnFactory{}
	tr, _ := dtls.NewTransport(factory, nil)

	tr.SetPort(1234)
	if tr.Port() != 1234 {
		t.Fatalf("Port() = %d, want 1234", tr.Port())
	}
}

func TestTransportConnect(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)
	peer := testPeer(1)

	session, err := tr.Connect(peer)
	if err != nil {
		t.Fatalf("Connect() = %v, want nil", err)
	}

	// Wait for the handshake.
	time.Sleep(100 * time.Millisecond)

	if session == nil {
		t.Fatal("session should not be nil")
	}

	if tr.SessionCount() != 1 {
		t.Fatalf("SessionCount() = %d, want 1", tr.SessionCount())
	}

	found := tr.FindSession(peer)
	if found != session {
		t.Fatal("FindSession() should return the same session")
	}

	conn.Close()
}

func TestTransportConnectNoCredential(t *testing.T) {
	factory := &mockConnFactory{}
	tr, _ := dtls.NewTransport(factory, nil)

	_, err := tr.Connect(testPeer(1))
	if !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Fatalf("Connect() without credential = %v, want ErrInvalidArgs", err)
	}
}

func TestTransportConnectWhenClosed(t *testing.T) {
	factory := &mockConnFactory{}
	cred := testPSKCredential()
	tr, _ := dtls.NewTransport(factory, cred)
	tr.Close()

	_, err := tr.Connect(testPeer(1))
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("Connect() after Close() = %v, want ErrInvalidState", err)
	}
}

func TestTransportMaxSessions(t *testing.T) {
	conn1 := newMockConn()
	conn2 := newMockConn()
	factory := &mockConnFactory{dialConn: conn1}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)
	tr.MaxSessions = 1

	_, err := tr.Connect(testPeer(1))
	if err != nil {
		t.Fatalf("first Connect() = %v, want nil", err)
	}

	time.Sleep(100 * time.Millisecond)

	factory.dialConn = conn2
	_, err = tr.Connect(testPeer(2))
	if !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatalf("second Connect() = %v, want ErrNoBufs", err)
	}

	conn1.Close()
}

func TestTransportHandleReceiveAccept(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{acceptConn: conn}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)
	tr.AcceptHandler = func(_ dtls.PeerInfo) bool { return true }

	peer := testPeer(1)
	tr.HandleReceive([]byte{0x16, 0xfe, 0xfd}, peer) // fake ClientHello

	time.Sleep(100 * time.Millisecond)

	if tr.SessionCount() != 1 {
		t.Fatalf("SessionCount() = %d, want 1", tr.SessionCount())
	}

	session := tr.FindSession(peer)
	if session == nil {
		t.Fatal("FindSession() should not return nil")
	}

	conn.Close()
}

func TestTransportHandleReceiveReject(t *testing.T) {
	factory := &mockConnFactory{}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)
	tr.AcceptHandler = func(_ dtls.PeerInfo) bool { return false }

	peer := testPeer(1)
	tr.HandleReceive([]byte{0x16, 0xfe, 0xfd}, peer)

	time.Sleep(100 * time.Millisecond)

	if tr.SessionCount() != 0 {
		t.Fatalf("SessionCount() = %d, want 0", tr.SessionCount())
	}
}

func TestTransportClose(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)
	_, _ = tr.Connect(testPeer(1))

	time.Sleep(100 * time.Millisecond)

	tr.Close()

	if !tr.IsClosed() {
		t.Fatal("transport should be closed")
	}
	if tr.SessionCount() != 0 {
		t.Fatalf("SessionCount() after close = %d, want 0", tr.SessionCount())
	}
}

func TestTransportRemoveSession(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)
	peer := testPeer(1)

	var removedPeer dtls.PeerInfo
	tr.RemoveHandler = func(p dtls.PeerInfo) {
		removedPeer = p
	}

	_, _ = tr.Connect(peer)
	time.Sleep(100 * time.Millisecond)

	tr.RemoveSession(peer)

	if tr.SessionCount() != 0 {
		t.Fatalf("SessionCount() after remove = %d, want 0", tr.SessionCount())
	}
	if removedPeer != peer {
		t.Fatalf("removed peer = %v, want %v", removedPeer, peer)
	}
}

func TestTransportSessions(t *testing.T) {
	conn1 := newMockConn()
	conn2 := newMockConn()
	factory := &mockConnFactory{dialConn: conn1}
	cred := testPSKCredential()

	tr, _ := dtls.NewTransport(factory, cred)

	_, _ = tr.Connect(testPeer(1))
	time.Sleep(50 * time.Millisecond)

	factory.dialConn = conn2
	_, _ = tr.Connect(testPeer(2))
	time.Sleep(50 * time.Millisecond)

	sessions := tr.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("Sessions() len = %d, want 2", len(sessions))
	}

	conn1.Close()
	conn2.Close()
}

func TestTransportSetCredential(t *testing.T) {
	factory := &mockConnFactory{}
	tr, _ := dtls.NewTransport(factory, nil)

	err := tr.SetCredential(testPSKCredential())
	if err != nil {
		t.Fatalf("SetCredential() = %v, want nil", err)
	}

	// Invalid credential should fail.
	err = tr.SetCredential(&dtls.Credential{CipherSuite: dtls.CipherSuitePsk})
	if err == nil {
		t.Fatal("SetCredential() with invalid should fail")
	}
}

// --------------------------------------------------------------------------
// Constants tests
// --------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if dtls.DefaultPort != 5684 {
		t.Fatalf("DefaultPort = %d, want 5684", dtls.DefaultPort)
	}
	if dtls.MaxPSKLength != 32 {
		t.Fatalf("MaxPSKLength = %d, want 32", dtls.MaxPSKLength)
	}
	if dtls.ApplicationDataMaxLength != 1152 {
		t.Fatalf("ApplicationDataMaxLength = %d, want 1152", dtls.ApplicationDataMaxLength)
	}
}
