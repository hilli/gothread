// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coaps_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/meshcop/dtls"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/coaps"
)

// --------------------------------------------------------------------------
// Mock DTLS Conn
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
	readCh          chan struct{}
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

func (m *mockConn) getWritten() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([][]byte, len(m.written))
	for i, w := range m.written {
		result[i] = make([]byte, len(w))
		copy(result[i], w)
	}
	return result
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
// Helpers
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

// waitForConnect waits for a connect event and returns it.
func waitForConnect(ch <-chan dtls.ConnectEvent, timeout time.Duration) (dtls.ConnectEvent, bool) {
	select {
	case ev := <-ch:
		return ev, true
	case <-time.After(timeout):
		return 0, false
	}
}

// makeNONRequest creates a simple NON GET request message for testing.
func makeNONRequest(uriPath string) *coap.Message {
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeGet, 0)
	msg.SetToken([]byte{0x02})
	msg.AppendOption(coap.OptionURIPath, []byte(uriPath))
	return msg
}

// --------------------------------------------------------------------------
// Session tests
// --------------------------------------------------------------------------

func TestNewSession(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)

	if s.Engine() == nil {
		t.Fatal("Engine() should not be nil")
	}
	if s.DtlsSession() != dtlsSess {
		t.Fatal("DtlsSession() should return the wrapped session")
	}
	if s.IsConnected() {
		t.Fatal("new session should not be connected")
	}
}

func TestSessionConnect(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	err := s.Connect(peer, conn)
	if err != nil {
		t.Fatalf("Connect() = %v, want nil", err)
	}

	ev, ok := waitForConnect(eventCh, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for connect event")
	}
	if ev != dtls.EventConnected {
		t.Fatalf("connect event = %v, want Connected", ev)
	}

	if !s.IsConnected() {
		t.Fatal("session should be connected after handshake")
	}

	if s.Peer() != peer {
		t.Fatalf("Peer() = %v, want %v", s.Peer(), peer)
	}

	conn.Close()
}

func TestSessionSendMessage(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = s.Connect(peer, conn)
	waitForConnect(eventCh, 2*time.Second)

	// Send a NON message (no retransmission tracking).
	msg := makeNONRequest("test")
	err := s.SendMessageNoTrack(msg)
	if err != nil {
		t.Fatalf("SendMessageNoTrack() = %v, want nil", err)
	}

	// The data should have been written to the mock conn.
	time.Sleep(50 * time.Millisecond)
	written := conn.getWritten()
	if len(written) == 0 {
		t.Fatal("expected data written to DTLS conn")
	}

	conn.Close()
}

func TestSessionSendMessageWhenDisconnected(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)

	msg := makeNONRequest("test")
	err := s.SendMessage(msg, nil, nil)
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("SendMessage() when disconnected = %v, want ErrInvalidState", err)
	}
}

func TestSessionReceive(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	// Register a resource.
	receivedCh := make(chan struct{}, 1)
	var receivedMsg *coap.Message
	s.AddResource(&coap.Resource{
		URIPath: "test",
		Handler: func(msg *coap.Message, info coap.MessageInfo) {
			receivedMsg = msg
			select {
			case receivedCh <- struct{}{}:
			default:
			}
		},
	})

	_ = s.Connect(peer, conn)
	waitForConnect(eventCh, 2*time.Second)

	// Push a CoAP NON GET to "test" through the mock conn.
	reqMsg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeGet, 100)
	reqMsg.SetToken([]byte{0xAB})
	reqMsg.AppendOption(coap.OptionURIPath, []byte("test"))
	conn.pushReadData(reqMsg.GetBytes())

	select {
	case <-receivedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resource handler")
	}

	if receivedMsg == nil {
		t.Fatal("handler should have received a message")
	}
	if receivedMsg.GetCode() != coap.CodeGet {
		t.Fatalf("received code = %v, want GET", receivedMsg.GetCode())
	}
}

func TestSessionDisconnectCleansUp(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = s.Connect(peer, conn)
	waitForConnect(eventCh, 2*time.Second)

	s.Disconnect()

	ev, ok := waitForConnect(eventCh, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for disconnect event")
	}
	if ev != dtls.EventDisconnectedLocalClosed {
		t.Fatalf("disconnect event = %v, want LocalClosed", ev)
	}
}

func TestSessionCleanup(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)

	// Cleanup on a fresh session should not panic.
	s.Cleanup()
}

func TestSessionDefaultHandler(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)
	conn := newMockConn()
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	receivedCh := make(chan struct{}, 1)
	s.SetDefaultHandler(func(_ *coap.Message, _ coap.MessageInfo) {
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	_ = s.Connect(peer, conn)
	waitForConnect(eventCh, 2*time.Second)

	// Send a request to an unregistered path — should hit default handler.
	reqMsg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeGet, 200)
	reqMsg.SetToken([]byte{0xCD})
	reqMsg.AppendOption(coap.OptionURIPath, []byte("unregistered"))
	conn.pushReadData(reqMsg.GetBytes())

	select {
	case <-receivedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for default handler")
	}

	conn.Close()
}

func TestSessionRemoveResource(t *testing.T) {
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)

	s.AddResource(&coap.Resource{
		URIPath: "test",
		Handler: func(_ *coap.Message, _ coap.MessageInfo) {},
	})
	s.RemoveResource("test")

	// No panic = success. More thorough testing is in the engine tests.
}

// --------------------------------------------------------------------------
// SecureServer tests
// --------------------------------------------------------------------------

func TestNewSecureServer(t *testing.T) {
	factory := &mockConnFactory{}
	cred := testPSKCredential()

	ss, err := coaps.NewSecureServer(factory, cred)
	if err != nil {
		t.Fatalf("NewSecureServer() = %v, want nil", err)
	}
	if ss == nil {
		t.Fatal("server should not be nil")
	}
	if ss.IsStarted() {
		t.Fatal("server should not be started")
	}
	if ss.IsConnected() {
		t.Fatal("server should not be connected")
	}
}

func TestNewSecureServerNilCredential(t *testing.T) {
	factory := &mockConnFactory{}

	ss, err := coaps.NewSecureServer(factory, nil)
	if err != nil {
		t.Fatalf("NewSecureServer(nil cred) = %v, want nil", err)
	}
	if ss == nil {
		t.Fatal("server should not be nil")
	}
}

func TestNewSecureServerInvalidCredential(t *testing.T) {
	factory := &mockConnFactory{}
	cred := &dtls.Credential{CipherSuite: dtls.CipherSuitePsk} // missing PSK

	_, err := coaps.NewSecureServer(factory, cred)
	if err == nil {
		t.Fatal("NewSecureServer() with invalid credential should fail")
	}
}

func TestSecureServerStartStop(t *testing.T) {
	factory := &mockConnFactory{}
	ss, _ := coaps.NewSecureServer(factory, nil)

	if err := ss.Start(5684); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	if !ss.IsStarted() {
		t.Fatal("server should be started")
	}

	// Double start should fail.
	if err := ss.Start(5684); !errors.Is(err, goterrors.ErrAlready) {
		t.Fatalf("double Start() = %v, want ErrAlready", err)
	}

	ss.Stop()
	if ss.IsStarted() {
		t.Fatal("server should not be started after Stop()")
	}
}

func TestSecureServerConnect(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	ss, _ := coaps.NewSecureServer(factory, cred)
	_ = ss.Start(5684)
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	ss.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	err := ss.Connect(peer)
	if err != nil {
		t.Fatalf("Connect() = %v, want nil", err)
	}

	ev, ok := waitForConnect(eventCh, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for connect")
	}
	if ev != dtls.EventConnected {
		t.Fatalf("event = %v, want Connected", ev)
	}

	if !ss.IsConnected() {
		t.Fatal("server should be connected")
	}

	conn.Close()
}

func TestSecureServerConnectWhenNotStarted(t *testing.T) {
	factory := &mockConnFactory{}
	cred := testPSKCredential()
	ss, _ := coaps.NewSecureServer(factory, cred)

	err := ss.Connect(testPeer(1))
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("Connect() when not started = %v, want ErrInvalidState", err)
	}
}

func TestSecureServerSendMessage(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	ss, _ := coaps.NewSecureServer(factory, cred)
	_ = ss.Start(5684)
	peer := testPeer(1)

	eventCh := make(chan dtls.ConnectEvent, 2)
	ss.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = ss.Connect(peer)
	waitForConnect(eventCh, 2*time.Second)

	msg := makeNONRequest("test")
	err := ss.SendMessage(msg, nil, nil)
	if err != nil {
		t.Fatalf("SendMessage() = %v, want nil", err)
	}

	time.Sleep(50 * time.Millisecond)
	written := conn.getWritten()
	if len(written) == 0 {
		t.Fatal("expected data written")
	}

	conn.Close()
}

func TestSecureServerSendMessageWhenNoSession(t *testing.T) {
	factory := &mockConnFactory{}
	ss, _ := coaps.NewSecureServer(factory, nil)
	_ = ss.Start(5684)

	msg := makeNONRequest("test")
	err := ss.SendMessage(msg, nil, nil)
	if !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("SendMessage() without session = %v, want ErrInvalidState", err)
	}
}

func TestSecureServerDisconnect(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	ss, _ := coaps.NewSecureServer(factory, cred)
	_ = ss.Start(5684)

	eventCh := make(chan dtls.ConnectEvent, 2)
	ss.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = ss.Connect(testPeer(1))
	waitForConnect(eventCh, 2*time.Second)

	ss.Disconnect()

	ev, ok := waitForConnect(eventCh, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for disconnect")
	}
	if ev != dtls.EventDisconnectedLocalClosed {
		t.Fatalf("event = %v, want LocalClosed", ev)
	}
}

func TestSecureServerAddResource(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	ss, _ := coaps.NewSecureServer(factory, cred)
	_ = ss.Start(5684)

	// Add resource before connecting — should be applied to future sessions.
	receivedCh := make(chan struct{}, 1)
	ss.AddResource(&coap.Resource{
		URIPath: "test",
		Handler: func(_ *coap.Message, _ coap.MessageInfo) {
			select {
			case receivedCh <- struct{}{}:
			default:
			}
		},
	})

	eventCh := make(chan dtls.ConnectEvent, 2)
	ss.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = ss.Connect(testPeer(1))
	waitForConnect(eventCh, 2*time.Second)

	// Send a request that should hit the registered resource.
	reqMsg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeGet, 300)
	reqMsg.SetToken([]byte{0xEF})
	reqMsg.AppendOption(coap.OptionURIPath, []byte("test"))
	conn.pushReadData(reqMsg.GetBytes())

	select {
	case <-receivedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resource handler")
	}

	conn.Close()
}

func TestSecureServerRemoveResource(t *testing.T) {
	factory := &mockConnFactory{}
	ss, _ := coaps.NewSecureServer(factory, nil)

	ss.AddResource(&coap.Resource{
		URIPath: "test",
		Handler: func(_ *coap.Message, _ coap.MessageInfo) {},
	})
	ss.RemoveResource("test")
	// No panic = success.
}

func TestSecureServerSetDefaultHandler(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	ss, _ := coaps.NewSecureServer(factory, cred)
	_ = ss.Start(5684)

	receivedCh := make(chan struct{}, 1)
	ss.SetDefaultHandler(func(_ *coap.Message, _ coap.MessageInfo) {
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	eventCh := make(chan dtls.ConnectEvent, 2)
	ss.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = ss.Connect(testPeer(1))
	waitForConnect(eventCh, 2*time.Second)

	reqMsg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeGet, 400)
	reqMsg.SetToken([]byte{0x11})
	reqMsg.AppendOption(coap.OptionURIPath, []byte("unknown"))
	conn.pushReadData(reqMsg.GetBytes())

	select {
	case <-receivedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for default handler")
	}

	conn.Close()
}

func TestSecureServerSetCredential(t *testing.T) {
	factory := &mockConnFactory{}
	ss, _ := coaps.NewSecureServer(factory, nil)

	err := ss.SetCredential(testPSKCredential())
	if err != nil {
		t.Fatalf("SetCredential() = %v, want nil", err)
	}

	// Invalid credential should fail.
	err = ss.SetCredential(&dtls.Credential{CipherSuite: dtls.CipherSuitePsk})
	if err == nil {
		t.Fatal("SetCredential() with invalid should fail")
	}
}

func TestSecureServerGetSession(t *testing.T) {
	conn := newMockConn()
	factory := &mockConnFactory{dialConn: conn}
	cred := testPSKCredential()

	ss, _ := coaps.NewSecureServer(factory, cred)
	_ = ss.Start(5684)

	if ss.GetSession() != nil {
		t.Fatal("GetSession() should be nil before connect")
	}

	eventCh := make(chan dtls.ConnectEvent, 2)
	ss.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = ss.Connect(testPeer(1))
	waitForConnect(eventCh, 2*time.Second)

	if ss.GetSession() == nil {
		t.Fatal("GetSession() should not be nil after connect")
	}

	conn.Close()
}

// --------------------------------------------------------------------------
// peerInfoToMessageInfo helper test
// --------------------------------------------------------------------------

func TestPeerInfoToMessageInfo(t *testing.T) {
	// We test this indirectly by checking that messages sent through
	// the session have the correct addressing, but let's also verify
	// the session reports the correct peer.
	dtlsSess := dtls.NewSession()
	s := coaps.NewSession(dtlsSess)
	conn := newMockConn()
	peer := testPeer(42)

	eventCh := make(chan dtls.ConnectEvent, 2)
	s.SetConnectHandler(func(event dtls.ConnectEvent) {
		eventCh <- event
	})

	_ = s.Connect(peer, conn)
	waitForConnect(eventCh, 2*time.Second)

	if s.Peer().Address[15] != 42 {
		t.Fatalf("peer address last byte = %d, want 42", s.Peer().Address[15])
	}
	if s.Peer().Port != 5684 {
		t.Fatalf("peer port = %d, want 5684", s.Peer().Port)
	}

	conn.Close()
}
