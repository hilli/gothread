// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tinygo

package simulation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/hilli/gothread/crc"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
	"golang.org/x/sys/unix"
)

// Compile-time interface check.
var _ radio.Radio = (*UDPSimRadio)(nil)

const (
	// DefaultPortBase is the default UDP port base for the simulation protocol.
	DefaultPortBase = 9000
	// SimMulticastAddr is the multicast group used by OpenThread simulation nodes.
	SimMulticastAddr = "224.0.0.116"
	// udpMaxBuf is the maximum receive buffer size.
	udpMaxBuf = 256
)

// UDPSimRadio implements radio.Radio using OpenThread's UDP simulation protocol.
// It communicates with OpenThread simulation nodes via UDP multicast.
type UDPSimRadio struct {
	mu       sync.Mutex
	nodeID   uint16
	portBase uint16
	channel  uint8
	enabled  bool
	state    radio.State

	txConn *net.UDPConn    // send socket, bound to portBase+nodeID
	rxFd   int             // raw RX socket fd for multicast receive
	rxConn *net.UDPConn    // fallback RX (used when raw fd unavailable)
	rxMreq *syscall.IPMreq // saved for cleanup (IP_DROP_MEMBERSHIP)

	rxCallback func(*radio.Frame)
	stopCh     chan struct{}
	loopWg     sync.WaitGroup

	panID       uint16
	shortAddr   types.ShortAddress
	extAddr     types.ExtAddress
	txPower     int8
	promiscuous bool
	srcMatch    bool
	eui64       [8]byte
	txBuf       radio.Frame

	macFrameCounter uint32
}

// NewUDPSimRadio creates a radio bound to the given node ID using the default port base.
func NewUDPSimRadio(nodeID uint16) (*UDPSimRadio, error) {
	return NewUDPSimRadioWithPort(nodeID, DefaultPortBase)
}

// NewUDPSimRadioWithPort creates a radio bound to the given node ID and port base.
func NewUDPSimRadioWithPort(nodeID, portBase uint16) (*UDPSimRadio, error) {
	return &UDPSimRadio{
		nodeID:   nodeID,
		portBase: portBase,
		channel:  radio.Channel24GHzMin,
		eui64:    [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, byte(nodeID)},
	}, nil
}

// Start begins listening for incoming frames on the multicast group.
// It mimics the OpenThread simulation socket setup: TX binds to
// 127.0.0.1:portBase+nodeID, RX joins 224.0.0.116 on loopback.
func (r *UDPSimRadio) Start() (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// TX socket: bind to 127.0.0.1:portBase+nodeID (same as OT).
	txPort := int(r.portBase) + int(r.nodeID)
	txAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", txPort))
	if err != nil {
		return fmt.Errorf("resolve tx addr: %w", err)
	}
	txConn, err := net.ListenUDP("udp4", txAddr)
	if err != nil {
		return fmt.Errorf("bind tx socket: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, txConn.Close())
		}
	}()

	// Set IP_MULTICAST_IF to loopback and enable IP_MULTICAST_LOOP on TX
	// so packets go through the same path as OT.
	txRaw, err := txConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("tx syscall conn: %w", err)
	}
	var optionErr error
	if err := txRaw.Control(func(fd uintptr) {
		lo := [4]byte{127, 0, 0, 1}
		if err := syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, lo); err != nil {
			optionErr = fmt.Errorf("IP_MULTICAST_IF: %w", err)
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1); err != nil {
			optionErr = fmt.Errorf("IP_MULTICAST_LOOP: %w", err)
		}
	}); err != nil {
		return fmt.Errorf("configure tx socket: %w", err)
	}
	if optionErr != nil {
		return optionErr
	}

	// RX socket: use raw syscalls to exactly match OT's socket setup.
	// OT uses: SO_REUSEADDR, SO_REUSEPORT, IP_ADD_MEMBERSHIP on 127.0.0.1,
	// bind to 224.0.0.116:portBase.
	rxFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("rx socket: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, syscall.Close(rxFd))
		}
	}()
	if err := syscall.SetsockoptInt(rxFd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	if err := syscall.SetsockoptInt(rxFd, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("SO_REUSEPORT: %w", err)
	}

	// Join multicast group on loopback interface.
	mreq := syscall.IPMreq{
		Multiaddr: [4]byte{224, 0, 0, 116},
		Interface: [4]byte{127, 0, 0, 1},
	}
	if err := syscall.SetsockoptIPMreq(rxFd, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, &mreq); err != nil {
		return fmt.Errorf("IP_ADD_MEMBERSHIP: %w", err)
	}

	// Bind to 224.0.0.116:portBase.
	sa := syscall.SockaddrInet4{Port: int(r.portBase)}
	copy(sa.Addr[:], net.IPv4(224, 0, 0, 116).To4())
	if err := syscall.Bind(rxFd, &sa); err != nil {
		return fmt.Errorf("bind rx: %w", err)
	}
	if err := syscall.SetNonblock(rxFd, true); err != nil {
		return fmt.Errorf("rx nonblocking: %w", err)
	}

	r.txConn = txConn
	r.rxFd = rxFd
	r.rxMreq = &mreq
	r.stopCh = make(chan struct{})
	r.loopWg.Add(1)
	go r.receiveLoop()
	return nil
}

// Stop closes sockets and stops the receive goroutine.
func (r *UDPSimRadio) Stop() {
	r.mu.Lock()
	if r.stopCh != nil {
		close(r.stopCh)
		r.stopCh = nil
	}
	// Don't close rxFd here — let the nonblocking receiveLoop exit first,
	// then clean up. Otherwise Recvfrom on a closed fd hangs on macOS.
	if r.rxConn != nil {
		r.rxConn.Close()
		r.rxConn = nil
	}
	if r.txConn != nil {
		r.txConn.Close()
		r.txConn = nil
	}
	r.mu.Unlock()

	r.loopWg.Wait()

	// Now safe to close the rxFd after receiveLoop has exited.
	r.mu.Lock()
	if r.rxFd > 0 {
		if r.rxMreq != nil {
			syscall.SetsockoptIPMreq(r.rxFd, syscall.IPPROTO_IP, syscall.IP_DROP_MEMBERSHIP, r.rxMreq)
			r.rxMreq = nil
		}
		syscall.Close(r.rxFd)
		r.rxFd = 0
	}
	r.mu.Unlock()
}

func (r *UDPSimRadio) receiveLoop() {
	defer r.loopWg.Done()
	r.mu.Lock()
	fd := r.rxFd
	stop := r.stopCh
	r.mu.Unlock()
	if fd <= 0 || stop == nil {
		return
	}

	buf := make([]byte, udpMaxBuf)
	for {
		select {
		case <-stop:
			return
		default:
		}

		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// EAGAIN/EWOULDBLOCK means no data available — sleep briefly and retry.
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
					continue
				}
			}
			select {
			case <-stop:
				return
			default:
				continue
			}
		}
		if n < 2 { // need at least channel + 1 byte PSDU
			continue
		}

		// Filter out our own transmissions by source port.
		var senderPort int
		if sa, ok := from.(*syscall.SockaddrInet4); ok {
			senderPort = sa.Port
		}

		r.mu.Lock()
		selfPort := int(r.portBase) + int(r.nodeID)
		ch := r.channel
		state := r.state
		cb := r.rxCallback
		r.mu.Unlock()

		if senderPort == selfPort {
			continue
		}

		wireChannel := buf[0]
		if wireChannel != ch {
			continue
		}
		if state != radio.StateReceive {
			continue
		}

		psdu := make([]byte, n-1)
		copy(psdu, buf[1:n])

		frame := &radio.Frame{
			PSDU:    psdu,
			Channel: wireChannel,
			RxInfo: &radio.RxInfo{
				RSSI: -50,
				LQI:  255,
			},
		}
		if cb != nil {
			cb(frame)
		}
	}
}

// SetReceiveCallback sets the function called when a frame is received.
func (r *UDPSimRadio) SetReceiveCallback(cb func(*radio.Frame)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rxCallback = cb
}

// --- radio.Radio interface ---

func (r *UDPSimRadio) Enable() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = true
	r.state = radio.StateSleep
	return nil
}

func (r *UDPSimRadio) Disable() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = false
	r.state = radio.StateDisabled
	return nil
}

func (r *UDPSimRadio) IsEnabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled
}

func (r *UDPSimRadio) GetState() radio.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *UDPSimRadio) Sleep() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = radio.StateSleep
	return nil
}

func (r *UDPSimRadio) Receive(channel uint8) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channel = channel
	r.state = radio.StateReceive
	return nil
}

func (r *UDPSimRadio) Transmit(frame *radio.Frame) error {
	r.mu.Lock()
	r.state = radio.StateTransmit
	portBase := r.portBase
	ch := r.channel
	txConn := r.txConn
	r.mu.Unlock()

	if txConn == nil {
		return fmt.Errorf("udp sim radio: not started")
	}

	// Wire format: [channel][PSDU][CRC-16 LE]
	psdu := frame.PSDU
	checksum := crc.ChecksumCRC16CCITT(psdu)

	msg := make([]byte, 1+len(psdu)+2)
	msg[0] = ch
	copy(msg[1:], psdu)
	binary.LittleEndian.PutUint16(msg[1+len(psdu):], checksum)

	dst, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", SimMulticastAddr, portBase))
	if err != nil {
		return fmt.Errorf("resolve dst: %w", err)
	}
	_, err = txConn.WriteToUDP(msg, dst)
	return err
}

func (r *UDPSimRadio) GetTransmitBuffer() *radio.Frame {
	return &r.txBuf
}

func (r *UDPSimRadio) GetCaps() radio.Caps {
	return radio.CapNone
}

func (r *UDPSimRadio) GetIEEEEui64() [8]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.eui64
}

func (r *UDPSimRadio) SetPanID(panID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.panID = panID
}

func (r *UDPSimRadio) SetExtendedAddress(addr types.ExtAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extAddr = addr
}

func (r *UDPSimRadio) SetShortAddress(addr types.ShortAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shortAddr = addr
}

func (r *UDPSimRadio) GetTransmitPower() (int8, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.txPower, nil
}

func (r *UDPSimRadio) SetTransmitPower(power int8) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txPower = power
	return nil
}

func (r *UDPSimRadio) GetPromiscuous() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.promiscuous
}

func (r *UDPSimRadio) SetPromiscuous(enable bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.promiscuous = enable
}

func (r *UDPSimRadio) GetRSSI() int8 { return -50 }

func (r *UDPSimRadio) GetSupportedChannelMask() uint32 { return 0x07FFF800 }

func (r *UDPSimRadio) GetPreferredChannelMask() uint32 { return 0x07FFF800 }

func (r *UDPSimRadio) GetReceiveSensitivity() int8 { return -100 }

func (r *UDPSimRadio) EnableSrcMatch(enable bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.srcMatch = enable
}

func (r *UDPSimRadio) AddSrcMatchShortEntry(addr types.ShortAddress) error { return nil }
func (r *UDPSimRadio) AddSrcMatchExtEntry(addr types.ExtAddress) error     { return nil }
func (r *UDPSimRadio) ClearSrcMatchShortEntry(addr types.ShortAddress) error {
	return nil
}
func (r *UDPSimRadio) ClearSrcMatchExtEntry(addr types.ExtAddress) error { return nil }
func (r *UDPSimRadio) ClearSrcMatchShortEntries()                       {}
func (r *UDPSimRadio) ClearSrcMatchExtEntries()                         {}

func (r *UDPSimRadio) SetMacKey(keyIDMode uint8, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial) {
}

func (r *UDPSimRadio) SetMacFrameCounter(counter uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.macFrameCounter = counter
}

func (r *UDPSimRadio) SetMacFrameCounterIfLarger(counter uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if counter > r.macFrameCounter {
		r.macFrameCounter = counter
	}
}

func (r *UDPSimRadio) EnergyScan(channel uint8, duration uint16) error {
	return nil
}
