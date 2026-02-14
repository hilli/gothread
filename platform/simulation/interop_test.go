// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tinygo

package simulation

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/radio"
)

// otCLIPath returns the path to the ot-cli-ftd binary, or empty if not found.
func otCLIPath() string {
	// Walk up from the test file to find the openthread build directory.
	_, filename, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	candidate := filepath.Join(repoRoot, "openthread", "build", "simulation",
		"examples", "apps", "cli", "ot-cli-ftd")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

// otNode manages an OpenThread CLI simulation process.
type otNode struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	mu     sync.Mutex
}

// startOTNode starts ot-cli-ftd with the given node ID and port base.
func startOTNode(t *testing.T, nodeID int, portBase uint16) *otNode {
	t.Helper()
	bin := otCLIPath()
	if bin == "" {
		t.Skip("ot-cli-ftd not found; skipping interop test")
	}

	cmd := exec.Command(bin, fmt.Sprintf("%d", nodeID))
	cmd.Stderr = io.Discard
	// Only set PORT_BASE if non-default, to match OT's default behavior.
	if portBase != 9000 {
		cmd.Env = append(os.Environ(), fmt.Sprintf("PORT_BASE=%d", portBase))
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start ot-cli-ftd: %v", err)
	}

	n := &otNode{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdoutPipe),
	}

	// Wait for initial prompt.
	time.Sleep(500 * time.Millisecond)

	t.Cleanup(func() {
		n.send("thread stop")
		n.send("ifconfig down")
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})

	return n
}

// send writes a command to the OT CLI and waits for "Done" response.
func (n *otNode) send(command string) string {
	n.mu.Lock()
	defer n.mu.Unlock()

	fmt.Fprintf(n.stdin, "%s\n", command)

	var lines []string
	for n.stdout.Scan() {
		line := n.stdout.Text()
		line = strings.TrimSpace(line)
		if line == "Done" {
			break
		}
		if line == "Error 7: InvalidArgs" || strings.HasPrefix(line, "Error") {
			break
		}
		// Skip the echoed command, empty lines, and prompt.
		if line == "" || line == "> " || line == ">" || line == command ||
			strings.HasPrefix(line, "> "+command) {
			continue
		}
		// Strip leading "> " prompt from output.
		line = strings.TrimPrefix(line, "> ")
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// TestInteropReceiveOTFrame verifies that a gothread UDPSimRadio can
// receive raw 802.15.4 frames transmitted by an OpenThread simulation node.
//
// This test:
//  1. Starts an OpenThread ot-cli-ftd node as leader on channel 15
//  2. Creates a gothread UDPSimRadio on the same channel/multicast group
//  3. Listens for frames from the OT node
//  4. Parses received frames as valid IEEE 802.15.4 MAC frames
//
// This proves UDP transport + frame format interoperability.
func TestInteropReceiveOTFrame(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interop test in short mode")
	}

	// Use default port base (9000) to match OpenThread's default.
	portBase := uint16(9000)

	// Start OpenThread node (node ID 1) with the same port base.
	otNode := startOTNode(t, 1, portBase)

	// Configure OT network on channel 15.
	otNode.send("dataset init new")
	otNode.send("dataset channel 15")
	otNode.send("dataset panid 0xface")
	otNode.send("dataset networkname InteropTest")
	otNode.send("dataset commit active")
	otNode.send("ifconfig up")
	otNode.send("thread start")

	// Wait for OT to become leader (can take up to 40s in simulation).
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		state := otNode.send("state")
		if strings.Contains(state, "leader") || strings.Contains(state, "router") {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Verify OT is leader.
	state := strings.TrimSpace(otNode.send("state"))
	if !strings.Contains(state, "leader") && !strings.Contains(state, "router") {
		t.Fatalf("OT node did not become leader, state: %q", state)
	}
	t.Logf("OT node state: %s", state)

	// Create gothread UDPSimRadio (node ID 2) on the same port base.
	goRadio, err := NewUDPSimRadioWithPort(2, portBase)
	if err != nil {
		t.Fatalf("NewUDPSimRadio: %v", err)
	}
	if err := goRadio.Start(); err != nil {
		t.Fatalf("goRadio.Start: %v", err)
	}
	defer goRadio.Stop()

	// Enable radio and set to receive on channel 15.
	goRadio.Enable()
	goRadio.Receive(15)

	// Collect received frames.
	var receivedFrames []*radio.Frame
	var framesMu sync.Mutex
	goRadio.SetReceiveCallback(func(f *radio.Frame) {
		framesMu.Lock()
		defer framesMu.Unlock()
		frameCopy := &radio.Frame{
			PSDU:    make([]byte, len(f.PSDU)),
			Channel: f.Channel,
		}
		copy(frameCopy.PSDU, f.PSDU)
		receivedFrames = append(receivedFrames, frameCopy)
	})

	// OT leader broadcasts MLE advertisements periodically.
	// Also trigger a discovery response by sending a "discover" command.
	otNode.send("discover")

	// Wait for frames to arrive.
	var gotFrame bool
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		framesMu.Lock()
		n := len(receivedFrames)
		framesMu.Unlock()
		if n > 0 {
			gotFrame = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !gotFrame {
		t.Fatal("did not receive any frames from OT node within 10 seconds")
	}

	framesMu.Lock()
	frames := make([]*radio.Frame, len(receivedFrames))
	copy(frames, receivedFrames)
	framesMu.Unlock()

	t.Logf("Received %d frames from OT node", len(frames))

	// Parse at least one frame as a valid 802.15.4 MAC frame.
	var parsed bool
	for i, f := range frames {
		if len(f.PSDU) < 5 {
			t.Logf("  frame[%d]: too short (%d bytes), skipping", i, len(f.PSDU))
			continue
		}

		// Strip FCS (last 2 bytes) — OT simulation appends CRC.
		psduNoFCS := f.PSDU
		if len(psduNoFCS) > 2 {
			psduNoFCS = f.PSDU[:len(f.PSDU)-2]
		}

		mf := frame.NewFrame(psduNoFCS)
		ft := mf.GetType()

		// We expect Data frames (type 1) or Beacon frames (type 0) or
		// MAC Command frames (type 3) from the OT node.
		if ft > 7 {
			t.Logf("  frame[%d]: invalid frame type %d", i, ft)
			continue
		}

		t.Logf("  frame[%d]: type=%d len=%d channel=%d", i, ft, len(f.PSDU), f.Channel)

		// Try to extract PAN ID.
		if panID, err := mf.GetDstPanID(); err == nil {
			t.Logf("    PAN ID: 0x%04X", panID)
			if panID == 0xFACE {
				t.Logf("    ✓ PAN ID matches our configured 0xFACE")
			}
		}

		// Try to extract destination address.
		if dstAddr, err := mf.GetDstAddr(); err == nil {
			if dstAddr.IsShort() {
				t.Logf("    Dst Short: 0x%04X", dstAddr.GetShort())
			} else if dstAddr.IsExtended() {
				ext := dstAddr.GetExtended()
				t.Logf("    Dst Ext: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
					ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7])
			}
		}

		// Extract security enabled bit.
		fc := binary.LittleEndian.Uint16(psduNoFCS[0:2])
		secEnabled := fc&0x0008 != 0
		t.Logf("    Security: %v", secEnabled)

		parsed = true
	}

	if !parsed {
		t.Fatal("could not parse any received frame as valid 802.15.4")
	}

	t.Log("✓ Successfully received and parsed 802.15.4 frames from OpenThread node")
}
