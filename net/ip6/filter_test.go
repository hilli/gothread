// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6_test

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

func TestFilterAddUnsecurePort(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	if err := f.AddUnsecurePort(1234); err != nil {
		t.Fatalf("AddUnsecurePort(1234) unexpected error: %v", err)
	}

	if err := f.AddUnsecurePort(5678); err != nil {
		t.Fatalf("AddUnsecurePort(5678) unexpected error: %v", err)
	}

	if !f.IsUnsecurePort(1234) {
		t.Error("expected port 1234 to be unsecure")
	}

	if !f.IsUnsecurePort(5678) {
		t.Error("expected port 5678 to be unsecure")
	}
}

func TestFilterAddUnsecurePortZero(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	err := f.AddUnsecurePort(0)
	if !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Fatalf("AddUnsecurePort(0) = %v, want ErrInvalidArgs", err)
	}
}

func TestFilterAddUnsecurePortDuplicate(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	if err := f.AddUnsecurePort(1234); err != nil {
		t.Fatalf("first AddUnsecurePort(1234): %v", err)
	}

	if err := f.AddUnsecurePort(1234); err != nil {
		t.Fatalf("duplicate AddUnsecurePort(1234) should be no-op, got: %v", err)
	}

	ports := f.GetUnsecurePorts()
	if len(ports) != 1 {
		t.Errorf("expected 1 port after duplicate add, got %d", len(ports))
	}
}

func TestFilterAddUnsecurePortFull(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	if err := f.AddUnsecurePort(1000); err != nil {
		t.Fatalf("AddUnsecurePort(1000): %v", err)
	}

	if err := f.AddUnsecurePort(2000); err != nil {
		t.Fatalf("AddUnsecurePort(2000): %v", err)
	}

	err := f.AddUnsecurePort(3000)
	if !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatalf("AddUnsecurePort(3000) = %v, want ErrNoBufs", err)
	}
}

func TestFilterRemoveUnsecurePort(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	if err := f.AddUnsecurePort(1234); err != nil {
		t.Fatalf("AddUnsecurePort(1234): %v", err)
	}

	if err := f.RemoveUnsecurePort(1234); err != nil {
		t.Fatalf("RemoveUnsecurePort(1234): %v", err)
	}

	if f.IsUnsecurePort(1234) {
		t.Error("port 1234 should no longer be unsecure after removal")
	}
}

func TestFilterRemoveUnsecurePortZero(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	err := f.RemoveUnsecurePort(0)
	if !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Fatalf("RemoveUnsecurePort(0) = %v, want ErrInvalidArgs", err)
	}
}

func TestFilterRemoveUnsecurePortNotFound(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	err := f.RemoveUnsecurePort(9999)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("RemoveUnsecurePort(9999) = %v, want ErrNotFound", err)
	}
}

func TestFilterRemoveAllUnsecurePorts(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	if err := f.AddUnsecurePort(1000); err != nil {
		t.Fatalf("AddUnsecurePort(1000): %v", err)
	}

	if err := f.AddUnsecurePort(2000); err != nil {
		t.Fatalf("AddUnsecurePort(2000): %v", err)
	}

	f.RemoveAllUnsecurePorts()

	ports := f.GetUnsecurePorts()
	if len(ports) != 0 {
		t.Errorf("expected 0 ports after RemoveAll, got %d", len(ports))
	}

	if f.IsUnsecurePort(1000) {
		t.Error("port 1000 should not be present after RemoveAll")
	}

	if f.IsUnsecurePort(2000) {
		t.Error("port 2000 should not be present after RemoveAll")
	}
}

func TestFilterGetUnsecurePorts(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	// Empty filter returns empty slice.
	ports := f.GetUnsecurePorts()
	if len(ports) != 0 {
		t.Fatalf("expected 0 ports on fresh filter, got %d", len(ports))
	}

	if err := f.AddUnsecurePort(4000); err != nil {
		t.Fatalf("AddUnsecurePort(4000): %v", err)
	}

	if err := f.AddUnsecurePort(5000); err != nil {
		t.Fatalf("AddUnsecurePort(5000): %v", err)
	}

	ports = f.GetUnsecurePorts()
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}

	if ports[0] != 4000 {
		t.Errorf("ports[0] = %d, want 4000", ports[0])
	}

	if ports[1] != 5000 {
		t.Errorf("ports[1] = %d, want 5000", ports[1])
	}
}

func TestFilterCompaction(t *testing.T) {
	t.Parallel()

	var f ip6.Filter

	if err := f.AddUnsecurePort(1111); err != nil {
		t.Fatalf("AddUnsecurePort(1111): %v", err)
	}

	if err := f.AddUnsecurePort(2222); err != nil {
		t.Fatalf("AddUnsecurePort(2222): %v", err)
	}

	// Remove the first port; the second should compact into slot 0.
	if err := f.RemoveUnsecurePort(1111); err != nil {
		t.Fatalf("RemoveUnsecurePort(1111): %v", err)
	}

	ports := f.GetUnsecurePorts()
	if len(ports) != 1 {
		t.Fatalf("expected 1 port after removal, got %d", len(ports))
	}

	if ports[0] != 2222 {
		t.Errorf("expected port 2222 in slot 0 after compaction, got %d", ports[0])
	}

	// After compaction we should be able to add another port again.
	if err := f.AddUnsecurePort(3333); err != nil {
		t.Fatalf("AddUnsecurePort(3333) after compaction: %v", err)
	}

	ports = f.GetUnsecurePorts()
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports after re-add, got %d", len(ports))
	}

	if ports[0] != 2222 || ports[1] != 3333 {
		t.Errorf("ports = %v, want [2222, 3333]", ports)
	}
}
