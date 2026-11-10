// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

func TestStandardFragmentStopWithMissingForwarder(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	if err := inst.Do(context.Background(), func() error {
		inst.forwarder = nil
		return inst.SendUDP(nil, ip6.MessageInfo{})
	}); err != goterrors.ErrInvalidState {
		t.Fatalf("missing forwarding path admission=%v", err)
	}
	inst.Stop()
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	inst.Stop()
}
