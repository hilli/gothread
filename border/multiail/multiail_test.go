// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package multiail

import (
	"testing"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d.IsMultiAil() {
		t.Fatal("new detector should not be multi-AIL")
	}
	if d.GetInfraLinkCount() != 0 {
		t.Fatalf("new detector link count = %d, want 0", d.GetInfraLinkCount())
	}
	if d.GetRouterCount() != 0 {
		t.Fatalf("new detector router count = %d, want 0", d.GetRouterCount())
	}
}

func TestSingleRouter(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)

	if d.IsMultiAil() {
		t.Fatal("single router should not be multi-AIL")
	}
	if d.GetInfraLinkCount() != 1 {
		t.Fatalf("link count = %d, want 1", d.GetInfraLinkCount())
	}
	if d.GetRouterCount() != 1 {
		t.Fatalf("router count = %d, want 1", d.GetRouterCount())
	}
}

func TestMultipleRoutersSameLink(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 100)
	d.HandleRouterIdUpdated(3, 100)

	if d.IsMultiAil() {
		t.Fatal("multiple routers on same link should not be multi-AIL")
	}
	if d.GetInfraLinkCount() != 1 {
		t.Fatalf("link count = %d, want 1", d.GetInfraLinkCount())
	}
	if d.GetRouterCount() != 3 {
		t.Fatalf("router count = %d, want 3", d.GetRouterCount())
	}
}

func TestMultipleRoutersDifferentLinks(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 200)

	if !d.IsMultiAil() {
		t.Fatal("routers on different links should be multi-AIL")
	}
	if d.GetInfraLinkCount() != 2 {
		t.Fatalf("link count = %d, want 2", d.GetInfraLinkCount())
	}
}

func TestThreeDistinctLinks(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 200)
	d.HandleRouterIdUpdated(3, 300)

	if !d.IsMultiAil() {
		t.Fatal("three distinct links should be multi-AIL")
	}
	if d.GetInfraLinkCount() != 3 {
		t.Fatalf("link count = %d, want 3", d.GetInfraLinkCount())
	}
}

func TestUpdateRouterLinkId(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 200)

	if !d.IsMultiAil() {
		t.Fatal("expected multi-AIL before update")
	}

	// Update router 2 to same link as router 1.
	d.HandleRouterIdUpdated(2, 100)

	if d.IsMultiAil() {
		t.Fatal("should not be multi-AIL after update to same link")
	}
	if d.GetInfraLinkCount() != 1 {
		t.Fatalf("link count = %d, want 1", d.GetInfraLinkCount())
	}
}

func TestRemoveRouter(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 200)

	if !d.IsMultiAil() {
		t.Fatal("expected multi-AIL")
	}

	// Remove router 2.
	if !d.HandleRouterRemoved(2) {
		t.Fatal("HandleRouterRemoved should return true for tracked router")
	}

	if d.IsMultiAil() {
		t.Fatal("should not be multi-AIL after removing router")
	}
	if d.GetRouterCount() != 1 {
		t.Fatalf("router count = %d, want 1", d.GetRouterCount())
	}

	// Remove unknown router.
	if d.HandleRouterRemoved(99) {
		t.Fatal("HandleRouterRemoved should return false for unknown router")
	}
}

func TestRemoveAllRouters(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 200)

	d.HandleRouterRemoved(1)
	d.HandleRouterRemoved(2)

	if d.IsMultiAil() {
		t.Fatal("should not be multi-AIL with no routers")
	}
	if d.GetRouterCount() != 0 {
		t.Fatalf("router count = %d, want 0", d.GetRouterCount())
	}
	if d.GetInfraLinkCount() != 0 {
		t.Fatalf("link count = %d, want 0", d.GetInfraLinkCount())
	}
}

func TestClear(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 200)
	d.HandleRouterIdUpdated(3, 300)

	d.Clear()

	if d.IsMultiAil() {
		t.Fatal("should not be multi-AIL after Clear")
	}
	if d.GetRouterCount() != 0 {
		t.Fatalf("router count = %d, want 0", d.GetRouterCount())
	}
	if d.GetInfraLinkCount() != 0 {
		t.Fatalf("link count = %d, want 0", d.GetInfraLinkCount())
	}
}

func TestGetLinkIdForRouter(t *testing.T) {
	d := NewDetector()
	d.HandleRouterIdUpdated(5, 500)

	linkID, ok := d.GetLinkIdForRouter(5)
	if !ok {
		t.Fatal("expected router 5 to be found")
	}
	if linkID != 500 {
		t.Fatalf("linkID = %d, want 500", linkID)
	}

	_, ok = d.GetLinkIdForRouter(99)
	if ok {
		t.Fatal("expected router 99 to not be found")
	}
}

func TestMixedRoutersOnLinks(t *testing.T) {
	d := NewDetector()
	// 3 routers on link 100, 2 on link 200.
	d.HandleRouterIdUpdated(1, 100)
	d.HandleRouterIdUpdated(2, 100)
	d.HandleRouterIdUpdated(3, 100)
	d.HandleRouterIdUpdated(4, 200)
	d.HandleRouterIdUpdated(5, 200)

	if !d.IsMultiAil() {
		t.Fatal("expected multi-AIL")
	}
	if d.GetInfraLinkCount() != 2 {
		t.Fatalf("link count = %d, want 2", d.GetInfraLinkCount())
	}
	if d.GetRouterCount() != 5 {
		t.Fatalf("router count = %d, want 5", d.GetRouterCount())
	}

	// Remove all routers from link 200.
	d.HandleRouterRemoved(4)
	d.HandleRouterRemoved(5)

	if d.IsMultiAil() {
		t.Fatal("should not be multi-AIL after removing all link-200 routers")
	}
	if d.GetInfraLinkCount() != 1 {
		t.Fatalf("link count = %d, want 1", d.GetInfraLinkCount())
	}
}
