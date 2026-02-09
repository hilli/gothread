// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import "testing"

func TestDeviceRole_String(t *testing.T) {
	tests := []struct {
		role DeviceRole
		want string
	}{
		{RoleDisabled, "Disabled"},
		{RoleDetached, "Detached"},
		{RoleChild, "Child"},
		{RoleRouter, "Router"},
		{RoleLeader, "Leader"},
		{DeviceRole(255), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.role.String(); got != tt.want {
				t.Errorf("DeviceRole(%d).String() = %q, want %q", tt.role, got, tt.want)
			}
		})
	}
}

func TestDeviceMode(t *testing.T) {
	tests := []struct {
		name    string
		rxOn    bool
		ftd     bool
		netData bool
		valid   bool
		isMED   bool
	}{
		{"none", false, false, false, true, false},
		{"netData only", false, false, true, true, false},
		{"rxOn only", true, false, false, true, true},
		{"rxOn+netData", true, false, true, true, true},
		{"ftd only", false, true, false, false, false},
		{"ftd+netData", false, true, true, false, false},
		{"rxOn+ftd", true, true, false, true, false},
		{"rxOn+ftd+netData", true, true, true, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mode uint8
			if tt.rxOn {
				mode |= ModeRxOnWhenIdle
			}
			if tt.ftd {
				mode |= ModeFullThreadDevice
			}
			if tt.netData {
				mode |= ModeFullNetworkData
			}

			dm := NewDeviceMode(mode)

			if got := dm.IsRxOnWhenIdle(); got != tt.rxOn {
				t.Errorf("IsRxOnWhenIdle() = %v, want %v", got, tt.rxOn)
			}
			if got := dm.IsFullThreadDevice(); got != tt.ftd {
				t.Errorf("IsFullThreadDevice() = %v, want %v", got, tt.ftd)
			}
			if got := dm.IsFullNetworkData(); got != tt.netData {
				t.Errorf("IsFullNetworkData() = %v, want %v", got, tt.netData)
			}
			if got := dm.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
			if got := dm.IsMinimalEndDevice(); got != tt.isMED {
				t.Errorf("IsMinimalEndDevice() = %v, want %v", got, tt.isMED)
			}

			// Reserved bit must always be set.
			if dm.Get()&ModeReserved == 0 {
				t.Error("Reserved bit not set")
			}
		})
	}
}

func TestDeviceMode_Set(t *testing.T) {
	dm := NewDeviceMode(0)
	dm.Set(ModeRxOnWhenIdle | ModeFullThreadDevice)

	if !dm.IsRxOnWhenIdle() {
		t.Error("expected RxOnWhenIdle after Set")
	}
	if !dm.IsFullThreadDevice() {
		t.Error("expected FullThreadDevice after Set")
	}
	if dm.Get()&ModeReserved == 0 {
		t.Error("Reserved bit not set after Set")
	}
}

func TestRLOC16Helpers(t *testing.T) {
	t.Run("RouterID0", func(t *testing.T) {
		rloc := RLOC16FromRouterID(0)
		if rloc != 0x0000 {
			t.Errorf("RLOC16FromRouterID(0) = 0x%04X, want 0x0000", rloc)
		}
		if got := RouterIDFromRLOC16(0x0000); got != 0 {
			t.Errorf("RouterIDFromRLOC16(0x0000) = %d, want 0", got)
		}
		if got := ChildIDFromRLOC16(0x0000); got != 0 {
			t.Errorf("ChildIDFromRLOC16(0x0000) = %d, want 0", got)
		}
		if !IsRouterRLOC16(0x0000) {
			t.Error("IsRouterRLOC16(0x0000) = false, want true")
		}
		if IsChildRLOC16(0x0000) {
			t.Error("IsChildRLOC16(0x0000) = true, want false")
		}
	})

	t.Run("RouterID1", func(t *testing.T) {
		rloc := RLOC16FromRouterID(1)
		if rloc != 0x0400 {
			t.Errorf("RLOC16FromRouterID(1) = 0x%04X, want 0x0400", rloc)
		}
		// Child of router 1: 0x0401
		if !IsChildRLOC16(0x0401) {
			t.Error("IsChildRLOC16(0x0401) = false, want true")
		}
		if got := RouterIDFromRLOC16(0x0401); got != 1 {
			t.Errorf("RouterIDFromRLOC16(0x0401) = %d, want 1", got)
		}
		if got := ChildIDFromRLOC16(0x0401); got != 1 {
			t.Errorf("ChildIDFromRLOC16(0x0401) = %d, want 1", got)
		}
		// Max child of router 1: 0x05ff
		if got := RouterIDFromRLOC16(0x05ff); got != 1 {
			t.Errorf("RouterIDFromRLOC16(0x05ff) = %d, want 1", got)
		}
		if got := ChildIDFromRLOC16(0x05ff); got != 511 {
			t.Errorf("ChildIDFromRLOC16(0x05ff) = %d, want 511", got)
		}
	})

	t.Run("RouterID62", func(t *testing.T) {
		rloc := RLOC16FromRouterID(62)
		if rloc != 0xF800 {
			t.Errorf("RLOC16FromRouterID(62) = 0x%04X, want 0xF800", rloc)
		}
	})

	t.Run("RouterIDValid", func(t *testing.T) {
		if !IsRouterIDValid(62) {
			t.Error("IsRouterIDValid(62) = false, want true")
		}
		if IsRouterIDValid(63) {
			t.Error("IsRouterIDValid(63) = true, want false")
		}
	})

	t.Run("RouterIDMatch", func(t *testing.T) {
		if !RouterIDMatch(0x0400, 0x0401) {
			t.Error("RouterIDMatch(0x0400, 0x0401) = false, want true")
		}
		if RouterIDMatch(0x0400, 0x0800) {
			t.Error("RouterIDMatch(0x0400, 0x0800) = true, want false")
		}
	})

	t.Run("ParentRLOC16", func(t *testing.T) {
		if got := ParentRLOC16ForRLOC16(0x0401); got != 0x0400 {
			t.Errorf("ParentRLOC16ForRLOC16(0x0401) = 0x%04X, want 0x0400", got)
		}
	})
}

func TestRouterIDSet(t *testing.T) {
	t.Run("Clear", func(t *testing.T) {
		var s RouterIDSet
		s.Add(5)
		s.Clear()

		if s.GetAllocatedCount() != 0 {
			t.Errorf("GetAllocatedCount() after Clear = %d, want 0", s.GetAllocatedCount())
		}
		if s.Contains(5) {
			t.Error("Contains(5) after Clear = true, want false")
		}
	})

	t.Run("AddContainsRemove", func(t *testing.T) {
		var s RouterIDSet

		ids := []uint8{0, 1, 31, 62}
		for _, id := range ids {
			s.Add(id)
		}

		if got := s.GetAllocatedCount(); got != uint8(len(ids)) {
			t.Errorf("GetAllocatedCount() = %d, want %d", got, len(ids))
		}

		for _, id := range ids {
			if !s.Contains(id) {
				t.Errorf("Contains(%d) = false, want true", id)
			}
		}

		// IDs not added should not be present.
		if s.Contains(2) {
			t.Error("Contains(2) = true, want false")
		}
		if s.Contains(63) {
			t.Error("Contains(63) = true, want false")
		}

		// Remove and verify.
		s.Remove(31)
		if s.Contains(31) {
			t.Error("Contains(31) after Remove = true, want false")
		}
		if got := s.GetAllocatedCount(); got != uint8(len(ids))-1 {
			t.Errorf("GetAllocatedCount() after Remove = %d, want %d", got, len(ids)-1)
		}
	})

	t.Run("MSBFirstBitOrdering", func(t *testing.T) {
		var s RouterIDSet
		s.Add(0)

		// Router ID 0 should set bit 7 (0x80) of byte 0.
		if s[0] != 0x80 {
			t.Errorf("Add(0): byte[0] = 0x%02X, want 0x80", s[0])
		}

		s.Clear()
		s.Add(7)
		// Router ID 7 should set bit 0 (0x01) of byte 0.
		if s[0] != 0x01 {
			t.Errorf("Add(7): byte[0] = 0x%02X, want 0x01", s[0])
		}

		s.Clear()
		s.Add(8)
		// Router ID 8 should set bit 7 (0x80) of byte 1.
		if s[1] != 0x80 {
			t.Errorf("Add(8): byte[1] = 0x%02X, want 0x80", s[1])
		}
	})
}

func TestALOCHelpers(t *testing.T) {
	t.Run("Leader", func(t *testing.T) {
		if !IsALOCForLeader(0xfc00) {
			t.Error("IsALOCForLeader(0xfc00) = false, want true")
		}
		if IsALOCForLeader(0xfc01) {
			t.Error("IsALOCForLeader(0xfc01) = true, want false")
		}
		if got := ALOCForLeader(); got != 0xfc00 {
			t.Errorf("ALOCForLeader() = 0x%04X, want 0xfc00", got)
		}
	})

	t.Run("DHCP6Agent", func(t *testing.T) {
		if !IsALOCForDHCP6Agent(0xfc01) {
			t.Error("IsALOCForDHCP6Agent(0xfc01) = false, want true")
		}
		if !IsALOCForDHCP6Agent(0xfc0f) {
			t.Error("IsALOCForDHCP6Agent(0xfc0f) = false, want true")
		}
		if IsALOCForDHCP6Agent(0xfc00) {
			t.Error("IsALOCForDHCP6Agent(0xfc00) = true, want false")
		}
		if IsALOCForDHCP6Agent(0xfc10) {
			t.Error("IsALOCForDHCP6Agent(0xfc10) = true, want false")
		}

		// Round-trip context ID.
		aloc := ALOCFromDHCP6AgentContextID(5)
		if !IsALOCForDHCP6Agent(aloc) {
			t.Errorf("ALOCFromDHCP6AgentContextID(5) = 0x%04X is not DHCP6Agent", aloc)
		}
		if got := ALOCDDHCP6AgentContextID(aloc); got != 5 {
			t.Errorf("ALOCDDHCP6AgentContextID(0x%04X) = %d, want 5", aloc, got)
		}
	})

	t.Run("Service", func(t *testing.T) {
		if !IsALOCForService(0xfc10) {
			t.Error("IsALOCForService(0xfc10) = false, want true")
		}
		if !IsALOCForService(0xfc1f) {
			t.Error("IsALOCForService(0xfc1f) = false, want true")
		}
		if IsALOCForService(0xfc0f) {
			t.Error("IsALOCForService(0xfc0f) = true, want false")
		}
		if IsALOCForService(0xfc20) {
			t.Error("IsALOCForService(0xfc20) = true, want false")
		}

		// Round-trip service ID.
		aloc := ALOCFromServiceID(5)
		if !IsALOCForService(aloc) {
			t.Errorf("ALOCFromServiceID(5) = 0x%04X is not Service", aloc)
		}
		if got := ALOCToServiceID(aloc); got != 5 {
			t.Errorf("ALOCToServiceID(0x%04X) = %d, want 5", aloc, got)
		}
	})

	t.Run("Commissioner", func(t *testing.T) {
		if !IsALOCForCommissioner(0xfc30) {
			t.Error("IsALOCForCommissioner(0xfc30) = false, want true")
		}
		if !IsALOCForCommissioner(0xfc37) {
			t.Error("IsALOCForCommissioner(0xfc37) = false, want true")
		}
		if IsALOCForCommissioner(0xfc2f) {
			t.Error("IsALOCForCommissioner(0xfc2f) = true, want false")
		}
		if IsALOCForCommissioner(0xfc38) {
			t.Error("IsALOCForCommissioner(0xfc38) = true, want false")
		}

		// Session ID masking.
		aloc := ALOCFromCommissionerSessionID(0x1234)
		if !IsALOCForCommissioner(aloc) {
			t.Errorf("ALOCFromCommissionerSessionID(0x1234) = 0x%04X is not Commissioner", aloc)
		}
		// 0x1234 & 0x0007 = 4, so ALOC = 0xfc34.
		if aloc != 0xfc34 {
			t.Errorf("ALOCFromCommissionerSessionID(0x1234) = 0x%04X, want 0xfc34", aloc)
		}
	})

	t.Run("PrimaryBackboneRouter", func(t *testing.T) {
		if !IsALOCForPrimaryBackboneRouter(0xfc38) {
			t.Error("IsALOCForPrimaryBackboneRouter(0xfc38) = false, want true")
		}
		if IsALOCForPrimaryBackboneRouter(0xfc37) {
			t.Error("IsALOCForPrimaryBackboneRouter(0xfc37) = true, want false")
		}
		if got := ALOCForPrimaryBackboneRouter(); got != 0xfc38 {
			t.Errorf("ALOCForPrimaryBackboneRouter() = 0x%04X, want 0xfc38", got)
		}
	})

	t.Run("NDAgent", func(t *testing.T) {
		if !IsALOCForNDAgent(0xfc40) {
			t.Error("IsALOCForNDAgent(0xfc40) = false, want true")
		}
		if !IsALOCForNDAgent(0xfc4e) {
			t.Error("IsALOCForNDAgent(0xfc4e) = false, want true")
		}
		if IsALOCForNDAgent(0xfc3f) {
			t.Error("IsALOCForNDAgent(0xfc3f) = true, want false")
		}
		if IsALOCForNDAgent(0xfc4f) {
			t.Error("IsALOCForNDAgent(0xfc4f) = true, want false")
		}

		// Round-trip context ID.
		aloc := ALOCFromNDAgentContextID(5)
		if !IsALOCForNDAgent(aloc) {
			t.Errorf("ALOCFromNDAgentContextID(5) = 0x%04X is not NDAgent", aloc)
		}
		if got := ALOCToNDAgentContextID(aloc); got != 5 {
			t.Errorf("ALOCToNDAgentContextID(0x%04X) = %d, want 5", aloc, got)
		}
	})
}

// ---------------------------------------------------------------------------
// ComparePartitions tests
// ---------------------------------------------------------------------------

func TestComparePartitions(t *testing.T) {
	tests := []struct {
		name       string
		singletonA bool
		leaderA    LeaderData
		singletonB bool
		leaderB    LeaderData
		want       int
	}{
		{
			name:       "higher weighting wins",
			singletonA: false,
			leaderA:    LeaderData{Weighting: 10, PartitionID: 1},
			singletonB: false,
			leaderB:    LeaderData{Weighting: 5, PartitionID: 2},
			want:       1,
		},
		{
			name:       "lower weighting loses",
			singletonA: false,
			leaderA:    LeaderData{Weighting: 5, PartitionID: 2},
			singletonB: false,
			leaderB:    LeaderData{Weighting: 10, PartitionID: 1},
			want:       -1,
		},
		{
			name:       "singleton loses to non-singleton",
			singletonA: true,
			leaderA:    LeaderData{Weighting: 64, PartitionID: 100},
			singletonB: false,
			leaderB:    LeaderData{Weighting: 64, PartitionID: 1},
			want:       -1,
		},
		{
			name:       "non-singleton beats singleton",
			singletonA: false,
			leaderA:    LeaderData{Weighting: 64, PartitionID: 1},
			singletonB: true,
			leaderB:    LeaderData{Weighting: 64, PartitionID: 100},
			want:       1,
		},
		{
			name:       "higher partition ID wins",
			singletonA: false,
			leaderA:    LeaderData{Weighting: 64, PartitionID: 200},
			singletonB: false,
			leaderB:    LeaderData{Weighting: 64, PartitionID: 100},
			want:       1,
		},
		{
			name:       "lower partition ID loses",
			singletonA: false,
			leaderA:    LeaderData{Weighting: 64, PartitionID: 100},
			singletonB: false,
			leaderB:    LeaderData{Weighting: 64, PartitionID: 200},
			want:       -1,
		},
		{
			name:       "equal partitions",
			singletonA: false,
			leaderA:    LeaderData{Weighting: 64, PartitionID: 100},
			singletonB: false,
			leaderB:    LeaderData{Weighting: 64, PartitionID: 100},
			want:       0,
		},
		{
			name:       "both singletons higher ID wins",
			singletonA: true,
			leaderA:    LeaderData{Weighting: 64, PartitionID: 200},
			singletonB: true,
			leaderB:    LeaderData{Weighting: 64, PartitionID: 100},
			want:       1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComparePartitions(tt.singletonA, tt.leaderA, tt.singletonB, tt.leaderB)
			if got != tt.want {
				t.Errorf("ComparePartitions() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IsSingleton tests
// ---------------------------------------------------------------------------

func TestIsSingleton(t *testing.T) {
	var empty RouterIDSet
	if IsSingleton(empty) {
		t.Error("empty set should not be singleton")
	}

	var one RouterIDSet
	one.Add(5)
	if !IsSingleton(one) {
		t.Error("set with one ID should be singleton")
	}

	var two RouterIDSet
	two.Add(5)
	two.Add(10)
	if IsSingleton(two) {
		t.Error("set with two IDs should not be singleton")
	}
}
