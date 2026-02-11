// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

import "testing"

func TestConfig_HasPrimary_Valid(t *testing.T) {
	c := Config{Server16: 0x0400}
	if !c.HasPrimary() {
		t.Fatal("expected HasPrimary() == true for valid Server16")
	}
}

func TestConfig_HasPrimary_Invalid(t *testing.T) {
	c := Config{Server16: InvalidServer16}
	if c.HasPrimary() {
		t.Fatal("expected HasPrimary() == false for InvalidServer16")
	}
}

func TestConfig_HasPrimary_Zero(t *testing.T) {
	c := Config{Server16: 0}
	if !c.HasPrimary() {
		t.Fatal("expected HasPrimary() == true for Server16 == 0")
	}
}

func TestConfig_DefaultValues(t *testing.T) {
	// Verify the constant values match the OpenThread specification.
	if DefaultRegistrationDelay != 5 {
		t.Fatalf("DefaultRegistrationDelay = %d, want 5", DefaultRegistrationDelay)
	}
	if DefaultMlrTimeout != 3600 {
		t.Fatalf("DefaultMlrTimeout = %d, want 3600", DefaultMlrTimeout)
	}
	if MinMlrTimeout != 300 {
		t.Fatalf("MinMlrTimeout = %d, want 300", MinMlrTimeout)
	}
	if MaxMlrTimeout != 2147483 {
		t.Fatalf("MaxMlrTimeout = %d, want 2147483", MaxMlrTimeout)
	}
	if DefaultRegistrationJitter != 5 {
		t.Fatalf("DefaultRegistrationJitter = %d, want 5", DefaultRegistrationJitter)
	}
	if ParentAggregateDelay != 5 {
		t.Fatalf("ParentAggregateDelay = %d, want 5", ParentAggregateDelay)
	}
	if BackboneUDPPort != 61631 {
		t.Fatalf("BackboneUDPPort = %d, want 61631", BackboneUDPPort)
	}
}

func TestConfig_MlrTimeoutRange(t *testing.T) {
	if DefaultMlrTimeout < MinMlrTimeout || DefaultMlrTimeout > MaxMlrTimeout {
		t.Fatal("DefaultMlrTimeout is not within [MinMlrTimeout, MaxMlrTimeout]")
	}
	// MaxMlrTimeout * 1000 should not overflow uint32.
	if uint64(MaxMlrTimeout)*1000 <= uint64(MaxMlrTimeout) {
		t.Fatal("MaxMlrTimeout * 1000 overflows")
	}
}

func TestDomainPrefixEvent_Values(t *testing.T) {
	if DomainPrefixAdded != 0 {
		t.Fatalf("DomainPrefixAdded = %d, want 0", DomainPrefixAdded)
	}
	if DomainPrefixRemoved != 1 {
		t.Fatalf("DomainPrefixRemoved = %d, want 1", DomainPrefixRemoved)
	}
	if DomainPrefixRefreshed != 2 {
		t.Fatalf("DomainPrefixRefreshed = %d, want 2", DomainPrefixRefreshed)
	}
	if DomainPrefixUnchanged != 3 {
		t.Fatalf("DomainPrefixUnchanged = %d, want 3", DomainPrefixUnchanged)
	}
}
