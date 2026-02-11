// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package vendor

import (
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	t.Parallel()

	info := Default()
	if info.VendorName != "" || info.VendorModel != "" || info.VendorSwVersion != "" ||
		info.VendorData != "" || info.VendorAppURL != "" {
		t.Error("Default() should return all empty strings")
	}
}

func TestValidate_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		info Info
	}{
		{"empty", Default()},
		{"all fields", Info{
			VendorName:      "Acme",
			VendorModel:     "Widget-1000",
			VendorSwVersion: "1.0.0",
			VendorData:      "custom data",
			VendorAppURL:    "https://example.com",
		}},
		{"max lengths", Info{
			VendorName:      strings.Repeat("a", MaxNameLength),
			VendorModel:     strings.Repeat("b", MaxModelLength),
			VendorSwVersion: strings.Repeat("c", MaxSwVersionLength),
			VendorData:      strings.Repeat("d", MaxDataLength),
			VendorAppURL:    strings.Repeat("e", MaxAppURLLength),
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(tt.info); err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestValidate_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		info Info
	}{
		{"name too long", Info{VendorName: strings.Repeat("x", MaxNameLength+1)}},
		{"model too long", Info{VendorModel: strings.Repeat("x", MaxModelLength+1)}},
		{"sw version too long", Info{VendorSwVersion: strings.Repeat("x", MaxSwVersionLength+1)}},
		{"data too long", Info{VendorData: strings.Repeat("x", MaxDataLength+1)}},
		{"app url too long", Info{VendorAppURL: strings.Repeat("x", MaxAppURLLength+1)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(tt.info); err == nil {
				t.Error("Validate() error = nil, want error")
			}
		})
	}
}
