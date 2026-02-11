// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package vendor provides Thread vendor information management.
//
// This is a Go port of the vendor info defined in OpenThread's
// src/core/thread/vendor_info.hpp.
package vendor

import "github.com/hilli/gothread/errors"

// Maximum field lengths.
const (
	MaxNameLength      = 32
	MaxModelLength     = 32
	MaxSwVersionLength = 16
	MaxDataLength      = 64
	MaxAppURLLength    = 64
)

// Info holds the Thread vendor information fields.
type Info struct {
	VendorName      string
	VendorModel     string
	VendorSwVersion string
	VendorData      string
	VendorAppURL    string
}

// Default returns an Info with empty fields. It represents the default
// vendor configuration.
func Default() Info {
	return Info{}
}

// Validate checks that all fields in the Info struct are within their
// maximum allowed lengths. Returns an error if any field is too long.
func Validate(info Info) error {
	if len(info.VendorName) > MaxNameLength {
		return errors.ErrInvalidArgs
	}
	if len(info.VendorModel) > MaxModelLength {
		return errors.ErrInvalidArgs
	}
	if len(info.VendorSwVersion) > MaxSwVersionLength {
		return errors.ErrInvalidArgs
	}
	if len(info.VendorData) > MaxDataLength {
		return errors.ErrInvalidArgs
	}
	if len(info.VendorAppURL) > MaxAppURLLength {
		return errors.ErrInvalidArgs
	}
	return nil
}
