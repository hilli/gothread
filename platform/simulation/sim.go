// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package simulation provides simulated platform implementations for running
// Thread without hardware. All components are in-memory and suitable for
// testing and development.
package simulation

import "github.com/hilli/gothread/platform"

// Platform bundles all simulated platform components.
type Platform struct {
	Alarm    *SimAlarm
	Entropy  *SimEntropy
	Settings *SimSettings
	Logger   *SimLogger
	Radio    *SimRadio
}

// NewPlatform creates a complete simulation platform with all components
// initialized and ready to use.
func NewPlatform() *Platform {
	return &Platform{
		Alarm:    NewSimAlarm(),
		Entropy:  &SimEntropy{},
		Settings: NewSimSettings(),
		Logger:   NewSimLogger(platform.LogLevelDebg),
		Radio:    NewSimRadio(),
	}
}
