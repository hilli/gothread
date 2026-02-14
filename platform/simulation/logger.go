// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"log"

	"github.com/hilli/gothread/platform"
)

// Compile-time interface check.
var _ platform.Logger = (*SimLogger)(nil)

// SimLogger implements platform.Logger using the standard log package.
type SimLogger struct {
	Level platform.LogLevel
}

// NewSimLogger creates a new SimLogger that logs messages at or below the given level.
func NewSimLogger(level platform.LogLevel) *SimLogger {
	return &SimLogger{Level: level}
}

// Log emits a log message with level and region prefixes.
func (l *SimLogger) Log(level platform.LogLevel, region platform.LogRegion, msg string) {
	if level > l.Level {
		return
	}
	log.Printf("[%s][%d] %s", level, region, msg)
}
