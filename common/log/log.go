// Copyright (c) 2026, Jan Hillegeer. All rights reserved.
// Copyright (c) 2022, The OpenThread Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// Package log implements the OpenThread logging subsystem.
//
// This is a Go port of openthread/src/core/common/log.hpp and log.cpp.
// It provides level-filtered, region-tagged logging with a pluggable Logger
// interface.
package log

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
	"sync"
	"time"
)

// Level represents a log severity level.
type Level uint8

const (
	// LevelNone disables all log output.
	LevelNone Level = iota
	// LevelCrit logs critical messages only.
	LevelCrit
	// LevelWarn logs warnings and above.
	LevelWarn
	// LevelNote logs notable events and above.
	LevelNote
	// LevelInfo logs informational messages and above.
	LevelInfo
	// LevelDebg logs debug messages and above (all messages).
	LevelDebg
)

// String returns a human-readable label for the log level.
func (l Level) String() string {
	switch l {
	case LevelNone:
		return "NONE"
	case LevelCrit:
		return "CRIT"
	case LevelWarn:
		return "WARN"
	case LevelNote:
		return "NOTE"
	case LevelInfo:
		return "INFO"
	case LevelDebg:
		return "DEBG"
	default:
		return "????"
	}
}

// Region identifies the subsystem that produced a log message.
type Region string

// OpenThread log regions.
const (
	RegionMle      Region = "Mle"
	RegionArp      Region = "Arp"
	RegionBbr      Region = "Bbr"
	RegionBr       Region = "Br"
	RegionCliApi   Region = "CliApi" //nolint:revive // Retain the established public API spelling for source compatibility.
	RegionCoap     Region = "Coap"
	RegionCore     Region = "Core"
	RegionDns      Region = "Dns" //nolint:revive // Retain the established public API spelling for source compatibility.
	RegionIcmp     Region = "Icmp"
	RegionIp6      Region = "Ip6" //nolint:revive // Retain the established public API spelling for source compatibility.
	RegionMac      Region = "Mac"
	RegionMesh     Region = "Mesh"
	RegionMeshCoP  Region = "MeshCoP"
	RegionMdns     Region = "Mdns"
	RegionNetData  Region = "NetData"
	RegionPlatform Region = "Platform"
	RegionSrp      Region = "Srp"
	RegionTmf      Region = "Tmf"
	RegionUtil     Region = "Util"
)

// Logger is the interface that must be implemented by a log backend.
type Logger interface {
	Log(level Level, region Region, format string, args ...interface{})
}

// DefaultLogger writes formatted log messages to an io.Writer, filtering by
// a configurable level threshold.
type DefaultLogger struct {
	mu    sync.Mutex
	w     io.Writer
	level Level
	nowFn func() time.Time // overridable for testing
}

// NewDefaultLogger creates a DefaultLogger that writes to w and only emits
// messages at level <= threshold. A threshold of LevelNone silences output.
func NewDefaultLogger(w io.Writer, threshold Level) *DefaultLogger {
	return &DefaultLogger{w: w, level: threshold, nowFn: time.Now}
}

// Log implements the Logger interface.
func (d *DefaultLogger) Log(level Level, region Region, format string, args ...interface{}) {
	if level == LevelNone || level > d.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ts := d.now().Format("2006-01-02 15:04:05.000")

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := fmt.Fprintf(d.w, "[%s] %s [%-8s] %s\n", ts, level, region, msg); err != nil {
		stdlog.Printf("gothread: write log: %v", err)
	}
}

func (d *DefaultLogger) now() time.Time {
	if d.nowFn != nil {
		return d.nowFn()
	}
	return time.Now()
}

// SetLevel changes the level threshold. Messages with level > threshold are
// suppressed.
func (d *DefaultLogger) SetLevel(l Level) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.level = l
}

// GetLevel returns the current level threshold.
func (d *DefaultLogger) GetLevel() Level {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.level
}

// Package-level logger state.
var (
	globalMu     sync.RWMutex
	globalLogger Logger = NewDefaultLogger(os.Stderr, LevelInfo)
)

// SetLogger replaces the package-level logger. Passing nil disables logging.
func SetLogger(l Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = l
}

// GetLogger returns the current package-level logger.
func GetLogger() Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger
}

func logAt(level Level, region Region, format string, args ...interface{}) {
	l := GetLogger()
	if l != nil {
		l.Log(level, region, format, args...)
	}
}

// Crit emits a critical log message.
func Crit(region Region, format string, args ...interface{}) {
	logAt(LevelCrit, region, format, args...)
}

// Warn emits a warning log message.
func Warn(region Region, format string, args ...interface{}) {
	logAt(LevelWarn, region, format, args...)
}

// Note emits a notable-event log message.
func Note(region Region, format string, args ...interface{}) {
	logAt(LevelNote, region, format, args...)
}

// Info emits an informational log message.
func Info(region Region, format string, args ...interface{}) {
	logAt(LevelInfo, region, format, args...)
}

// Debg emits a debug log message.
func Debg(region Region, format string, args ...interface{}) {
	logAt(LevelDebg, region, format, args...)
}
