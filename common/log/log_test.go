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

package log

import (
	"bytes"
	"io"
	stdlog "log"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestDefaultLoggerReportsWriteFailure(t *testing.T) {
	var diagnostics bytes.Buffer
	original := stdlog.Writer()
	stdlog.SetOutput(&diagnostics)
	t.Cleanup(func() { stdlog.SetOutput(original) })

	logger := NewDefaultLogger(failingWriter{}, LevelInfo)
	logger.Log(LevelWarn, RegionCore, "message")
	if !strings.Contains(diagnostics.String(), "write log: "+io.ErrClosedPipe.Error()) {
		t.Fatalf("missing write failure diagnostic: %q", diagnostics.String())
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{LevelNone, "NONE"},
		{LevelCrit, "CRIT"},
		{LevelWarn, "WARN"},
		{LevelNote, "NOTE"},
		{LevelInfo, "INFO"},
		{LevelDebg, "DEBG"},
		{Level(99), "????"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestDefaultLoggerFiltering(t *testing.T) {
	tests := []struct {
		name      string
		threshold Level
		logLevel  Level
		wantEmpty bool
	}{
		{"crit at warn threshold", LevelWarn, LevelCrit, false},
		{"warn at warn threshold", LevelWarn, LevelWarn, false},
		{"info at warn threshold", LevelWarn, LevelInfo, true},
		{"debg at warn threshold", LevelWarn, LevelDebg, true},
		{"none level message", LevelDebg, LevelNone, true},
		{"crit at none threshold", LevelNone, LevelCrit, true},
		{"debg at debg threshold", LevelDebg, LevelDebg, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewDefaultLogger(&buf, tt.threshold)
			logger.Log(tt.logLevel, RegionCore, "test message")
			isEmpty := buf.Len() == 0
			if isEmpty != tt.wantEmpty {
				t.Errorf("got empty=%v, want empty=%v (threshold=%v, logLevel=%v, buf=%q)",
					isEmpty, tt.wantEmpty, tt.threshold, tt.logLevel, buf.String())
			}
		})
	}
}

func TestDefaultLoggerFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewDefaultLogger(&buf, LevelDebg)
	logger.Log(LevelInfo, RegionMle, "hello %s %d", "world", 42)
	line := buf.String()
	if !strings.Contains(line, "INFO") {
		t.Errorf("output missing level: %q", line)
	}
	if !strings.Contains(line, "Mle") {
		t.Errorf("output missing region: %q", line)
	}
	if !strings.Contains(line, "hello world 42") {
		t.Errorf("output missing message: %q", line)
	}
}

func TestDefaultLoggerSetGetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewDefaultLogger(&buf, LevelWarn)
	if got := logger.GetLevel(); got != LevelWarn {
		t.Fatalf("GetLevel() = %v, want %v", got, LevelWarn)
	}
	logger.SetLevel(LevelDebg)
	if got := logger.GetLevel(); got != LevelDebg {
		t.Fatalf("GetLevel() = %v after SetLevel, want %v", got, LevelDebg)
	}
}

// captureLogger captures log calls for verification.
type captureLogger struct {
	calls []capturedCall
}

type capturedCall struct {
	level  Level
	region Region
	msg    string
}

func (c *captureLogger) Log(level Level, region Region, format string, args ...interface{}) {
	c.calls = append(c.calls, capturedCall{
		level:  level,
		region: region,
		msg:    format, // simplified; not formatting args for capture
	})
}

func TestSetGetLogger(t *testing.T) {
	// Save and restore global logger.
	orig := GetLogger()
	defer SetLogger(orig)

	cl := &captureLogger{}
	SetLogger(cl)
	if got := GetLogger(); got != cl {
		t.Fatal("GetLogger did not return the logger set by SetLogger")
	}
}

func TestPackageLevelHelpers(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)

	cl := &captureLogger{}
	SetLogger(cl)

	Crit(RegionCore, "c")
	Warn(RegionMac, "w")
	Note(RegionIp6, "n")
	Info(RegionMesh, "i")
	Debg(RegionDns, "d")

	if len(cl.calls) != 5 {
		t.Fatalf("expected 5 calls, got %d", len(cl.calls))
	}

	tests := []struct {
		idx    int
		level  Level
		region Region
	}{
		{0, LevelCrit, RegionCore},
		{1, LevelWarn, RegionMac},
		{2, LevelNote, RegionIp6},
		{3, LevelInfo, RegionMesh},
		{4, LevelDebg, RegionDns},
	}
	for _, tt := range tests {
		c := cl.calls[tt.idx]
		if c.level != tt.level {
			t.Errorf("call[%d] level = %v, want %v", tt.idx, c.level, tt.level)
		}
		if c.region != tt.region {
			t.Errorf("call[%d] region = %v, want %v", tt.idx, c.region, tt.region)
		}
	}
}

func TestNilLoggerDoesNotPanic(t *testing.T) {
	orig := GetLogger()
	defer SetLogger(orig)

	SetLogger(nil)
	// These should not panic.
	Crit(RegionCore, "test")
	Info(RegionCore, "test")
}

func TestRegionConstants(t *testing.T) {
	// Verify that all regions are non-empty unique strings.
	regions := []Region{
		RegionMle, RegionArp, RegionBbr, RegionBr, RegionCliApi,
		RegionCoap, RegionCore, RegionDns, RegionIcmp, RegionIp6,
		RegionMac, RegionMesh, RegionMeshCoP, RegionMdns, RegionNetData,
		RegionPlatform, RegionSrp, RegionTmf, RegionUtil,
	}
	seen := make(map[Region]bool, len(regions))
	for _, r := range regions {
		if r == "" {
			t.Error("empty region constant")
		}
		if seen[r] {
			t.Errorf("duplicate region %q", r)
		}
		seen[r] = true
	}
}
