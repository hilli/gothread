// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package platform defines the Go interfaces for platform abstraction in
// gothread. Each interface corresponds to a set of platform functions that
// a concrete platform must provide.
//
// This is a Go port of the platform interfaces declared in OpenThread's
// include/openthread/platform/ headers (alarm-milli.h, alarm-micro.h,
// settings.h, entropy.h, logging.h, misc.h, time.h).
package platform

// --------------------------------------------------------------------------
// Alarm — millisecond precision timer (alarm-milli.h)
// --------------------------------------------------------------------------

// Alarm provides a millisecond-precision monotonic timer.
type Alarm interface {
	// Start schedules an alarm to fire at t0+dt milliseconds.
	Start(t0, dt uint32)

	// Stop cancels any pending alarm.
	Stop()

	// GetNow returns the current platform time in milliseconds.
	GetNow() uint32
}

// AlarmHandler is the callback invoked when an Alarm fires.
type AlarmHandler interface {
	// AlarmFired is called when the scheduled alarm expires.
	AlarmFired()
}

// --------------------------------------------------------------------------
// AlarmMicro — microsecond precision timer (alarm-micro.h, optional)
// --------------------------------------------------------------------------

// AlarmMicro provides a microsecond-precision monotonic timer.
// This interface is optional; platforms that do not support microsecond
// alarms (e.g. no CSL) need not implement it.
type AlarmMicro interface {
	// StartMicro schedules an alarm to fire at t0+dt microseconds.
	StartMicro(t0, dt uint32)

	// StopMicro cancels any pending microsecond alarm.
	StopMicro()

	// GetNowMicro returns the current platform time in microseconds.
	GetNowMicro() uint32
}

// AlarmMicroHandler is the callback invoked when an AlarmMicro fires.
type AlarmMicroHandler interface {
	// AlarmMicroFired is called when the scheduled microsecond alarm expires.
	AlarmMicroFired()
}

// --------------------------------------------------------------------------
// Time — 64-bit microsecond monotonic clock (time.h)
// --------------------------------------------------------------------------

// Time provides a 64-bit monotonic microsecond clock.
type Time interface {
	// Now returns the current platform time in microseconds.
	Now() uint64
}

// --------------------------------------------------------------------------
// Entropy — cryptographic random number source (entropy.h)
// --------------------------------------------------------------------------

// Entropy provides a cryptographically secure random byte source.
type Entropy interface {
	// Fill fills buf with cryptographic-quality random bytes.
	Fill(buf []byte) error
}

// --------------------------------------------------------------------------
// Settings — non-volatile storage (settings.h)
// --------------------------------------------------------------------------

// SettingsKey identifies a persistent setting.
type SettingsKey uint16

const (
	// SettingsKeyActiveDataset stores the Thread Active Operational Dataset.
	SettingsKeyActiveDataset SettingsKey = 0x0001
	// SettingsKeyPendingDataset stores the Thread Pending Operational Dataset.
	SettingsKeyPendingDataset SettingsKey = 0x0002
	// SettingsKeyNetworkInfo stores the Thread network information.
	SettingsKeyNetworkInfo SettingsKey = 0x0003
	// SettingsKeyParentInfo stores the Thread parent information.
	SettingsKeyParentInfo SettingsKey = 0x0004
	// SettingsKeyChildInfo stores the Thread child information.
	SettingsKeyChildInfo SettingsKey = 0x0005
	// SettingsKeySRPClientInfo stores the SRP client information.
	SettingsKeySRPClientInfo SettingsKey = 0x0007
	// SettingsKeySRPServerInfo stores the SRP server information.
	SettingsKeySRPServerInfo SettingsKey = 0x0008
	// SettingsKeySLAACIIDSecretKey stores the SLAAC IID secret key.
	SettingsKeySLAACIIDSecretKey SettingsKey = 0x0009
	// SettingsKeyDADInfo stores the duplicate address detection info.
	SettingsKeyDADInfo SettingsKey = 0x000a
	// SettingsKeyBorderAgentID stores the border agent identifier.
	SettingsKeyBorderAgentID SettingsKey = 0x000b
)

// Settings provides persistent non-volatile storage for Thread settings.
// Keys that hold multiple values (e.g. ChildInfo) use index-based access:
// Get and Delete accept an index parameter (0-based). An index of -1
// passed to Delete removes all entries for that key.
//
// Get must return ErrSettingsNotFound (possibly wrapped) only for absent
// entries, not for I/O failures or corrupt data. Set must atomically replace
// an entry and make it durable before returning success. A failed Set may
// leave either the old or the new complete value, never a partial value.
// Do not roll back stored state, share a namespace between live instances,
// or restore credentials without their associated counter reservations.
type Settings interface {
	// Get reads the entry at index for the setting identified by key.
	// For single-value keys, use index 0. Returns the value bytes or
	// an error if the key/index does not exist.
	Get(key SettingsKey, index int) ([]byte, error)

	// Set writes (or overwrites) a single-value setting identified by
	// key, replacing any existing list entries.
	Set(key SettingsKey, value []byte) error

	// Add appends a value to a list-type setting identified by key.
	Add(key SettingsKey, value []byte) error

	// Delete removes the entry at index for the setting identified by
	// key. An index of -1 deletes all entries for that key.
	Delete(key SettingsKey, index int) error

	// Wipe removes all settings (factory reset).
	Wipe() error
}

// --------------------------------------------------------------------------
// Logger — platform logging (logging.h)
// --------------------------------------------------------------------------

// LogLevel indicates the severity of a log message.
type LogLevel uint8

const (
	// LogLevelNone disables logging.
	LogLevelNone LogLevel = 0
	// LogLevelCrit indicates a critical/fatal log message.
	LogLevelCrit LogLevel = 1
	// LogLevelWarn indicates a warning log message.
	LogLevelWarn LogLevel = 2
	// LogLevelNote indicates a notable informational log message.
	LogLevelNote LogLevel = 3
	// LogLevelInfo indicates an informational log message.
	LogLevelInfo LogLevel = 4
	// LogLevelDebg indicates a debug log message.
	LogLevelDebg LogLevel = 5
)

// String returns the human-readable name of a LogLevel.
func (l LogLevel) String() string {
	switch l {
	case LogLevelNone:
		return "NONE"
	case LogLevelCrit:
		return "CRIT"
	case LogLevelWarn:
		return "WARN"
	case LogLevelNote:
		return "NOTE"
	case LogLevelInfo:
		return "INFO"
	case LogLevelDebg:
		return "DEBG"
	default:
		return "UNKN"
	}
}

// LogRegion identifies the subsystem that produced a log message.
type LogRegion uint8

const (
	// LogRegionAPI is the API/application region.
	LogRegionAPI LogRegion = iota
	// LogRegionMLE is the Mesh Link Establishment region.
	LogRegionMLE
	// LogRegionARP is the address resolution region.
	LogRegionARP
	// LogRegionNet is the IPv6/networking region.
	LogRegionNet
	// LogRegionMAC is the MAC layer region.
	LogRegionMAC
	// LogRegionCore is the core OpenThread region.
	LogRegionCore
	// LogRegionMem is the memory/heap region.
	LogRegionMem
	// LogRegionUtil is the utility region.
	LogRegionUtil
	// LogRegionBBR is the backbone router region.
	LogRegionBBR
	// LogRegionMLR is the multicast listener registration region.
	LogRegionMLR
	// LogRegionDNS is the DNS region.
	LogRegionDNS
	// LogRegionTCP is the TCP region.
	LogRegionTCP
	// LogRegionSRP is the SRP region.
	LogRegionSRP
	// LogRegionBR is the border router region.
	LogRegionBR
	// LogRegionCoAP is the CoAP protocol region.
	LogRegionCoAP
	// LogRegionPlatform is the platform/HAL region.
	LogRegionPlatform
)

// Logger provides platform-level logging.
type Logger interface {
	// Log emits a log message with the given severity level and region.
	Log(level LogLevel, region LogRegion, msg string)
}

// --------------------------------------------------------------------------
// Resetter — platform reset/reboot (misc.h)
// --------------------------------------------------------------------------

// ResetReason describes why the platform last reset.
type ResetReason uint8

const (
	// ResetPowerOn indicates a power-on reset.
	ResetPowerOn ResetReason = 0
	// ResetExternal indicates an external pin reset.
	ResetExternal ResetReason = 1
	// ResetSoftware indicates a software-requested reset.
	ResetSoftware ResetReason = 2
	// ResetFault indicates a hardware fault reset.
	ResetFault ResetReason = 3
	// ResetCrash indicates a crash/exception reset.
	ResetCrash ResetReason = 4
	// ResetAssert indicates an assertion-failure reset.
	ResetAssert ResetReason = 5
	// ResetWatchdog indicates a watchdog timer reset.
	ResetWatchdog ResetReason = 6
	// ResetOther indicates an unspecified reset reason.
	ResetOther ResetReason = 7
)

// String returns the human-readable name of a ResetReason.
func (r ResetReason) String() string {
	switch r {
	case ResetPowerOn:
		return "PowerOn"
	case ResetExternal:
		return "External"
	case ResetSoftware:
		return "Software"
	case ResetFault:
		return "Fault"
	case ResetCrash:
		return "Crash"
	case ResetAssert:
		return "Assert"
	case ResetWatchdog:
		return "Watchdog"
	case ResetOther:
		return "Other"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

// ErrSettingsNotFound is returned by Settings.Get when the key does not exist.
var ErrSettingsNotFound = &settingsError{msg: "settings: key not found"}

type settingsError struct {
	msg string
}

func (e *settingsError) Error() string {
	return e.msg
}

// Resetter provides platform reset and reset-reason query capability.
type Resetter interface {
	// Reset reboots the platform for the given reason.
	Reset(reason ResetReason)

	// GetResetReason returns the reason for the most recent platform reset.
	GetResetReason() ResetReason
}
