// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

var errStorage = errors.New("injected storage failure")

type persistentSettings struct {
	*simulation.SimSettings
	mu             sync.Mutex
	readFailure    platform.SettingsKey
	writeFailure   platform.SettingsKey
	deleteFailure  platform.SettingsKey
	commitThenFail bool
}

func newPersistentSettings() *persistentSettings {
	return &persistentSettings{SimSettings: simulation.NewSimSettings()}
}

func (s *persistentSettings) Get(k platform.SettingsKey, index int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k == s.readFailure {
		return nil, errStorage
	}
	return s.SimSettings.Get(k, index)
}

func (s *persistentSettings) Set(k platform.SettingsKey, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k == s.writeFailure && !s.commitThenFail {
		return errStorage
	}
	if err := s.SimSettings.Set(k, value); err != nil {
		return err
	}
	if k == s.writeFailure {
		return errStorage
	}
	return nil
}

func (s *persistentSettings) Delete(k platform.SettingsKey, index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k == s.deleteFailure {
		return errStorage
	}
	return s.SimSettings.Delete(k, index)
}

func datasetInfo() *meshcop.Info {
	info := &meshcop.Info{
		NetworkKey: [16]byte{0x12, 0x34, 0x56},
		Channel:    20, PanID: 0xabcd, NetworkName: "Persistent",
		Components: meshcop.Components{
			NetworkKey: true, Channel: true, PanID: true,
			NetworkName: true, ActiveTimestamp: true,
		},
	}
	info.ActiveTimestamp.SetSeconds(42)
	return info
}

func onLoop(t *testing.T, inst *instance.Instance, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	inst.PostTask(func() { done <- fn() })
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("event loop did not complete operation")
		return nil
	}
}

//nolint:gocritic // Match the public constructor's value-based Config API.
func startInstance(t *testing.T, cfg instance.Config, provision bool) *instance.Instance {
	t.Helper()
	inst := instance.New(cfg)
	if provision {
		if err := inst.ActiveDataset().SaveLocalFromInfo(datasetInfo()); err != nil {
			t.Fatal(err)
		}
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Stop)
	if err := onLoop(t, inst, func() error {
		if err := inst.IfConfigUp(); err != nil {
			return err
		}
		if err := inst.ThreadStart(); err != nil {
			return err
		}
		// Avoid background attachment traffic; the interface remains up.
		return inst.ThreadStop()
	}); err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestPersistenceDatasetLifecycle(t *testing.T) {
	s := newPersistentSettings()
	first := startInstance(t, instance.Config{Settings: s}, true)
	var pendingBytes []byte
	if err := onLoop(t, first, func() error {
		pending := datasetInfo()
		pending.Components.PendingTimestamp = true
		pending.PendingTimestamp.SetSeconds(43)
		pending.Components.Delay = true
		pending.Delay = 60000
		if err := first.PendingDataset().SaveLocalFromInfo(pending); err != nil {
			return err
		}
		pendingBytes = append([]byte(nil), meshcop.InfoToDataset(pending).Bytes()...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first.Stop()

	second := startInstance(t, instance.Config{Settings: s}, false)
	if err := onLoop(t, second, func() error {
		if !bytes.Equal(second.ReadActiveDataset(), meshcop.InfoToDataset(datasetInfo()).Bytes()) {
			return errors.New("active dataset not restored")
		}
		pending := &meshcop.Dataset{}
		if err := pending.SetFrom(pendingBytes); err != nil {
			return err
		}
		restored, err := second.PendingDataset().ReadInfo()
		if err != nil {
			return err
		}
		// Read adjusts/upserts Delay Timer, which can change TLV ordering.
		if *restored != pending.ConvertToInfo() {
			return errors.New("pending dataset contents not restored")
		}
		stored, err := s.Get(platform.SettingsKeyPendingDataset, 0)
		if err != nil || !bytes.Equal(stored, pendingBytes) {
			return fmt.Errorf("pending dataset storage changed on read: %w", err)
		}
		activeTS, pendingTS := second.GetActiveTimestamp(), second.GetPendingTimestamp()
		if !second.ActiveDataset().LocalSaved() || !second.PendingDataset().LocalSaved() ||
			activeTS.Seconds() != 42 || pendingTS.Seconds() != 43 {
			return errors.New("dataset manager timestamps/state not restored")
		}
		if second.GetPanChannel() != 20 || second.GetPanID() != 0xabcd ||
			second.KeyManager().GetNetworkKey() != key.NetworkKey(datasetInfo().NetworkKey) {
			return errors.New("restored active dataset not applied by ThreadStart")
		}
		if err := second.PendingDataset().Clear(); err != nil {
			return err
		}
		return second.ActiveDataset().SaveLocal(&meshcop.Dataset{})
	}); err != nil {
		t.Fatal(err)
	}
	second.Stop()
	third := instance.New(instance.Config{Settings: s})
	if err := third.Start(); err != nil {
		t.Fatal(err)
	}
	defer third.Stop()
	if err := onLoop(t, third, func() error {
		if third.ActiveDataset().LocalSaved() || third.PendingDataset().LocalSaved() {
			return errors.New("deleted datasets reappeared")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type capturedFrame struct {
	psdu  []byte
	state []byte
}

type recordingRadio struct {
	*simulation.SimRadio
	settings *persistentSettings
	frames   chan capturedFrame
}

func (r *recordingRadio) GetCaps() radio.Caps {
	return radio.CapCsmaBackoff | radio.CapTransmitRetries | radio.CapAckTimeout
}

func (r *recordingRadio) Transmit(frame *radio.Frame) error {
	state, err := r.settings.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != nil {
		return err
	}
	r.frames <- capturedFrame{psdu: append([]byte(nil), frame.PSDU...), state: state}
	// Deliberately do not deliver TransmitDone. A power cut may happen here.
	return nil
}

func sendAndCapture(t *testing.T, inst *instance.Instance, r *recordingRadio) (macCounter, mleCounter uint32) {
	t.Helper()
	msg := mle.NewMessage(mle.CommandAdvertisement)
	if err := onLoop(t, inst, func() error {
		return inst.MleService().Dispatcher().SendMessage(msg, mle.LinkLocalAllNodesMulticast)
	}); err != nil {
		t.Fatal(err)
	}
	var captured capturedFrame
	select {
	case captured = <-r.frames:
	case <-time.After(5 * time.Second):
		t.Fatal("radio did not receive frame")
	}
	ctx, offset, err := mesh.NewFramer().ParseFrameHeader(captured.psdu)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := mle.ParseMessage(msg.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	macCounter, mleCounter = ctx.Security.FrameCounter, pm.SecHeader.FrameCounter
	if macCounter >= binary.BigEndian.Uint32(captured.state[37:41]) ||
		mleCounter >= binary.BigEndian.Uint32(captured.state[41:45]) {
		t.Fatal("frame transmitted before durable MAC/MLE reservation")
	}
	var macKey [16]byte
	var address [8]byte
	if err := onLoop(t, inst, func() error {
		macKey = [16]byte(inst.KeyManager().GetCurrentMacKey())
		address = inst.GetExtAddress()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	plain, err := mesh.DecryptFramePayload(captured.psdu, offset, ctx, macKey, address)
	if err != nil || !bytes.HasSuffix(plain, msg.Bytes()) {
		t.Fatalf("radio frame does not contain encrypted MLE message: %v", err)
	}
	return macCounter, mleCounter
}

func TestPersistenceCrashRebootSkipsReservedCounters(t *testing.T) {
	s := newPersistentSettings()
	newRadio := func() *recordingRadio {
		return &recordingRadio{SimRadio: simulation.NewSimRadio(), settings: s, frames: make(chan capturedFrame, 4)}
	}
	r1 := newRadio()
	first := startInstance(t, instance.Config{Settings: s, Radio: r1}, true)
	if err := onLoop(t, first, func() error {
		first.SetCurrentKeySequence(17, key.ForceUpdate)
		return first.PersistenceError()
	}); err != nil {
		t.Fatal(err)
	}
	mac1, mle1 := sendAndCapture(t, first, r1)
	before, _ := s.Get(platform.SettingsKeyNetworkInfo, 0)
	first.Stop() // No ThreadStop, TX callback, or graceful state save.
	after, _ := s.Get(platform.SettingsKeyNetworkInfo, 0)
	if !bytes.Equal(before, after) {
		t.Fatal("Stop wrote security state; crash safety must not depend on Stop")
	}
	r2 := newRadio()
	second := startInstance(t, instance.Config{Settings: s, Radio: r2}, false)
	if err := onLoop(t, second, func() error {
		if second.GetCurrentKeySequence() != 17 {
			return errors.New("key sequence not restored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mac2, mle2 := sendAndCapture(t, second, r2)
	if mac2 <= mac1 || mle2 <= mle1 || mac2 < key.FrameCounterReservation || mle2 < key.FrameCounterReservation {
		t.Fatalf("reboot reused reserved counters: (%d,%d) -> (%d,%d)", mac1, mle1, mac2, mle2)
	}
}

// This drives the same public frame-request callback used by Mac, without a
// physical radio, so large reservation and exhaustion boundaries stay fast.
func buildSecuredFrame(inst *instance.Instance) (uint32, error) {
	if err := inst.SendMLE([]byte{0xff, 0x01}, mle.LinkLocalAllNodesMulticast); err != nil {
		return 0, err
	}
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		if err := inst.PersistenceError(); err != nil {
			return 0, err
		}
		return 0, errors.New("secured frame not built")
	}
	ctx, _, err := mesh.NewFramer().ParseFrameHeader(frame.PSDU)
	inst.HandleSentFrame(frame, nil)
	if err != nil {
		return 0, err
	}
	return ctx.Security.FrameCounter, nil
}

func TestPersistenceReservationBoundaryAndKeyChanges(t *testing.T) {
	s := newPersistentSettings()
	inst := startInstance(t, instance.Config{Settings: s}, true)
	for i := uint32(0); i <= key.FrameCounterReservation; i++ {
		if err := onLoop(t, inst, func() error {
			counter, err := buildSecuredMLE(inst)
			if err != nil || counter != i {
				return fmt.Errorf("MLE frame %d counter %d: %w", i, counter, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := onLoop(t, inst, func() error {
		state, err := s.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		if binary.BigEndian.Uint32(state[37:41]) != 2*key.FrameCounterReservation ||
			binary.BigEndian.Uint32(state[41:45]) != 2*key.FrameCounterReservation {
			return errors.New("reservation not extended at boundary")
		}
		for _, sequence := range []uint32{1, 0, math.MaxUint32, 0} {
			inst.SetCurrentKeySequence(sequence, key.ForceUpdate)
			counter, err := buildSecuredFrame(inst)
			if err != nil || counter <= key.FrameCounterReservation {
				return fmt.Errorf("sequence change reset counter to %d: %w", counter, err)
			}
			mleCounter, err := buildSecuredMLE(inst)
			if err != nil || mleCounter <= key.FrameCounterReservation {
				return fmt.Errorf("sequence change reset MLE counter to %d: %w", mleCounter, err)
			}
		}
		for _, networkKey := range []key.NetworkKey{{99}, key.NetworkKey(datasetInfo().NetworkKey)} {
			inst.KeyManager().SetNetworkKey(networkKey)
			counter, err := buildSecuredFrame(inst)
			if err != nil || counter <= key.FrameCounterReservation {
				return fmt.Errorf("network key change reset counter to %d: %w", counter, err)
			}
			mleCounter, err := buildSecuredMLE(inst)
			if err != nil || mleCounter <= key.FrameCounterReservation {
				return fmt.Errorf("network key change reset MLE counter to %d: %w", mleCounter, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceQueuedFramesAllocateAtBuildTime(t *testing.T) {
	inst := startInstance(t, instance.Config{Settings: newPersistentSettings()}, true)
	if err := onLoop(t, inst, func() error {
		for i := 0; i < 2; i++ {
			if err := inst.SendMLE([]byte{0xff, 1}, mle.LinkLocalAllNodesMulticast); err != nil {
				return err
			}
		}
		inst.SetCurrentKeySequence(4, key.ForceUpdate)
		for i := uint32(0); i < 2; i++ {
			frame := &radio.Frame{}
			if !inst.HandleFrameRequest(frame) {
				return errors.New("queued frame not built")
			}
			ctx, offset, err := mesh.NewFramer().ParseFrameHeader(frame.PSDU)
			if err != nil {
				return err
			}
			if ctx.Security.FrameCounter != i || ctx.Security.KeyId != inst.KeyManager().GetMacKeyId() {
				return errors.New("queued frame used stale security metadata")
			}
			if frame.TxInfo == nil || !frame.TxInfo.IsSecurityProcessed {
				return errors.New("software-secured frame not marked processed")
			}
			if _, err := mesh.DecryptFramePayload(frame.PSDU, offset, ctx,
				[16]byte(inst.KeyManager().GetCurrentMacKey()), inst.GetExtAddress()); err != nil {
				return err
			}
			inst.HandleSentFrame(frame, nil)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func buildSecuredMLE(inst *instance.Instance) (uint32, error) {
	msg := mle.NewMessage(mle.CommandAdvertisement)
	if err := inst.MleService().Dispatcher().SendMessage(msg, mle.LinkLocalAllNodesMulticast); err != nil {
		return 0, err
	}
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		if err := inst.PersistenceError(); err != nil {
			return 0, err
		}
		return 0, errors.New("secured MLE frame not built")
	}
	inst.HandleSentFrame(frame, nil)
	pm, err := mle.ParseMessage(msg.Bytes())
	if err != nil {
		return 0, err
	}
	return pm.SecHeader.FrameCounter, nil
}

func TestPersistenceDatasetFailures(t *testing.T) {
	s := newPersistentSettings()
	inst := startInstance(t, instance.Config{Settings: s}, true)
	if err := onLoop(t, inst, func() error {
		for _, dt := range []meshcop.DatasetType{meshcop.DatasetActive, meshcop.DatasetPending} {
			dm := inst.ActiveDataset().DatasetManager
			k := platform.SettingsKeyActiveDataset
			if dt == meshcop.DatasetPending {
				dm = inst.PendingDataset().DatasetManager
				k = platform.SettingsKeyPendingDataset
			}
			if err := dm.SaveLocalFromInfo(datasetInfo()); err != nil {
				return err
			}
			previous := dm.GetLocalTimestamp()
			info := datasetInfo()
			info.ActiveTimestamp.SetSeconds(100)
			ds := meshcop.InfoToDataset(info)
			s.writeFailure = k
			for _, save := range []func() error{
				func() error { return dm.SaveLocal(ds) },
				func() error { return dm.SaveLocalFromInfo(info) },
				func() error { return dm.SaveWithOptions(ds, true) },
			} {
				if err := save(); !errors.Is(err, errStorage) {
					return fmt.Errorf("dataset write failure hidden: %v", err)
				}
				if dm.GetLocalTimestamp() != previous {
					return errors.New("failed save changed local timestamp")
				}
			}
			s.writeFailure = 0
			s.deleteFailure = k
			if err := dm.Clear(); !errors.Is(err, errStorage) || !dm.LocalSaved() {
				return fmt.Errorf("failed deletion changed state or hid error: %v", err)
			}
			s.deleteFailure = 0
			s.readFailure = k
			if _, err := dm.Read(); !errors.Is(err, errStorage) {
				return fmt.Errorf("dataset read failure hidden: %v", err)
			}
			s.readFailure = 0
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceStartupFailures(t *testing.T) {
	for _, k := range []platform.SettingsKey{
		platform.SettingsKeyActiveDataset, platform.SettingsKeyPendingDataset, platform.SettingsKeyNetworkInfo,
	} {
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			for _, corrupt := range []bool{false, true} {
				s := newPersistentSettings()
				if corrupt {
					_ = s.Set(k, []byte{1, 2, 3})
				} else {
					s.readFailure = k
				}
				inst := instance.New(instance.Config{Settings: s})
				for _, start := range []func() error{inst.Start, inst.IfConfigUp, inst.ThreadStart} {
					if err := start(); err == nil || (!corrupt && !errors.Is(err, errStorage)) {
						t.Fatalf("startup ignored restore error (corrupt=%v): %v", corrupt, err)
					}
				}
			}
		})
	}
	t.Run("initial-write", func(t *testing.T) {
		s := newPersistentSettings()
		s.writeFailure = platform.SettingsKeyNetworkInfo
		if err := instance.New(instance.Config{Settings: s}).Start(); !errors.Is(err, errStorage) {
			t.Fatalf("initial counter write error hidden: %v", err)
		}
	})
	t.Run("credentials-without-counters", func(t *testing.T) {
		s := newPersistentSettings()
		_ = s.Set(platform.SettingsKeyActiveDataset, meshcop.InfoToDataset(datasetInfo()).Bytes())
		inst := instance.New(instance.Config{Settings: s})
		if err := inst.Start(); err == nil {
			inst.Stop()
			t.Fatal("existing credentials accepted without counter history")
		}
	})
	t.Run("counter-checksum", func(t *testing.T) {
		s := newPersistentSettings()
		if err := instance.New(instance.Config{Settings: s}).PersistenceError(); err != nil {
			t.Fatal(err)
		}
		state, err := s.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			t.Fatal(err)
		}
		state[37] ^= 1
		_ = s.Set(platform.SettingsKeyNetworkInfo, state)
		inst := instance.New(instance.Config{Settings: s})
		if err := inst.Start(); err == nil {
			inst.Stop()
			t.Fatal("damaged counter record passed checksum validation")
		}
	})
	t.Run("truncated-network-key", func(t *testing.T) {
		s := newPersistentSettings()
		_ = s.Set(platform.SettingsKeyActiveDataset, []byte{byte(meshcop.TLVNetworkKey), 1, 0x12})
		inst := instance.New(instance.Config{Settings: s})
		if err := inst.Start(); err == nil {
			inst.Stop()
			t.Fatal("structurally valid dataset with truncated credentials accepted")
		}
	})
}

func TestPersistenceCounterWriteFailureBlocksBothLayers(t *testing.T) {
	for _, mleFailure := range []bool{false, true} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("mle=%v/committed=%v", mleFailure, committed), func(t *testing.T) {
				s := newPersistentSettings()
				inst := startInstance(t, instance.Config{Settings: s}, true)
				if err := onLoop(t, inst, func() error {
					s.writeFailure = platform.SettingsKeyNetworkInfo
					s.commitThenFail = committed
					var err error
					if mleFailure {
						msg := mle.NewMessage(mle.CommandAdvertisement)
						before := append([]byte(nil), msg.Bytes()...)
						err = inst.MleService().Dispatcher().SendMessage(msg, mle.LinkLocalAllNodesMulticast)
						if !bytes.Equal(before, msg.Bytes()) || inst.GetMleFrameCounter() != 0 {
							return errors.New("failed MLE reservation encrypted or consumed a counter")
						}
					} else {
						_, err = buildSecuredFrame(inst)
					}
					if !errors.Is(err, errStorage) {
						return fmt.Errorf("counter reservation error hidden: %v", err)
					}
					s.writeFailure = 0
					if _, err := buildSecuredFrame(inst); !errors.Is(err, errStorage) {
						return errors.New("MAC resumed after ambiguous write failure")
					}
					err = inst.MleService().Dispatcher().SendMessage(mle.NewMessage(mle.CommandAdvertisement), mle.LinkLocalAllNodesMulticast)
					if !errors.Is(err, errStorage) {
						return errors.New("MLE resumed after ambiguous write failure")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				inst.Stop()
				fresh := startInstance(t, instance.Config{Settings: s}, false)
				if err := onLoop(t, fresh, func() error {
					counter, err := buildSecuredFrame(fresh)
					if committed && !mleFailure && counter < key.FrameCounterReservation {
						return errors.New("reboot ignored ambiguously committed reservation")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestPersistenceCounterExhaustion(t *testing.T) {
	s := newPersistentSettings()
	inst := startInstance(t, instance.Config{Settings: s}, true)
	if err := onLoop(t, inst, func() error {
		inst.KeyManager().SetMacFrameCounter(math.MaxUint32 - 1)
		inst.KeyManager().SetMleFrameCounter(math.MaxUint32 - 1)
		counter, err := buildSecuredFrame(inst)
		if err != nil || counter != math.MaxUint32-1 {
			return fmt.Errorf("last MAC counter: %d %w", counter, err)
		}
		msg := mle.NewMessage(mle.CommandAdvertisement)
		if err := inst.MleService().Dispatcher().SendMessage(msg, mle.LinkLocalAllNodesMulticast); err != nil {
			return err
		}
		if inst.GetMleFrameCounter() != math.MaxUint32 {
			return errors.New("last MLE counter wrapped")
		}
		err = inst.MleService().Dispatcher().SendMessage(mle.NewMessage(mle.CommandAdvertisement), mle.LinkLocalAllNodesMulticast)
		if !errors.Is(err, key.ErrFrameCounterExhausted) {
			return fmt.Errorf("MLE exhaustion hidden: %v", err)
		}
		inst.SetCurrentKeySequence(8, key.ForceUpdate)
		frame := &radio.Frame{}
		if inst.HandleFrameRequest(frame) {
			return errors.New("MAC exhaustion allowed another frame")
		}
		if inst.GetMacFrameCounter() != math.MaxUint32 {
			return errors.New("MAC counter wrapped")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inst.Stop()
	fresh := startInstance(t, instance.Config{Settings: s}, false)
	if err := onLoop(t, fresh, func() error {
		if fresh.GetMacFrameCounter() != math.MaxUint32 || fresh.GetMleFrameCounter() != math.MaxUint32 {
			return errors.New("reboot cleared exhausted state")
		}
		if _, err := buildSecuredMLE(fresh); !errors.Is(err, key.ErrFrameCounterExhausted) {
			return fmt.Errorf("rebooted MLE exhaustion hidden: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceReservationExtensionFailure(t *testing.T) {
	s := newPersistentSettings()
	inst := startInstance(t, instance.Config{Settings: s}, true)
	if err := onLoop(t, inst, func() error {
		if _, err := buildSecuredMLE(inst); err != nil {
			return err
		}
		inst.KeyManager().SetMacFrameCounter(key.FrameCounterReservation)
		inst.KeyManager().SetMleFrameCounter(key.FrameCounterReservation)
		s.writeFailure = platform.SettingsKeyNetworkInfo
		if _, err := buildSecuredMLE(inst); !errors.Is(err, errStorage) {
			return fmt.Errorf("extension failure hidden: %v", err)
		}
		state, err := s.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		if binary.BigEndian.Uint32(state[37:41]) != key.FrameCounterReservation ||
			binary.BigEndian.Uint32(state[41:45]) != key.FrameCounterReservation {
			return errors.New("failed extension changed durable bounds")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistenceKeySequenceWriteFailure(t *testing.T) {
	s := newPersistentSettings()
	inst := startInstance(t, instance.Config{Settings: s}, true)
	if err := onLoop(t, inst, func() error {
		s.writeFailure = platform.SettingsKeyNetworkInfo
		inst.SetCurrentKeySequence(9, key.ForceUpdate)
		if !errors.Is(inst.PersistenceError(), errStorage) || inst.GetCurrentKeySequence() != 0 {
			return errors.New("failed key-sequence persistence applied sequence or hid error")
		}
		if _, err := buildSecuredMLE(inst); !errors.Is(err, errStorage) {
			return fmt.Errorf("secured send ignored sequence persistence failure: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type offloadRadio struct{ *simulation.SimRadio }

func (*offloadRadio) GetCaps() radio.Caps { return radio.CapTransmitSec }

func TestPersistenceRejectsAutonomousSecurityOffload(t *testing.T) {
	inst := instance.New(instance.Config{
		Settings: newPersistentSettings(),
		Radio:    &offloadRadio{simulation.NewSimRadio()},
	})
	if err := inst.Start(); err == nil {
		inst.Stop()
		t.Fatal("persistent instance accepted unbounded hardware counter allocation")
	}
}

func TestPersistenceNilSettingsRemainVolatile(t *testing.T) {
	first := startInstance(t, instance.Config{}, true)
	if err := onLoop(t, first, func() error {
		a, err := buildSecuredFrame(first)
		if err != nil {
			return err
		}
		b, err := buildSecuredFrame(first)
		if err != nil || b <= a {
			return fmt.Errorf("volatile counters did not advance: %d %d %w", a, b, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first.Stop()
	second := instance.New(instance.Config{})
	if second.ActiveDataset().LocalSaved() || second.PendingDataset().LocalSaved() || second.GetMacFrameCounter() != 0 {
		t.Fatal("nil settings unexpectedly retained state")
	}
}
