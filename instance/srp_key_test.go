package instance

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	csettings "github.com/hilli/gothread/common/settings"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
)

var errSRPStorage = errors.New("SRP storage failure")
var errSRPEntropy = errors.New("SRP entropy failure")

type srpEntropy struct {
	calls int
	fail  bool
	next  byte
}

func (e *srpEntropy) Fill(dst []byte) error {
	e.calls++
	if e.fail {
		return errSRPEntropy
	}
	e.next++
	for i := range dst {
		dst[i] = e.next + byte(i)
	}
	return nil
}

type srpSettings struct {
	*simulation.SimSettings
	getErr, setErr bool
	commitThenFail bool
	keyWrites      int
}

func newSRPSettings() *srpSettings {
	return &srpSettings{SimSettings: simulation.NewSimSettings()}
}

const srpKeySlot = platform.SettingsKeySRPECDSAKey

func (s *srpSettings) Get(k platform.SettingsKey, index int) ([]byte, error) {
	if k == srpKeySlot && s.getErr {
		return nil, errSRPStorage
	}
	return s.SimSettings.Get(k, index)
}

func (s *srpSettings) Set(k platform.SettingsKey, value []byte) error {
	if k != srpKeySlot {
		return s.SimSettings.Set(k, value)
	}
	s.keyWrites++
	if s.setErr && !s.commitThenFail {
		return errSRPStorage
	}
	if err := s.SimSettings.Set(k, value); err != nil {
		return err
	}
	if s.setErr {
		return errSRPStorage
	}
	return nil
}

func TestSRPKeyRecordRestart(t *testing.T) {
	store := newSRPSettings()
	entropy := &srpEntropy{}
	inst := New(Config{Settings: store, Entropy: entropy})
	key, err := inst.loadSRPKey()
	if err != nil {
		t.Fatal(err)
	}
	if store.keyWrites != 1 {
		t.Fatal("key not persisted once before use")
	}
	entropy.fail = true
	restarted := New(Config{Settings: store, Entropy: entropy})
	calls := entropy.calls // Constructor has independent SLAAC scaffolding.
	restored, err := restarted.loadSRPKey()
	if err != nil || restored.GetPublicKey() != key.GetPublicKey() ||
		store.keyWrites != 1 || calls != entropy.calls {
		t.Fatal("reboot did not load exactly the durable signing identity")
	}
}

func TestSRPAndBorderAgentCanonicalNamespaces(t *testing.T) {
	if platform.SettingsKeySRPECDSAKey != platform.SettingsKey(csettings.KeySrpEcdsaKey) ||
		platform.SettingsKeyBorderAgentID != platform.SettingsKey(csettings.KeyBorderAgentId) ||
		platform.SettingsKeySRPECDSAKey == platform.SettingsKeyBorderAgentID {
		t.Fatal("canonical persistent identities collide")
	}
	store := newSRPSettings()
	border := bytes.Repeat([]byte{0x73}, 16)
	if err := store.Set(platform.SettingsKeyBorderAgentID, border); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Settings: store, Entropy: &srpEntropy{}}).loadSRPKey(); err != nil {
		t.Fatal(err)
	}
	if err := New(Config{Settings: store}).stackSettings.WriteBorderAgentId(border); err != nil {
		t.Fatal(err)
	}
	readBorder, err := store.Get(platform.SettingsKeyBorderAgentID, 0)
	if err != nil || !bytes.Equal(readBorder, border) {
		t.Fatal("SRP write changed canonical BorderAgent identity")
	}
	// A second load must preserve both canonical records without writes.
	if _, err := New(Config{Settings: store, Entropy: &srpEntropy{fail: true}}).loadSRPKey(); err != nil ||
		store.keyWrites != 1 {
		t.Fatal("canonical SRP record not preserved")
	}
}
func TestSRPKeyRecordFailClosed(t *testing.T) {
	for _, mode := range []string{"read", "before-commit", "after-commit", "entropy"} {
		t.Run(mode, func(t *testing.T) {
			store, entropy := newSRPSettings(), &srpEntropy{}
			inst := New(Config{Settings: store, Entropy: entropy})
			switch mode {
			case "read":
				store.getErr = true
			case "before-commit", "after-commit":
				store.setErr = true
				store.commitThenFail = mode == "after-commit"
			case "entropy":
				entropy.fail = true
			}
			expected := errSRPStorage
			if mode == "entropy" {
				expected = errSRPEntropy
			}
			key, err := inst.loadSRPKey()
			if key != nil || !errors.Is(err, expected) {
				t.Fatalf("failure returned usable credential or lost cause: %v", err)
			}
			if mode == "before-commit" || mode == "after-commit" {
				store.setErr = false
				if key, err := inst.loadSRPKey(); key != nil || !errors.Is(err, expected) {
					t.Fatal("ambiguous persistence failure not latched")
				}
				if store.keyWrites != 1 {
					t.Fatal("latched failure silently rewrote credentials")
				}
			}
			if mode == "after-commit" {
				before, _ := store.Get(srpKeySlot, 0)
				reopened := New(Config{Settings: store, Entropy: entropy})
				if _, err := reopened.loadSRPKey(); err != nil {
					t.Fatal("fresh Instance could not validate committed record")
				}
				after, _ := store.Get(srpKeySlot, 0)
				if !bytes.Equal(before, after) || store.keyWrites != 1 {
					t.Fatal("fresh Instance regenerated committed identity")
				}
			}
		})
	}
	for _, cfg := range []Config{{}, {Settings: newSRPSettings()}, {Entropy: &srpEntropy{}}} {
		if _, err := New(cfg).loadSRPKey(); !errors.Is(err, goterrors.ErrInvalidState) {
			t.Fatal("volatile credential fallback accepted")
		}
	}
}

func TestSRPKeyCorruptRecordsNeverRegenerate(t *testing.T) {
	store := newSRPSettings()
	if _, err := New(Config{Settings: store, Entropy: &srpEntropy{}}).loadSRPKey(); err != nil {
		t.Fatal(err)
	}
	valid, _ := store.Get(srpKeySlot, 0)
	for _, mode := range []string{"empty", "truncated", "version", "checksum", "zero-scalar", "overflow-scalar", "border-agent"} {
		t.Run(mode, func(t *testing.T) {
			value := append([]byte(nil), valid...)
			switch mode {
			case "empty":
				value = nil
			case "truncated":
				value = value[:20]
			case "version":
				value[4]++
			case "checksum":
				value[10] ^= 1
			case "zero-scalar", "overflow-scalar":
				for i := 5; i < 37; i++ {
					value[i] = 0
					if mode == "overflow-scalar" {
						value[i] = 0xff
					}
				}
				binary.BigEndian.PutUint32(value[37:], crc32.ChecksumIEEE(value[:37]))
			case "border-agent":
				value = make([]byte, 16)
			}
			if err := store.SimSettings.Set(srpKeySlot, value); err != nil {
				t.Fatal(err)
			}
			inst := New(Config{Settings: store, Entropy: &srpEntropy{}})
			if _, err := inst.loadSRPKey(); !errors.Is(err, goterrors.ErrParse) {
				t.Fatalf("corrupt existing record not rejected: %v", err)
			}
			after, _ := store.Get(srpKeySlot, 0)
			if !bytes.Equal(value, after) || store.keyWrites != 1 {
				t.Fatal("corrupt identity was erased or regenerated")
			}
		})
	}
}
