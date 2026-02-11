// Copyright (c) 2026, Jan Hillegeer. All rights reserved.
// Copyright (c) 2016, The OpenThread Authors. All rights reserved.
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

package settings

import (
	"bytes"
	"errors"
	"testing"
)

// helper creates and initialises a Settings backed by InMemoryDriver.
func newTestSettings(t *testing.T) *Settings {
	t.Helper()
	drv := NewInMemoryDriver()
	s := New(drv)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func TestKeyConstants(t *testing.T) {
	tests := []struct {
		name string
		key  uint16
		want uint16
	}{
		{"ActiveDataset", KeyActiveDataset, 0x0001},
		{"PendingDataset", KeyPendingDataset, 0x0002},
		{"NetworkInfo", KeyNetworkInfo, 0x0003},
		{"ParentInfo", KeyParentInfo, 0x0004},
		{"ChildInfo", KeyChildInfo, 0x0005},
		{"SlaacIidSecretKey", KeySlaacIidSecretKey, 0x0007},
		{"DadInfo", KeyDadInfo, 0x0008},
		{"SrpEcdsaKey", KeySrpEcdsaKey, 0x000b},
		{"SrpClientInfo", KeySrpClientInfo, 0x000c},
		{"BrUlaPrefix", KeyBrUlaPrefix, 0x000f},
		{"BrOnLinkPrefixes", KeyBrOnLinkPrefixes, 0x0010},
		{"BorderAgentId", KeyBorderAgentId, 0x0011},
	}
	for _, tt := range tests {
		if tt.key != tt.want {
			t.Errorf("%s = 0x%04x, want 0x%04x", tt.name, tt.key, tt.want)
		}
	}
}

func TestSingleValueCRUD(t *testing.T) {
	tests := []struct {
		name  string
		key   uint16
		read  func(s *Settings) ([]byte, error)
		write func(s *Settings, v []byte) error
		del   func(s *Settings) error
	}{
		{"ActiveDataset", KeyActiveDataset,
			func(s *Settings) ([]byte, error) { return s.ReadActiveDataset() },
			func(s *Settings, v []byte) error { return s.WriteActiveDataset(v) },
			func(s *Settings) error { return s.DeleteActiveDataset() },
		},
		{"PendingDataset", KeyPendingDataset,
			func(s *Settings) ([]byte, error) { return s.ReadPendingDataset() },
			func(s *Settings, v []byte) error { return s.WritePendingDataset(v) },
			func(s *Settings) error { return s.DeletePendingDataset() },
		},
		{"NetworkInfo", KeyNetworkInfo,
			func(s *Settings) ([]byte, error) { return s.ReadNetworkInfo() },
			func(s *Settings, v []byte) error { return s.WriteNetworkInfo(v) },
			func(s *Settings) error { return s.DeleteNetworkInfo() },
		},
		{"ParentInfo", KeyParentInfo,
			func(s *Settings) ([]byte, error) { return s.ReadParentInfo() },
			func(s *Settings, v []byte) error { return s.WriteParentInfo(v) },
			func(s *Settings) error { return s.DeleteParentInfo() },
		},
		{"DadInfo", KeyDadInfo,
			func(s *Settings) ([]byte, error) { return s.ReadDadInfo() },
			func(s *Settings, v []byte) error { return s.WriteDadInfo(v) },
			nil,
		},
		{"SrpEcdsaKey", KeySrpEcdsaKey,
			func(s *Settings) ([]byte, error) { return s.ReadSrpEcdsaKey() },
			func(s *Settings, v []byte) error { return s.WriteSrpEcdsaKey(v) },
			nil,
		},
		{"SrpClientInfo", KeySrpClientInfo,
			func(s *Settings) ([]byte, error) { return s.ReadSrpClientInfo() },
			func(s *Settings, v []byte) error { return s.WriteSrpClientInfo(v) },
			nil,
		},
		{"BrUlaPrefix", KeyBrUlaPrefix,
			func(s *Settings) ([]byte, error) { return s.ReadBrUlaPrefix() },
			func(s *Settings, v []byte) error { return s.WriteBrUlaPrefix(v) },
			nil,
		},
		{"SlaacIidSecretKey", KeySlaacIidSecretKey,
			func(s *Settings) ([]byte, error) { return s.ReadSlaacIidSecretKey() },
			func(s *Settings, v []byte) error { return s.WriteSlaacIidSecretKey(v) },
			nil,
		},
		{"BorderAgentId", KeyBorderAgentId,
			func(s *Settings) ([]byte, error) { return s.ReadBorderAgentId() },
			func(s *Settings, v []byte) error { return s.WriteBorderAgentId(v) },
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSettings(t)
			value := []byte{0xde, 0xad, 0xbe, 0xef}

			// Read before write → not found.
			_, err := tt.read(s)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("initial read: got err=%v, want ErrNotFound", err)
			}

			// Write.
			if err := tt.write(s, value); err != nil {
				t.Fatalf("write: %v", err)
			}

			// Read after write.
			got, err := tt.read(s)
			if err != nil {
				t.Fatalf("read after write: %v", err)
			}
			if !bytes.Equal(got, value) {
				t.Fatalf("read = %x, want %x", got, value)
			}

			// Overwrite with different value.
			value2 := []byte{0xca, 0xfe}
			if err := tt.write(s, value2); err != nil {
				t.Fatalf("overwrite: %v", err)
			}
			got, _ = tt.read(s)
			if !bytes.Equal(got, value2) {
				t.Fatalf("read after overwrite = %x, want %x", got, value2)
			}

			// Delete if supported.
			if tt.del != nil {
				if err := tt.del(s); err != nil {
					t.Fatalf("delete: %v", err)
				}
				_, err = tt.read(s)
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("read after delete: got err=%v, want ErrNotFound", err)
				}
			}
		})
	}
}

func TestChildInfoListCRUD(t *testing.T) {
	s := newTestSettings(t)

	child1 := []byte{0x01, 0x02, 0x03}
	child2 := []byte{0x04, 0x05, 0x06}
	child3 := []byte{0x07, 0x08, 0x09}

	// Add three children.
	for _, c := range [][]byte{child1, child2, child3} {
		if err := s.AddChildInfo(c); err != nil {
			t.Fatalf("AddChildInfo: %v", err)
		}
	}

	// Read each by index.
	for i, want := range [][]byte{child1, child2, child3} {
		got, err := s.ReadChildInfo(i)
		if err != nil {
			t.Fatalf("ReadChildInfo(%d): %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ReadChildInfo(%d) = %x, want %x", i, got, want)
		}
	}

	// Delete middle entry.
	if err := s.DeleteChildInfo(1); err != nil {
		t.Fatalf("DeleteChildInfo(1): %v", err)
	}

	// After deletion: index 0 = child1, index 1 = child3.
	got, err := s.ReadChildInfo(0)
	if err != nil || !bytes.Equal(got, child1) {
		t.Errorf("after delete, index 0 = %x err=%v, want %x", got, err, child1)
	}
	got, err = s.ReadChildInfo(1)
	if err != nil || !bytes.Equal(got, child3) {
		t.Errorf("after delete, index 1 = %x err=%v, want %x", got, err, child3)
	}
	_, err = s.ReadChildInfo(2)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete, index 2: got err=%v, want ErrNotFound", err)
	}

	// Delete all.
	if err := s.DeleteAllChildInfo(); err != nil {
		t.Fatalf("DeleteAllChildInfo: %v", err)
	}
	_, err = s.ReadChildInfo(0)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete all: got err=%v, want ErrNotFound", err)
	}
}

func TestBrOnLinkPrefixListCRUD(t *testing.T) {
	s := newTestSettings(t)

	p1 := []byte{0xaa}
	p2 := []byte{0xbb}

	if err := s.AddBrOnLinkPrefix(p1); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.AddBrOnLinkPrefix(p2); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := s.ReadBrOnLinkPrefix(0)
	if err != nil || !bytes.Equal(got, p1) {
		t.Errorf("ReadBrOnLinkPrefix(0) = %x err=%v, want %x", got, err, p1)
	}
	got, err = s.ReadBrOnLinkPrefix(1)
	if err != nil || !bytes.Equal(got, p2) {
		t.Errorf("ReadBrOnLinkPrefix(1) = %x err=%v, want %x", got, err, p2)
	}

	if err := s.DeleteBrOnLinkPrefix(0); err != nil {
		t.Fatalf("DeleteBrOnLinkPrefix: %v", err)
	}
	got, _ = s.ReadBrOnLinkPrefix(0)
	if !bytes.Equal(got, p2) {
		t.Errorf("after delete, index 0 = %x, want %x", got, p2)
	}

	if err := s.DeleteAllBrOnLinkPrefixes(); err != nil {
		t.Fatalf("DeleteAllBrOnLinkPrefixes: %v", err)
	}
	_, err = s.ReadBrOnLinkPrefix(0)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after wipe: got err=%v, want ErrNotFound", err)
	}
}

func TestWipe(t *testing.T) {
	s := newTestSettings(t)

	_ = s.WriteNetworkInfo([]byte{0x01})
	_ = s.WriteActiveDataset([]byte{0x02})
	_ = s.AddChildInfo([]byte{0x03})

	if err := s.Wipe(); err != nil {
		t.Fatalf("Wipe: %v", err)
	}

	for _, key := range []uint16{KeyNetworkInfo, KeyActiveDataset, KeyChildInfo} {
		_, err := s.Read(key)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("key 0x%04x after Wipe: got err=%v, want ErrNotFound", key, err)
		}
	}
}

func TestGenericReadWrite(t *testing.T) {
	s := newTestSettings(t)
	value := []byte{0x11, 0x22, 0x33}

	if err := s.Write(0xFFFF, value); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := s.Read(0xFFFF)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("Read = %x, want %x", got, value)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	s := newTestSettings(t)
	err := s.Delete(0x9999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete non-existent: got err=%v, want ErrNotFound", err)
	}
}

func TestInMemoryDriverValueIsolation(t *testing.T) {
	// Verify that the driver copies values rather than referencing the
	// caller's slice.
	s := newTestSettings(t)
	buf := []byte{0x01, 0x02}
	_ = s.Write(KeyNetworkInfo, buf)

	// Mutate original.
	buf[0] = 0xFF
	got, _ := s.ReadNetworkInfo()
	if got[0] == 0xFF {
		t.Error("driver did not copy value on write")
	}

	// Mutate returned slice.
	got[0] = 0xAA
	got2, _ := s.ReadNetworkInfo()
	if got2[0] == 0xAA {
		t.Error("driver did not copy value on read")
	}
}

func TestDeinit(t *testing.T) {
	drv := NewInMemoryDriver()
	s := New(drv)
	_ = s.Init()
	_ = s.Write(KeyNetworkInfo, []byte{1})
	s.Deinit()
	// After deinit the internal map is nil; re-init should give clean state.
	_ = s.Init()
	_, err := s.ReadNetworkInfo()
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after deinit+init: got err=%v, want ErrNotFound", err)
	}
}
