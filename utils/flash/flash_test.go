// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package flash

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

func TestInit(t *testing.T) {
	t.Run("default size", func(t *testing.T) {
		var f Flash
		if err := f.Init(0); err != nil {
			t.Fatalf("Init(0) = %v, want nil", err)
		}
		if f.swapSize != SwapSize {
			t.Errorf("swapSize = %d, want %d", f.swapSize, SwapSize)
		}
	})
	t.Run("custom size", func(t *testing.T) {
		var f Flash
		if err := f.Init(512); err != nil {
			t.Fatalf("Init(512) = %v, want nil", err)
		}
		if f.swapSize != 512 {
			t.Errorf("swapSize = %d, want 512", f.swapSize)
		}
	})
	t.Run("too small", func(t *testing.T) {
		var f Flash
		if err := f.Init(2); err != errors.ErrInvalidArgs {
			t.Errorf("Init(2) = %v, want ErrInvalidArgs", err)
		}
	})
}

func newFlash(t *testing.T) *Flash {
	t.Helper()
	var f Flash
	if err := f.Init(0); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return &f
}

func TestAddAndGet(t *testing.T) {
	f := newFlash(t)
	data := []byte("hello")
	if err := f.Add(1, data); err != nil {
		t.Fatalf("Add(1) = %v", err)
	}
	got, err := f.Get(1, 0)
	if err != nil {
		t.Fatalf("Get(1, 0) = %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("Get(1, 0) = %q, want %q", got, "hello")
	}
}

func TestAddMultipleRecords(t *testing.T) {
	f := newFlash(t)
	if err := f.Add(1, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := f.Add(1, []byte("second")); err != nil {
		t.Fatal(err)
	}
	got0, err := f.Get(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got0) != "first" {
		t.Errorf("index 0 = %q, want %q", got0, "first")
	}
	got1, err := f.Get(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got1) != "second" {
		t.Errorf("index 1 = %q, want %q", got1, "second")
	}
}

func TestGetNotFound(t *testing.T) {
	f := newFlash(t)
	_, err := f.Get(99, 0)
	if err != errors.ErrNotFound {
		t.Errorf("Get(99, 0) = %v, want ErrNotFound", err)
	}
}

func TestDelete(t *testing.T) {
	f := newFlash(t)
	f.Add(1, []byte("a"))
	f.Add(1, []byte("b"))

	if err := f.Delete(1, 0); err != nil {
		t.Fatal(err)
	}
	// After deleting index 0, the former index 1 becomes index 0.
	got, err := f.Get(1, 0)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if string(got) != "b" {
		t.Errorf("after delete index 0 = %q, want %q", got, "b")
	}
	// Index 1 should not exist.
	_, err = f.Get(1, 1)
	if err != errors.ErrNotFound {
		t.Errorf("Get(1,1) after delete = %v, want ErrNotFound", err)
	}
}

func TestSet(t *testing.T) {
	f := newFlash(t)
	f.Add(5, []byte("old1"))
	f.Add(5, []byte("old2"))

	if err := f.Set(5, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := f.Get(5, 0)
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("after Set = %q, want %q", got, "new")
	}
	// Only one record should exist.
	_, err = f.Get(5, 1)
	if err != errors.ErrNotFound {
		t.Errorf("Get(5,1) after Set = %v, want ErrNotFound", err)
	}
}

func TestWipe(t *testing.T) {
	f := newFlash(t)
	f.Add(1, []byte("data"))
	f.Wipe()
	_, err := f.Get(1, 0)
	if err != errors.ErrNotFound {
		t.Errorf("Get after Wipe = %v, want ErrNotFound", err)
	}
}

func TestCompaction(t *testing.T) {
	// Use a small swap so compaction triggers.
	var f Flash
	if err := f.Init(64); err != nil {
		t.Fatal(err)
	}
	// Fill with small records, delete some, then add more to trigger compaction.
	for i := 0; i < 5; i++ {
		if err := f.Add(uint16(i), []byte{byte(i)}); err != nil {
			t.Fatalf("Add(%d) = %v", i, err)
		}
	}
	// Delete records 0-3, freeing space.
	for i := 0; i < 4; i++ {
		f.Delete(uint16(i), 0)
	}
	// This should trigger compaction and succeed.
	if err := f.Add(10, []byte("after compact")); err != nil {
		t.Fatalf("Add after compaction = %v", err)
	}
	got, err := f.Get(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "after compact" {
		t.Errorf("after compaction = %q, want %q", got, "after compact")
	}
	// Record 4 should still be there.
	got4, err := f.Get(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got4) != 1 || got4[0] != 4 {
		t.Errorf("record 4 = %v, want [4]", got4)
	}
}

func TestDeletedKeyRejected(t *testing.T) {
	f := newFlash(t)
	if err := f.Add(0xFFFF, []byte("x")); err != errors.ErrInvalidArgs {
		t.Errorf("Add(0xFFFF) = %v, want ErrInvalidArgs", err)
	}
}

func TestNoBufs(t *testing.T) {
	var f Flash
	f.Init(recordOverhead + 1) // room for exactly 1 byte of value
	f.Add(1, []byte{0x42})
	// Second record should fail.
	if err := f.Add(2, []byte{0x43}); err != errors.ErrNoBufs {
		t.Errorf("second Add = %v, want ErrNoBufs", err)
	}
}

func TestCRC16(t *testing.T) {
	// Known test vector: CRC-16/CCITT-FALSE of "123456789" = 0x29B1
	got := crc16([]byte("123456789"))
	if got != 0x29B1 {
		t.Errorf("crc16(\"123456789\") = 0x%04X, want 0x29B1", got)
	}
}

func TestEmptyValue(t *testing.T) {
	f := newFlash(t)
	if err := f.Add(1, nil); err != nil {
		t.Fatal(err)
	}
	got, err := f.Get(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty value Get = %v, want empty", got)
	}
}

func TestMultipleKeys(t *testing.T) {
	f := newFlash(t)
	f.Add(1, []byte("key1"))
	f.Add(2, []byte("key2"))
	f.Add(3, []byte("key3"))

	for _, tc := range []struct {
		key  uint16
		want string
	}{
		{1, "key1"},
		{2, "key2"},
		{3, "key3"},
	} {
		got, err := f.Get(tc.key, 0)
		if err != nil {
			t.Fatalf("Get(%d) = %v", tc.key, err)
		}
		if string(got) != tc.want {
			t.Errorf("Get(%d) = %q, want %q", tc.key, got, tc.want)
		}
	}
}
