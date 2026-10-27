// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	csettings "github.com/hilli/gothread/common/settings"
	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/dhcp6"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/slaac"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
)

type identityRadio struct {
	*simulation.SimRadio
	factoryEUI64 [8]byte
	filterAddr   types.ExtAddress
	filterWrites int
}

func (r *identityRadio) GetIEEEEui64() [8]byte { return r.factoryEUI64 }

func (r *identityRadio) SetExtendedAddress(addr types.ExtAddress) {
	r.filterAddr = addr
	r.filterWrites++
	r.SimRadio.SetExtendedAddress(addr)
}

func TestConstructorFactoryIdentity(t *testing.T) {
	// Deliberately asymmetric bytes catch accidental reversal and U/L-bit changes.
	eui64 := [8]byte{0xa4, 0x17, 0x2b, 0xc3, 0x5d, 0xe6, 0x79, 0x80}
	var secret [32]byte
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	settings := simulation.NewSimSettings()
	secretKey := platform.SettingsKey(csettings.KeySlaacIidSecretKey)
	if err := settings.Set(secretKey, secret[:]); err != nil {
		t.Fatal(err)
	}
	// A fresh constructor reuses the same factory identity and stored privacy
	// secret, without a late Mac.SetExtAddress call from the application.
	for boot := 0; boot < 2; boot++ {
		r := &identityRadio{SimRadio: simulation.NewSimRadio(), factoryEUI64: eui64}
		inst := instance.New(instance.Config{Radio: r, Settings: settings})
		if err := inst.PersistenceError(); err != nil {
			t.Fatal(err)
		}
		if inst.GetExtAddress() != types.ExtAddress(eui64) || inst.SubMac().GetExtAddress() != types.ExtAddress(eui64) {
			t.Errorf("boot %d: MAC/SubMac identity does not match factory EUI-64", boot)
		}
		if r.filterWrites != 1 || r.filterAddr != types.ExtAddress(eui64) {
			t.Errorf("boot %d: radio filter writes=%d, address=%x; want one write of %x",
				boot, r.filterWrites, r.filterAddr, eui64)
		}
		assertConstructorIdentityConsumers(t, inst, eui64, secret)
		storedSecret, err := settings.Get(secretKey, 0)
		if err != nil || !bytes.Equal(storedSecret, secret[:]) {
			t.Fatalf("boot %d: constructor replaced stored SLAAC privacy secret: %v", boot, err)
		}
	}
}

func TestConstructorNilRadioIdentity(t *testing.T) {
	inst := instance.New(instance.Config{})
	if inst.GetExtAddress() != (types.ExtAddress{}) || inst.SubMac().GetExtAddress() != (types.ExtAddress{}) {
		t.Fatal("nil radio changed the existing zero MAC/SubMac identity")
	}
	assertConstructorIdentityConsumers(t, inst, [8]byte{}, [32]byte{})
}

func assertConstructorIdentityConsumers(t *testing.T, inst *instance.Instance, eui64 [8]byte, secret [32]byte) {
	t.Helper()
	wantLinkLocal := ip6.Address{0xfe, 0x80}
	copy(wantLinkLocal[8:], eui64[:])
	wantLinkLocal[8] ^= 0x02
	if got := inst.GetLinkLocalAddress(); got != wantLinkLocal {
		t.Errorf("link-local address = %x, want modified EUI-64 %x", got, wantLinkLocal)
	}
	if err := inst.IfConfigUp(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := inst.IfConfigDown(); err != nil {
			t.Error(err)
		}
	}()

	t.Run("slaac", func(t *testing.T) {
		prefix := slaac.Prefix{
			Prefix: [16]byte{0xfd, 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed},
			Length: 64, Flags: slaac.FlagOnMesh | slaac.FlagSlaac,
		}
		inst.SlaacManager().Update([]slaac.Prefix{prefix})
		addresses := inst.SlaacManager().GetAddresses()
		if len(addresses) != 1 {
			t.Fatalf("generated %d SLAAC addresses, want 1", len(addresses))
		}
		input := append([]byte(nil), prefix.Prefix[:]...)
		input = append(input, prefix.Length)
		input = append(input, eui64[:]...)
		input = append(input, 0) // Initial DAD counter.
		input = append(input, secret[:]...)
		hash := sha256.Sum256(input)
		var want ip6.Address
		copy(want[:8], prefix.Prefix[:8])
		copy(want[8:], hash[:8])
		want[8] &^= 0x02
		if addresses[0].Address != want {
			t.Errorf("SLAAC address = %x, want constructor identity-derived %x", addresses[0].Address, want)
		}
	})

	t.Run("dhcp-client-and-server", func(t *testing.T) {
		prefix := ip6.NetworkPrefix{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
		client := inst.Dhcp6Client()
		client.UpdateAddresses([]dhcp6.PrefixInfo{{Prefix: prefix, PrefixLength: 64}})
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		defer client.Stop()
		solicit := inst.Forwarder().HandleFrameRequest()
		if solicit == nil {
			t.Fatal("DHCP client did not send a Solicit")
		}
		assertDUIDIdentity(t, solicit.Data, dhcp6.OptionCodeClientID, eui64)

		server := inst.Dhcp6Server()
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()
		if err := server.AddPrefix(prefix, 64); err != nil {
			t.Fatal(err)
		}
		if err := server.HandleReceive(solicit.Data, &ip6.MessageInfo{
			PeerAddr: wantLinkLocal, PeerPort: dhcp6.ClientPort,
		}); err != nil {
			t.Fatal(err)
		}
		reply := inst.Forwarder().HandleFrameRequest()
		if reply == nil {
			t.Fatal("DHCP server did not send a Reply")
		}
		assertDUIDIdentity(t, reply.Data, dhcp6.OptionCodeServerID, eui64)
	})

	t.Run("routing-prefixes", func(t *testing.T) {
		manager := inst.RoutingManager()
		if err := manager.SetEnabled(true); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := manager.SetEnabled(false); err != nil {
				t.Error(err)
			}
		}()
		manager.HandleInfraIfStateChanged(true)
		hash := sha256.Sum256(eui64[:])
		wantOMR, wantOnLink := [16]byte{0xfd}, [16]byte{0xfd}
		copy(wantOMR[1:6], hash[:5])
		copy(wantOnLink[1:6], hash[5:10])
		omr, ok := manager.GetOmrPrefix()
		if !ok || omr.Prefix != wantOMR || omr.PrefixLen != 64 {
			t.Errorf("OMR prefix = %+v (found=%v), want identity-derived %x/64", omr, ok, wantOMR)
		}
		onLink, length, ok := manager.GetOnLinkPrefix()
		if !ok || onLink != wantOnLink || length != 48 {
			t.Errorf("on-link prefix = %x/%d (found=%v), want identity-derived %x/48", onLink, length, ok, wantOnLink)
		}
	})
}

func assertDUIDIdentity(t *testing.T, payload []byte, code dhcp6.OptionCode, eui64 [8]byte) {
	t.Helper()
	if len(payload) < dhcp6.HeaderSize {
		t.Fatal("DHCP payload is too short")
	}
	options, err := dhcp6.ParseOptions(payload[dhcp6.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	option := dhcp6.FindOption(options, code)
	if option == nil {
		t.Fatalf("DHCP option %d not emitted", code)
	}
	want := append([]byte{0, 3, 0, 27}, eui64[:]...)
	if !bytes.Equal(option.Data, want) {
		t.Errorf("DHCP DUID = %x, want canonical EUI-64 %x", option.Data, want)
	}
}
