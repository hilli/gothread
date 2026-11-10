// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/tmf"
)

// Only the approved realm-local own-address query is decapsulated here.
// It is not generic HBH/UDP or a multicast-forwarding path.
func (client *ownedMlrClient) receiveOwnRealmQuery(packet []byte, addresses lowpan.AddressContext,
	linkInfo *mesh.ReceivedFrameInfo, nativeLink nativeMLELink) {
	drop := func() { client.inst.forwarder.RecordReceiveError(false) }
	if client.stopped || len(packet) < 56 || packet[6] != 0 || packet[7] == 0 ||
		packet[40] != ip6.ProtoUDP || packet[41] != 0 || packet[42] != ip6.MPLOptionType {
		drop()
		return
	}
	var peer, destination ip6.Address
	copy(peer[:], packet[8:24])
	copy(destination[:], packet[24:40])
	if destination != ip6.MulticastRealmLocalAllRouters || !peer.IsRoutingLocator() {
		drop()
		return
	}
	seed := peer.GetIid().GetLocator()
	switch packet[43] {
	case 2:
		if packet[44]&0xdf != 0 || packet[46] != 1 || packet[47] != 0 {
			drop()
			return
		}
	case 4:
		if packet[44]&0xdf != byte(ip6.MPLSeedIDLength2) || binary.BigEndian.Uint16(packet[46:48]) != seed {
			drop()
			return
		}
	default:
		drop()
		return
	}
	udpPacket := make([]byte, len(packet)-8)
	copy(udpPacket[:40], packet[:40])
	udpPacket[6] = ip6.ProtoUDP
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)-40))
	copy(udpPacket[40:], packet[48:])
	if !validNativeUDP(udpPacket) {
		drop()
		return
	}
	info := ip6.MessageInfo{PeerAddr: peer, SockAddr: destination,
		PeerPort: binary.BigEndian.Uint16(udpPacket[40:42]), SockPort: binary.BigEndian.Uint16(udpPacket[42:44]), HopLimit: packet[7]}
	nativeLink.realmQueryMPL = true
	input := ownedQueryInput{messageInfo: info, link: nativeLink, epoch: client.inst.threadEpoch}
	if !client.validOwnLink(&input, false) || info.PeerPort != tmf.Port || info.SockPort != tmf.Port {
		drop()
		return
	}
	message, err := coap.ParseMessage(udpPacket[48:])
	if err != nil {
		drop()
		return
	}
	target, err := ownAddressTarget(message)
	if err != nil {
		drop()
		return
	}
	if _, err := client.inst.currentOwnedAddressProof(target, peer); err != nil {
		drop()
		return
	}
	// Malformed/nonown queries cannot consume the shared MPL seed record.
	if err := client.mpl.UpdateSeedSet(seed, packet[45]); err != nil {
		return
	}
	addresses.SrcShortValid = false
	client.inst.dispatchIPv6Packet(udpPacket, addresses, linkInfo, nativeLink)
}
