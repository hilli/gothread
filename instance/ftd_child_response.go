// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import "github.com/hilli/gothread/thread/mle"

func (inst *Instance) armOwnedLinkResponse(peer *ownedControlPeer) {
	inst.retireExpectedMLE(peer.expected)
	peer.expected = &ownedMLEResponse{
		command: mle.CommandLinkAccept, epoch: inst.threadEpoch,
		counter: peer.counterFloor, sequence: peer.sequence,
		until:     inst.timers.nowTime().Add(mle.LinkRequestTimeout),
		challenge: append([]byte(nil), peer.router.PendingChallenge[:]...),
		peer:      peer, peerGeneration: peer.generation,
	}
}
