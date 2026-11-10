// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import "github.com/hilli/gothread/net/ip6"

func (inst *Instance) hasOwnedRLOCAddress() bool {
	attachment := inst.ownedAttachment
	if attachment == nil {
		return false
	}
	for _, assigned := range inst.netif.GetUnicastAddresses() {
		if assigned.Valid && assigned.RLOC && assigned.Address.GetPrefix() == ip6.NetworkPrefix(attachment.prefix) &&
			assigned.Address.IsRoutingLocator() && assigned.Address.GetIid().GetLocator() == attachment.rloc {
			return true
		}
	}
	return false
}
