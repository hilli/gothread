// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
)

// ThreadProfileResources describes implementation bounds, not currently free
// resources, authenticated attachment, BBR acceptance or native readiness.
type ThreadProfileResources struct {
	MaxUnicastPayload             int
	MaxOrdinaryMulticastAddresses int
	MaxSiteMulticastReferences    int
	MaxSiteMulticastAddresses     int
	MaxSiteMulticastPayload       int
}

// Resources is a pure profile query, also used by public admission dispatch.
// Site capacity is additional to the ordinary external multicast pool.
// Group authentication/key capacity belongs to the consumer, not this contract.
func (profile ThreadAttachProfile) Resources() (ThreadProfileResources, error) {
	bounds := ThreadProfileResources{
		MaxUnicastPayload:             mesh.IPv6MTU - ip6.HeaderSize - ip6.UDPHeaderSize,
		MaxOrdinaryMulticastAddresses: ip6.MaxExternalMulticastAddresses,
	}
	switch profile {
	case ThreadAttachAwakeMTD:
		return bounds, nil
	case ThreadAttachAwakeFTDChild:
		bounds.MaxSiteMulticastReferences = len(ownedSiteGroups{}.handles)
		bounds.MaxSiteMulticastAddresses = len(ownedSiteGroups{}.entries)
		bounds.MaxSiteMulticastPayload = MaxSiteMulticastPayload
		return bounds, nil
	default:
		return ThreadProfileResources{}, goterrors.ErrInvalidArgs
	}
}
