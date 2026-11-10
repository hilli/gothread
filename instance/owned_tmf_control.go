// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"time"

	"github.com/hilli/gothread/backbone"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/bbr"
	"github.com/hilli/gothread/thread/tmf"
)

type ownedMlrLeader struct {
	*backbone.Leader
}

func (leader ownedMlrLeader) GetDomainPrefix() (ip6.Prefix, bool) {
	return leader.Leader.GetDomainPrefix(), leader.HasDomainPrefix()
}

// One owner-loop engine serves the existing MLR client and the precise own-EID
// query resource. No second query engine or generic resolver service is made.
func newOwnedTMFControl(inst *Instance) (*ownedMlrClient, error) {
	if inst.ownedAttachment == nil || inst.ownedAttachment.profile != ThreadAttachAwakeFTDChild {
		return nil, goterrors.ErrNotCapable
	}
	if err := inst.validateOwnedProfile(); err != nil {
		return nil, err
	}
	link := inst.netif.IsMulticastSubscribed(ip6.MulticastLinkLocalAllRouters)
	realm := inst.netif.IsMulticastSubscribed(ip6.MulticastRealmLocalAllRouters)
	if link != realm {
		return nil, goterrors.ErrInvalidState
	}
	client := &ownedMlrClient{inst: inst, leader: backbone.NewLeader(nil), mpl: ip6.NewMpl(), mlrPaused: true}
	client.manager = bbr.NewMlrManager(bbr.WithMaxEntries(maxOwnedSiteGroups), bbr.WithMlrLeaderProvider(ownedMlrLeader{client.leader}))
	var err error
	client.engine, err = coap.NewEngineWithScheduler(client.send, nativeEntropyReader{inst}, inst.timers.nowTime, inst.timers.scheduleWithCancel)
	if err != nil {
		return nil, err
	}
	client.engine.AddResource(&coap.Resource{URIPath: tmf.UriPathAddressQuery, Handler: client.handleOwnAddressQuery})
	if !realm {
		inst.netif.SubscribeAllRoutersMulticast()
		client.ownsRouterSubscription = true
	}
	client.scheduleControlTick()
	return client, nil
}

func (client *ownedMlrClient) scheduleControlTick() {
	client.cancelControlTick = client.inst.timers.scheduleWithCancel(time.Second, func() {
		if client.stopped {
			return
		}
		client.mpl.HandleTimeTick()
		now := client.inst.timers.nowTime()
		for i, query := range &client.ownQueries {
			if query.valid && !now.Before(query.until) {
				client.ownQueries[i] = ownedQueryIdentity{}
			}
		}
		client.scheduleControlTick()
	})
}
