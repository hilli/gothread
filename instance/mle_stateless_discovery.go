// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import "github.com/hilli/gothread/thread/mle"

func ownedStatelessDiscovery(info *mle.RxInfo) bool {
	if info.Command != mle.CommandDiscoveryRequest && info.Command != mle.CommandDiscoveryResponse {
		return false
	}
	if len(info.TLVs) != 1 || info.TLVs[0].Type != mle.TLVDiscovery {
		return false
	}
	return true
}

func unsecuredDiscoveryPayload(payload []byte) bool {
	message, err := mle.ParseMessage(payload)
	return err == nil && message.SecuritySuite == mle.SecuritySuiteNone && len(message.Payload) > 0 &&
		(mle.Command(message.Payload[0]) == mle.CommandDiscoveryRequest || mle.Command(message.Payload[0]) == mle.CommandDiscoveryResponse)
}
