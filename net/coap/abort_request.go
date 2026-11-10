// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coap

import goterrors "github.com/hilli/gothread/errors"

// AbortRequest retires the exact captured token/peer transaction, not unrelated
// requests sharing an owner engine. Callbacks run after the engine lock drops.
func (e *Engine) AbortRequest(token []byte, peer MessageInfo) error {
	e.mu.Lock()
	var selected *pendingRequest
	for _, pending := range e.pending {
		if tokensEqual(pending.token, token) && pending.info.HasSamePeerAddrAndPort(peer) && pending.info.LocalAddr == peer.LocalAddr {
			selected = pending
			break
		}
	}
	e.mu.Unlock()
	if selected == nil {
		return goterrors.ErrNotFound
	}
	e.finalizeCoapTransaction(selected, nil, peer, goterrors.ErrAbort)
	return nil
}
