// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import "github.com/hilli/gothread/thread/bbr"

func (client *ownedMlrClient) preparationFailed(cause error) error {
	client.lastErr = cause
	client.manager.HandleMlrResponse(bbr.MlrStatusGeneralFailure, nil)
	return cause
}
