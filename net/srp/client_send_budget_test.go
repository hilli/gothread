// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srp

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

func TestSRPSuccessfulSendResetsOnlyLocalSendFailureBudget(t *testing.T) {
	env, _, outcomes := responseRegressionEnv(t)
	for cycle := 0; cycle < 2; cycle++ {
		env.sender.sendErr = errors.ErrNoRoute
		for i := uint8(0); i < MaxTxFailureRetries-1; i++ {
			fireOwnedResponseTimer(t, env)
		}
		if len(*outcomes) != cycle {
			t.Fatal("consecutive local sends reached a premature terminal outcome")
		}
		env.sender.sendErr = nil
		fireOwnedResponseTimer(t, env)
		if env.sender.packetCount() != cycle+1 || env.client.txFailureRetryCount != 0 {
			t.Fatal("successful local send did not preserve the baseline failure-budget reset")
		}
		fireOwnedResponseTimer(t, env)
		if len(*outcomes) != cycle+1 || (*outcomes)[cycle].err != errors.ErrResponseTimeout ||
			env.client.GetState() != StateToRetry {
			t.Fatal("response failure was counted as a terminal local-send failure")
		}
	}
}
