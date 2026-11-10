// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srp

import (
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

func activeResponseTimer(t *testing.T, env *testEnv) *fakeTimer {
	t.Helper()
	env.client.mu.Lock()
	timer := env.client.timer
	env.client.mu.Unlock()
	if timer == nil {
		t.Fatal("expected an active owned timer")
	}
	result, ok := timer.(*fakeTimer)
	if !ok {
		t.Fatalf("unexpected timer implementation %T", timer)
	}
	return result
}

func fireOwnedResponseTimer(t *testing.T, env *testEnv) *fakeTimer {
	t.Helper()
	timer := activeResponseTimer(t, env)
	env.now = env.now.Add(timer.delay)
	timer.Fire()
	return timer
}

func TestSRPResponseTimeoutsRemainRetryableWithCappedBackoff(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	fireOwnedResponseTimer(t, env)
	var previousID uint16
	var previousDeadline time.Duration
	var completed []*fakeTimer
	const attempts = 20 // Beyond the local-send-failure bound and into the interval cap.
	for attempt := 0; attempt < attempts; attempt++ {
		id := currentSRPMessageID(t, env)
		if id == previousID {
			t.Fatalf("retry immediately reused the previous message ID %d", id)
		}
		previousID = id
		deadline := activeResponseTimer(t, env)
		if deadline.delay < time.Duration(MinRetryWaitInterval)*time.Millisecond ||
			deadline.delay > time.Duration(MaxRetryWaitInterval+RetryIntervalJitter)*time.Millisecond ||
			deadline.delay < previousDeadline {
			t.Fatalf("deadline/backoff not bounded/monotonic: %v -> %v", previousDeadline, deadline.delay)
		}
		previousDeadline = deadline.delay
		completed = append(completed, fireOwnedResponseTimer(t, env))
		if len(*outcomes) != attempt+1 || (*outcomes)[attempt].err != errors.ErrResponseTimeout ||
			(*outcomes)[attempt].removed != 0 || service.State != ItemStateToAdd {
			t.Fatalf("timeout attempt published false/duplicate outcome: %+v item=%v", *outcomes, service.State)
		}
		if env.client.GetState() != StateToRetry {
			t.Fatalf("timeout introduced a response-count hard stop: %v", env.client.GetState())
		}
		if attempt+1 < attempts {
			fireOwnedResponseTimer(t, env)
		}
	}
	if env.sender.packetCount() != attempts || env.client.GetState() != StateToRetry ||
		env.client.retryWaitInterval != MaxRetryWaitInterval {
		t.Fatalf("retry/backoff semantics changed: sends=%d state=%v wait=%d",
			env.sender.packetCount(), env.client.GetState(), env.client.retryWaitInterval)
	}
	retry := activeResponseTimer(t, env)
	for _, stale := range completed {
		stale.Fire()
	}
	if env.sender.packetCount() != attempts || len(*outcomes) != attempts || activeResponseTimer(t, env) != retry {
		t.Fatal("stale deadline disturbed the current capped retry")
	}
	env.client.Stop()
	retry.Fire()
	if env.sender.packetCount() != attempts || len(*outcomes) != attempts {
		t.Fatal("stopped retry continued after explicit lifecycle cancellation")
	}
}

func TestSRPRejectedAttemptsRetryWithoutNilOrPruning(t *testing.T) {
	for _, rc := range []dns.ResponseCode{
		dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNameExists, dns.RcodeNotImplemented,
		dns.RcodeFormatError, dns.RcodeNotAuth,
	} {
		t.Run(fmt.Sprint(rc), func(t *testing.T) {
			env, service, outcomes := responseRegressionEnv(t)
			fireOwnedResponseTimer(t, env)
			attempts := int(MaxTxFailureRetries) + 2
			for attempt := 0; attempt < attempts; attempt++ {
				id := currentSRPMessageID(t, env)
				env.client.HandleResponse(buildSimpleResponse(id, rc))
				env.client.HandleResponse(buildSimpleResponse(id, rc)) // Duplicate cannot add an outcome.
				if len(*outcomes) != attempt+1 || (*outcomes)[attempt].err != dns.ResponseCodeToError(rc) ||
					(*outcomes)[attempt].removed != 0 || service.State != ItemStateToAdd {
					t.Fatalf("rejection applied success or wrong error: %+v state=%v", *outcomes, service.State)
				}
				if attempt+1 < attempts {
					fireOwnedResponseTimer(t, env)
				}
			}
			if env.client.GetState() != StateToRetry || env.sender.packetCount() != attempts {
				t.Fatal("rejected update gained a new permanent response-count hard stop")
			}
			activeResponseTimer(t, env)
		})
	}
}

func TestSRPWrongOrInappropriateResponseKeepsDeadline(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	fireOwnedResponseTimer(t, env)
	id := currentSRPMessageID(t, env)
	deadline := activeResponseTimer(t, env)
	query := buildSimpleResponse(id, dns.RcodeSuccess)
	query[2] &^= 0x80
	wrongOpcode := buildSimpleResponse(id, dns.RcodeSuccess)
	wrongOpcode[2] &^= 0x78
	truncated := buildSimpleResponse(id, dns.RcodeSuccess)
	truncated[2] |= 0x02
	malformedLease := buildResponse(id, dns.RcodeSuccess, 1, 2)
	malformedLease = malformedLease[:len(malformedLease)-1]
	for _, response := range [][]byte{
		{0, 1, 2}, buildSimpleResponse(id+1, dns.RcodeSuccess),
		query, wrongOpcode, truncated, malformedLease,
	} {
		env.client.HandleResponse(response)
		if len(*outcomes) != 0 || service.State != ItemStateAdding ||
			env.client.GetState() != StateUpdating || activeResponseTimer(t, env) != deadline {
			t.Fatalf("wrong/stale/malformed response completed or cancelled current attempt: %x %+v", response, *outcomes)
		}
	}
	fireOwnedResponseTimer(t, env)
	if len(*outcomes) != 1 || (*outcomes)[0].err != errors.ErrResponseTimeout {
		t.Fatal("ignored response suppressed the actual deadline")
	}
}

func TestSRPSuccessRefreshAndWithdrawalCancelOldTimers(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	fireOwnedResponseTimer(t, env)
	oldID := currentSRPMessageID(t, env)
	oldDeadline := activeResponseTimer(t, env)
	env.client.HandleResponse(buildResponse(oldID, dns.RcodeSuccess, 3600, 86400))
	renewal := activeResponseTimer(t, env)
	if service.State != ItemStateRegistered || len(*outcomes) != 1 || (*outcomes)[0].err != nil {
		t.Fatalf("positive registration changed: %+v %v", *outcomes, service.State)
	}
	oldDeadline.Fire()
	env.client.HandleResponse(buildResponse(oldID, dns.RcodeSuccess, 1, 2))
	if len(*outcomes) != 1 || activeResponseTimer(t, env) != renewal {
		t.Fatal("duplicate response/stale deadline changed a completed registration")
	}
	fireOwnedResponseTimer(t, env) // renewal -> pending refresh update timer.
	fireOwnedResponseTimer(t, env) // actual refresh send.
	newID := currentSRPMessageID(t, env)
	if oldID == newID || service.State != ItemStateRefreshing {
		t.Fatal("renewal did not own a distinct refresh attempt")
	}
	env.client.HandleResponse(buildSimpleResponse(oldID, dns.RcodeRefused))
	if len(*outcomes) != 1 {
		t.Fatal("old registration response completed refresh")
	}
	env.client.HandleResponse(buildResponse(newID, dns.RcodeSuccess, 7200, 604800))
	if len(*outcomes) != 2 || (*outcomes)[1].err != nil || service.State != ItemStateRegistered {
		t.Fatal("positive refresh failed")
	}
	if err := env.client.RemoveHostAndServices(true, true); err != nil {
		t.Fatal(err)
	}
	fireOwnedResponseTimer(t, env)
	removeDeadline := activeResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeSuccess))
	if len(*outcomes) != 3 || (*outcomes)[2].err != nil || (*outcomes)[2].removed != 1 ||
		service.State != ItemStateRemoved || len(env.client.GetServices()) != 0 ||
		env.client.GetHostInfo().State != ItemStateRemoved {
		t.Fatalf("positive withdrawal changed: %+v service=%v", *outcomes, service.State)
	}
	removeDeadline.Fire()
	env.client.mu.Lock()
	timer := env.client.timer
	env.client.mu.Unlock()
	if timer != nil || len(*outcomes) != 3 {
		t.Fatal("withdrawal left a lease/deadline timer that could refresh removed services")
	}
}

func TestSRPImmediateSendErrorIsNotResponseTimeout(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	sendErr := errors.ErrNoRoute
	env.sender.sendErr = sendErr
	for attempt := 0; attempt < int(MaxTxFailureRetries); attempt++ {
		fireOwnedResponseTimer(t, env)
		if service.State == ItemStateRegistered || service.State == ItemStateRemoved {
			t.Fatal("immediate send failure published success")
		}
	}
	if env.sender.packetCount() != 0 || len(*outcomes) != 1 || (*outcomes)[0].err != errors.ErrFailed {
		t.Fatalf("send failure changed its baseline terminal ErrFailed or pretended a response timeout: %+v sends=%d", *outcomes, env.sender.packetCount())
	}
}

func TestSRPNilCallbackStillRetiresOnlySuccessfulRemoval(t *testing.T) {
	env, service, _ := responseRegressionEnv(t)
	env.client.SetCallback(nil)
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeRefused))
	if service.State != ItemStateToAdd || len(env.client.GetServices()) != 1 {
		t.Fatal("nil callback turned rejection into registration/removal")
	}
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildResponse(currentSRPMessageID(t, env), dns.RcodeSuccess, 7200, 604800))
	if err := env.client.RemoveService(service); err != nil {
		t.Fatal(err)
	}
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeRefused))
	if service.State != ItemStateToRemove || len(env.client.GetServices()) != 1 {
		t.Fatal("rejected nil-callback withdrawal pruned ownership")
	}
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeSuccess))
	if len(env.client.GetServices()) != 0 || service.State != ItemStateRemoved {
		t.Fatal("successful removal leaked ownership just because callback was nil")
	}
}

func TestSRPTimeoutWithdrawalsNeverPublishRemovalSuccess(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildResponse(currentSRPMessageID(t, env), dns.RcodeSuccess, 7200, 604800))
	*outcomes = nil
	if err := env.client.RemoveService(service); err != nil {
		t.Fatal(err)
	}
	fireOwnedResponseTimer(t, env)
	fireOwnedResponseTimer(t, env)
	if len(*outcomes) != 1 || (*outcomes)[0].err != errors.ErrResponseTimeout ||
		(*outcomes)[0].removed != 0 || service.State != ItemStateToRemove ||
		len(env.client.GetServices()) != 1 {
		t.Fatal("timeout withdrawal falsely removed/published success")
	}
}

func TestSRPCallbackCanStopWithoutOldRetryResurrection(t *testing.T) {
	env, service, _ := responseRegressionEnv(t)
	calls := 0
	env.client.SetCallback(func(err error, _ *HostInfo, _, removed []*Service) {
		calls++
		if err != errors.ErrSecurity || len(removed) != 0 {
			t.Errorf("callback received false success/removal: %v", err)
		}
		env.client.Stop()
	})
	fireOwnedResponseTimer(t, env)
	deadline := activeResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeRefused))
	if calls != 1 || env.client.GetState() != StateStopped || service.State == ItemStateRegistered {
		t.Fatal("callback Stop did not preserve the rejection outcome")
	}
	deadline.Fire()
	env.timer.Fire()
	if calls != 1 || env.sender.packetCount() != 1 || env.client.GetState() != StateStopped {
		t.Fatal("old timer resurrected work after callback Stop")
	}
}

func TestSRPSupersededLifecycleTimersCannotAffectNewAttempt(t *testing.T) {
	for _, action := range []string{"stop-restart", "pause-resume", "clear-host-reconfigure", "clear-service", "change-server"} {
		t.Run(action, func(t *testing.T) {
			env, service, outcomes := responseRegressionEnv(t)
			fireOwnedResponseTimer(t, env)
			oldID := currentSRPMessageID(t, env)
			oldDeadline := activeResponseTimer(t, env)
			switch action {
			case "stop-restart":
				server := env.client.GetServerAddress()
				env.client.Stop()
				if err := env.client.Start(server); err != nil {
					t.Fatal(err)
				}
			case "pause-resume":
				env.client.Pause()
				env.client.Resume()
			case "clear-host-reconfigure":
				env.client.ClearHostAndServices()
				if err := env.client.SetHostName("new-host"); err != nil {
					t.Fatal(err)
				}
				if err := env.client.SetHostAddresses([]ip6.Address{{0xfd, 15: 2}}); err != nil {
					t.Fatal(err)
				}
				service = &Service{Name: "_new._udp", InstanceName: "new", Port: 5540}
				if err := env.client.AddService(service); err != nil {
					t.Fatal(err)
				}
			case "clear-service":
				if err := env.client.ClearService(service); err != nil {
					t.Fatal(err)
				}
				service = &Service{Name: "_new._udp", InstanceName: "new", Port: 5540}
				if err := env.client.AddService(service); err != nil {
					t.Fatal(err)
				}
			case "change-server":
				server := env.client.GetServerAddress()
				server.Address[15]++
				env.client.SetServerAddress(server)
			}
			fireOwnedResponseTimer(t, env)
			newID := currentSRPMessageID(t, env)
			current := activeResponseTimer(t, env)
			if newID == oldID {
				t.Fatal("superseded operation reused an old response identity")
			}
			oldDeadline.Fire()
			env.client.HandleResponse(buildSimpleResponse(oldID, dns.RcodeSuccess))
			if env.client.GetState() != StateUpdating || activeResponseTimer(t, env) != current || len(*outcomes) != 0 {
				t.Fatalf("stale timer/response affected a later %s operation", action)
			}
			env.client.HandleResponse(buildResponse(newID, dns.RcodeSuccess, 7200, 604800))
			if service.State != ItemStateRegistered {
				t.Fatal("current operation did not complete")
			}
		})
	}
}
