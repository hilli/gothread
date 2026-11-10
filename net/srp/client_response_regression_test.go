// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

type srpOutcome struct {
	err                     error
	hostState, serviceState ItemState
	services, removed       int
}

func responseRegressionEnv(t *testing.T) (*testEnv, *Service, *[]srpOutcome) {
	t.Helper()
	env := newTestEnv(t)
	env.start()
	if err := env.client.SetHostName("response-host"); err != nil {
		t.Fatal(err)
	}
	if err := env.client.SetHostAddresses([]ip6.Address{{0xfd, 7: 1, 15: 1}}); err != nil {
		t.Fatal(err)
	}
	service := &Service{Name: "_test._udp", InstanceName: "response-service", Port: 5540}
	if err := env.client.AddService(service); err != nil {
		t.Fatal(err)
	}
	var outcomes []srpOutcome
	env.client.SetCallback(func(err error, host *HostInfo, services, removed []*Service) {
		outcomes = append(outcomes, srpOutcome{
			err: err, hostState: host.State, serviceState: service.State,
			services: len(services), removed: len(removed),
		})
	})
	t.Cleanup(env.client.Stop)
	return env, service, &outcomes
}

func currentSRPMessageID(t *testing.T, env *testEnv) uint16 {
	t.Helper()
	packet := env.sender.lastPacket().data
	var header dns.Header
	if err := header.UnmarshalBinary(packet); err != nil {
		t.Fatal(err)
	}
	if header.GetType() != dns.TypeQuery || header.GetOpCode() != dns.OpcodeUpdate ||
		header.QDCount != 1 || header.NSCount == 0 || header.ARCount != 2 {
		t.Fatalf("sender did not receive a real serialized signed DNS update: %+v", header)
	}
	return binary.BigEndian.Uint16(packet[:2])
}

func TestSRPRejectedRegistrationHasOnlyFailureOutcome(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	env.fireTimer()
	messageID := currentSRPMessageID(t, env)
	// Even a rejected response containing a lease must not grant that lease.
	env.client.HandleResponse(buildResponse(messageID, dns.RcodeRefused, 1, 2))
	if len(*outcomes) != 1 || (*outcomes)[0].err != dns.ResponseCodeToError(dns.RcodeRefused) {
		t.Fatalf("rejected registration outcomes=%+v, want one exact RCODE error and no nil success", *outcomes)
	}
	if service.State != ItemStateToAdd || env.client.GetHostInfo().State != ItemStateToAdd ||
		env.client.GetState() != StateToRetry {
		t.Fatalf("rejected registration falsely applied success or lost pending work: host=%v service=%v client=%v",
			env.client.GetHostInfo().State, service.State, env.client.GetState())
	}
	env.client.mu.Lock()
	lease, keyLease, renew := env.client.lease, env.client.keyLease, env.client.leaseRenewTime
	env.client.mu.Unlock()
	if lease != 0 || keyLease != 0 || !renew.IsZero() {
		t.Fatal("negative response changed lease/renewal state")
	}
}

func TestSRPRejectedWithdrawalCannotRemoveOrPublishSuccess(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	env.fireTimer()
	env.client.HandleResponse(buildResponse(currentSRPMessageID(t, env), dns.RcodeSuccess, 7200, 604800))
	if service.State != ItemStateRegistered {
		t.Fatal("positive setup registration was not accepted")
	}
	*outcomes = nil
	if err := env.client.RemoveHostAndServices(true, true); err != nil {
		t.Fatal(err)
	}
	env.fireTimer()
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeRefused))
	if len(*outcomes) != 1 || (*outcomes)[0].err != errors.ErrSecurity || (*outcomes)[0].removed != 0 {
		t.Fatalf("rejected withdrawal outcomes=%+v, want one failure and no removal success", *outcomes)
	}
	if service.State != ItemStateToRemove || env.client.GetHostInfo().State != ItemStateToRemove ||
		len(env.client.GetServices()) != 1 || env.client.GetServices()[0] != service {
		t.Fatalf("rejected withdrawal removed/pruned accepted ownership: host=%v service=%v services=%d",
			env.client.GetHostInfo().State, service.State, len(env.client.GetServices()))
	}
}

func TestSRPSuccessfulSendWithoutResponseHasDeadline(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	updateTimer := env.timer
	env.fireTimer()
	if env.sender.packetCount() != 1 || env.client.GetState() != StateUpdating {
		t.Fatal("fixture did not successfully send a real pending DNS update")
	}
	currentSRPMessageID(t, env)
	if env.timer == updateTimer || env.timer.delay < time.Duration(MinRetryWaitInterval)*time.Millisecond {
		t.Fatal("successful send did not arm a distinct bounded response deadline")
	}
	env.fireTimer()
	if len(*outcomes) != 1 || (*outcomes)[0].err != errors.ErrResponseTimeout ||
		env.client.GetState() != StateToRetry || service.State != ItemStateToAdd {
		t.Fatalf("missing response did not produce pending retry + one timeout: outcomes=%+v state=%v item=%v",
			*outcomes, env.client.GetState(), service.State)
	}
}
