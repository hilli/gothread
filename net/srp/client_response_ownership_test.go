// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srp

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

type srpSenderFunc func([]byte, ip6.SockAddr) error

func (send srpSenderFunc) Send(data []byte, destination ip6.SockAddr) error {
	return send(data, destination)
}

func TestSRPSynchronousSenderResponseHasOneDefiniteOutcome(t *testing.T) {
	for _, responseCode := range []dns.ResponseCode{dns.RcodeSuccess, dns.RcodeRefused} {
		env, service, outcomes := responseRegressionEnv(t)
		env.client.sender = srpSenderFunc(func(data []byte, destination ip6.SockAddr) error {
			if err := env.sender.Send(data, destination); err != nil {
				return err
			}
			env.client.HandleResponse(buildResponse(binary.BigEndian.Uint16(data[:2]), responseCode, 3600, 86400))
			// A definitive synchronous server response wins over a later
			// sender-return error; it must not arm a second deadline/outcome.
			return errors.ErrNoRoute
		})
		fireOwnedResponseTimer(t, env)
		if len(*outcomes) != 1 || (*outcomes)[0].err != dns.ResponseCodeToError(responseCode) {
			t.Fatalf("reentrant sender lost exact response outcome: %+v", *outcomes)
		}
		if responseCode == dns.RcodeSuccess && service.State != ItemStateRegistered {
			t.Fatal("synchronous positive response was lost")
		}
		if responseCode != dns.RcodeSuccess && service.State != ItemStateToAdd {
			t.Fatal("synchronous rejection applied success")
		}
	}
}

func TestSRPReturningSupersededSendCannotArmNewDeadline(t *testing.T) {
	env, _, outcomes := responseRegressionEnv(t)
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	env.client.sender = srpSenderFunc(func(data []byte, destination ip6.SockAddr) error {
		if err := env.sender.Send(data, destination); err != nil {
			return err
		}
		close(entered)
		<-release
		return nil
	})
	old := env.timer
	go func() { old.Fire(); close(completed) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not start")
	}
	server := env.client.GetServerAddress()
	env.client.Stop()
	if err := env.client.Start(server); err != nil {
		t.Fatal(err)
	}
	current := activeResponseTimer(t, env)
	unblock()
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("old sender did not release")
	}
	if activeResponseTimer(t, env) != current || len(*outcomes) != 0 || env.client.GetState() != StateToUpdate {
		t.Fatal("old successful send return attached its deadline to the restarted operation")
	}
	env.client.sender = env.sender
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeSuccess))
	if len(*outcomes) != 1 || (*outcomes)[0].err != nil {
		t.Fatal("restarted operation did not complete independently")
	}
}

func TestSRPFailureCallbackCanReplaceTheServiceOperation(t *testing.T) {
	env, _, _ := responseRegressionEnv(t)
	next := &Service{Name: "_new._udp", InstanceName: "replacement", Port: 7777}
	var outcomes []error
	env.client.SetCallback(func(err error, _ *HostInfo, _, removed []*Service) {
		outcomes = append(outcomes, err)
		if len(removed) != 0 {
			t.Error("rejected operation published removal")
		}
		if err != nil {
			env.client.ClearHostAndServices()
			if err := env.client.SetHostName("replacement-host"); err != nil {
				t.Error(err)
			}
			if err := env.client.SetHostAddresses([]ip6.Address{{0xfd, 15: 9}}); err != nil {
				t.Error(err)
			}
			if err := env.client.AddService(next); err != nil {
				t.Error(err)
			}
		}
	})
	fireOwnedResponseTimer(t, env)
	oldID := currentSRPMessageID(t, env)
	oldDeadline := activeResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(oldID, dns.RcodeRefused))
	if len(outcomes) != 1 || outcomes[0] != errors.ErrSecurity {
		t.Fatal("failure callback replacement did not preserve one error")
	}
	current := activeResponseTimer(t, env)
	oldDeadline.Fire()
	if activeResponseTimer(t, env) != current || env.client.GetState() != StateToUpdate {
		t.Fatal("old callback/deadline modified a replacement operation")
	}
	fireOwnedResponseTimer(t, env)
	newID := currentSRPMessageID(t, env)
	env.client.HandleResponse(buildSimpleResponse(oldID, dns.RcodeSuccess))
	if len(outcomes) != 1 {
		t.Fatal("old response completed replacement operation")
	}
	env.client.HandleResponse(buildSimpleResponse(newID, dns.RcodeSuccess))
	if len(outcomes) != 2 || outcomes[1] != nil || next.State != ItemStateRegistered {
		t.Fatal("replacement operation did not complete normally")
	}
}

func TestSRPStaleRetryCannotOperateOnNewConfiguration(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	fireOwnedResponseTimer(t, env)
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeRefused))
	oldRetry := activeResponseTimer(t, env)
	if err := env.client.SetHostAddresses([]ip6.Address{{0xfd, 15: 7}}); err != nil {
		t.Fatal(err)
	}
	fireOwnedResponseTimer(t, env)
	deadline := activeResponseTimer(t, env)
	oldRetry.Fire()
	oldRetry.Fire()
	if env.sender.packetCount() != 2 || len(*outcomes) != 1 ||
		activeResponseTimer(t, env) != deadline || service.State == ItemStateRegistered {
		t.Fatal("queued retry callback operated on a newer request")
	}
}

func TestSRPWireIDsCanBeReusedWithoutLifetimeExhaustion(t *testing.T) {
	env, service, outcomes := responseRegressionEnv(t)
	var ids []uint16
	for cycle := 0; cycle < 3; cycle++ {
		if cycle != 0 {
			if err := env.client.SetHostAddresses([]ip6.Address{{0xfd, 15: byte(cycle + 1)}}); err != nil {
				t.Fatal(err)
			}
		}
		fireOwnedResponseTimer(t, env)
		id := currentSRPMessageID(t, env)
		ids = append(ids, id)
		env.client.HandleResponse(buildSimpleResponse(id, dns.RcodeSuccess))
		if service.State != ItemStateRegistered || len(*outcomes) != cycle+1 || (*outcomes)[cycle].err != nil {
			t.Fatal("long-lived client stopped accepting successful independent updates")
		}
	}
	// The deterministic RNG always samples 1. Only the immediately previous
	// ID is excluded; reuse after intervening transactions is intentional.
	if ids[0] == ids[1] || ids[1] == ids[2] || ids[0] != ids[2] {
		t.Fatalf("wire ID behavior was replaced by a lifetime uniqueness policy: %v", ids)
	}
}
