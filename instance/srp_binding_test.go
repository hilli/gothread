package instance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/srp"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
)

type srpPair struct {
	client, server *fragmentEndpoint
	binding        *SRPBinding
	config         SRPConfig
	store          *srpSettings
	entropy        *srpEntropy
	response       []byte
	responsePeer   ip6.SockAddr
	sendResponse   bool
}

func newSRPPair(t *testing.T, provision bool) *srpPair {
	t.Helper()
	store, entropy := newSRPSettings(), &srpEntropy{}
	caps := radio.CapCsmaBackoff | radio.CapTransmitRetries | radio.CapAckTimeout
	pair := &srpPair{
		client: newFragmentEndpointEntropy(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, store, caps, entropy),
		server: newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings()),
		store:  store, entropy: entropy, sendResponse: true,
	}
	info := fragmentInfo(fragmentSource, udpPeerExt, true)
	advertised := info.SockAddr
	advertised[8], advertised[11], advertised[12], advertised[14], advertised[15] = 0x71, 0, 0, 0, 0x23
	pair.config = SRPConfig{
		Local:    ip6.SockAddr{Address: info.SockAddr, Port: 40000},
		Server:   ip6.SockAddr{Address: info.PeerAddr, Port: 53},
		HostName: "native-host", Addresses: []ip6.Address{advertised},
	}
	mustSRPLoop(t, pair.client.inst, func() error {
		now := time.Now()
		pair.client.inst.timers.now = func() time.Time { return now }
		pair.client.inst.netif.AddUnicastAddress(&ip6.UnicastAddress{Address: advertised, PrefixLength: 64, Valid: true})
		if !provision {
			return nil
		}
		var err error
		pair.binding, err = pair.client.inst.StartSRP(pair.config)
		return err
	})
	mustSRPLoop(t, pair.server.inst, func() error {
		pair.server.inst.srpServer = srp.NewServer(
			srp.WithServerAfterFunc(func(delay time.Duration, fn func()) srp.Timer {
				timer := &srpLoopTimer{active: true}
				timer.cancel = pair.server.inst.timers.scheduleWithCancel(delay, fn)
				return timer
			}),
			srp.WithServerResponder(func(data []byte, peer ip6.SockAddr) {
				pair.response = append([]byte(nil), data...)
				pair.responsePeer = peer
				if pair.sendResponse {
					owned := append([]byte(nil), data...)
					pair.server.inst.timers.schedule(0, func() {
						if err := pair.server.inst.SendUDP(owned, ip6.MessageInfo{
							SockAddr: pair.config.Server.Address, SockPort: pair.config.Server.Port,
							PeerAddr: peer.Address, PeerPort: peer.Port,
						}); err != nil {
							t.Errorf("real server response admission: %v", err)
						}
					})
				}
			}))
		pair.server.inst.srpServer.Enable(true)
		return pair.server.inst.srpServer.Start(pair.config.Server.Port)
	})
	t.Cleanup(func() {
		mustSRPLoop(t, pair.server.inst, func() error { pair.server.inst.srpServer.Stop(); return nil })
	})
	return pair
}

func mustSRPLoop(t *testing.T, inst *Instance, fn func() error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := inst.Do(ctx, fn); err != nil {
		t.Fatal(err)
	}
}

func fireSRPTimer(t *testing.T, binding *SRPBinding) {
	t.Helper()
	mustSRPLoop(t, binding.inst, func() error {
		timer := binding.timer
		if timer == nil || !timer.active {
			return fmt.Errorf("no active bound client timer")
		}
		timer.cancel()
		timer.fire()
		return nil
	})
}

func forwardSRPDatagram(t *testing.T, source, destination *fragmentEndpoint) int {
	t.Helper()
	frames := 0
	for {
		capture := captureUDP(t, source.driver.boundedUDPRadio)
		ctx, _ := nativeAdaptation(t, capture, source.macKey)
		if capture.frame.TxInfo.SubmissionID == 0 || ctx.Security.FrameCounter == ^uint32(0) {
			t.Fatal("unowned transmit or exhausted frame counter")
		}
		deliverNativeFrame(t, destination, capture)
		completeNativeFrame(t, source, capture, nil)
		frames++
		var pending bool
		mustSRPLoop(t, source.inst, func() error { pending = source.inst.pendingTxMsg != nil; return nil })
		if !pending {
			return frames
		}
		if frames >= 20 {
			t.Fatal("unexpected unbounded SRP datagram fragmentation")
		}
	}
}

func nextSRPNotice(t *testing.T, binding *SRPBinding) SRPNotice {
	t.Helper()
	select {
	case notice, ok := <-binding.Notices():
		if !ok {
			t.Fatalf("binding unexpectedly closed: %v", binding.Err())
		}
		return notice
	default:
		t.Fatal("no outcome from actual matching response/deadline")
		return SRPNotice{}
	}
}

func exchangeSRP(t *testing.T, pair *srpPair) SRPNotice {
	t.Helper()
	performSRPExchange(t, pair)
	return nextSRPNotice(t, pair.binding)
}

func performSRPExchange(t *testing.T, pair *srpPair) {
	t.Helper()
	fireSRPTimer(t, pair.binding)
	if frames := forwardSRPDatagram(t, pair.client, pair.server); frames < 2 {
		t.Fatal("test did not exercise secured fragmented DNS UPDATE")
	}
	forwardSRPDatagram(t, pair.server, pair.client)
	mustSRPLoop(t, pair.client.inst, func() error { return nil }) // Drain deferred native RX.
	if pair.responsePeer != pair.config.Local {
		t.Fatal("production request lost original IPv6 tuple/nonzero owned port")
	}
}

func nativeService(name string) srp.Service {
	return srp.Service{Name: "_matter._tcp", InstanceName: name, Port: 5540,
		TxtEntries: []dns.TxtEntry{{Key: "SII", Value: []byte("5000")}}}
}

func TestBoundSRPProductionRegisterReplaceWithdraw(t *testing.T) {
	pair := newSRPPair(t, true)
	service := nativeService("fabric-1")
	var token uint64
	mustSRPLoop(t, pair.client.inst, func() error {
		var err error
		token, err = pair.binding.UpsertService(service)
		return err
	})
	service.TxtEntries[0].Value[0] = 'X'
	notice := exchangeSRP(t, pair)
	if notice.Err != nil || notice.Revision != token || len(notice.Services) != 1 ||
		notice.Services[0].State != srp.ItemStateRegistered || string(notice.Services[0].TxtEntries[0].Value) != "5000" {
		t.Fatalf("actual registration/deep ownership failed: err=%v services=%d", notice.Err, len(notice.Services))
	}
	mustSRPLoop(t, pair.server.inst, func() error {
		hosts := pair.server.inst.srpServer.GetHosts()
		if len(hosts) != 1 || len(hosts[0].Services) != 1 || hosts[0].Services[0].Port != 5540 {
			return fmt.Errorf("real server did not commit registration")
		}
		return nil
	})
	service = nativeService("fabric-1")
	service.Port = 5541
	mustSRPLoop(t, pair.client.inst, func() error {
		var err error
		token, err = pair.binding.UpsertService(service)
		return err
	})
	updated := exchangeSRP(t, pair)
	if updated.Err != nil || len(updated.Services) != 1 || updated.Services[0].Port != 5541 || updated.Revision != token {
		t.Fatal("replacement was not independently acknowledged")
	}
	updated.Services[0].TxtEntries[0].Value[0] = 'Y'
	mustSRPLoop(t, pair.client.inst, func() error {
		var err error
		token, err = pair.binding.WithdrawService(service.Name, service.InstanceName)
		return err
	})
	removed := exchangeSRP(t, pair)
	if removed.Err != nil || len(removed.Services) != 0 || len(removed.RemovedServices) != 1 ||
		removed.RemovedServices[0].State != srp.ItemStateRemoved || removed.Revision != token ||
		string(removed.RemovedServices[0].TxtEntries[0].Value) != "5000" {
		t.Fatalf("withdrawal was not a deep-owned actual ACK: %v", removed.Err)
	}
	mustSRPLoop(t, pair.client.inst, pair.binding.Stop)
	if pair.binding.Err() != nil {
		t.Fatal("explicit local stop returned remote claim/failure")
	}
}

func TestBoundSRPSixServicesBatchHighwaterAndACKSubset(t *testing.T) {
	pair := newSRPPair(t, true)
	services := make([]srp.Service, 6)
	var highwater uint64
	mustSRPLoop(t, pair.client.inst, func() error {
		for i := range services {
			services[i] = nativeService(fmt.Sprintf("fabric-%d", i))
		}
		services[5].Name = "_matterc._udp"
		services[5].SubTypeLabels = []string{"_S15", "_L3840", "_V65521", "_T257", "_CM1"}
		for _, service := range services {
			var err error
			highwater, err = pair.binding.UpsertService(service)
			if err != nil {
				return err
			}
		}
		return nil
	})
	for i := range services {
		notice := exchangeSRP(t, pair)
		if notice.Err != nil || len(notice.Services) != 1 || notice.Services[0].InstanceName != services[i].InstanceName ||
			notice.Revision != highwater || len(notice.RemovedServices) != 0 {
			t.Fatalf("batch ACK included unselected/old registrations at index%d: %+v", i, notice)
		}
		if i == 5 && len(notice.Services[0].SubTypeLabels) != 5 {
			t.Fatal("commissionable subtypes truncated")
		}
	}
	// A is refreshed first. Then lose B's automatic renewal response: the
	// error invalidates consumer health, including A's earlier registration.
	fireSRPTimer(t, pair.binding) // Lease renewal -> scheduled UPDATE.
	renewedA := exchangeSRP(t, pair)
	if len(renewedA.Services) != 1 || renewedA.Services[0].InstanceName != services[0].InstanceName {
		t.Fatal("automatic renewal did not select A first")
	}
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = false; return nil })
	fireSRPTimer(t, pair.binding) // Actual B renewal send.
	forwardSRPDatagram(t, pair.client, pair.server)
	fireSRPTimer(t, pair.binding) // Actual lost-response deadline.
	failure := nextSRPNotice(t, pair.binding)
	if failure.Err != goterrors.ErrResponseTimeout || pair.binding.Err() != nil {
		t.Fatal("renewal timeout was hidden or incorrectly terminal")
	}
	// A's retained Registered flag MUST NOT be re-ACKed by B's retry.
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = true; return nil })
	recoveredB := exchangeSRP(t, pair)
	if recoveredB.Err != nil || len(recoveredB.Services) != 1 ||
		recoveredB.Services[0].InstanceName != services[1].InstanceName {
		t.Fatal("B-only response falsely healed A/other retained registrations")
	}
	healthy := map[string]bool{recoveredB.Services[0].InstanceName: true}
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(services[0]); return err })
	for range 5 { // C,D,E,F,then explicitly re-admitted A.
		notice := exchangeSRP(t, pair)
		if notice.Err != nil || len(notice.Services) != 1 {
			t.Fatal("recovery lacked actual single-service ACK")
		}
		healthy[notice.Services[0].InstanceName] = true
	}
	if len(healthy) != 6 {
		t.Fatal("whole health recovered without a fresh ACK for every desired service")
	}
}

func TestBoundSRPNoResponseWrongTupleAndPauseOwnership(t *testing.T) {
	pair := newSRPPair(t, true)
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(nativeService("A")); return err })
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = false; return nil })
	fireSRPTimer(t, pair.binding)
	forwardSRPDatagram(t, pair.client, pair.server)
	response := append([]byte(nil), pair.response...)
	info := pair.binding.messageInfo()
	info.PeerAddr, info.PeerPort = pair.config.Server.Address, pair.config.Server.Port
	mustSRPLoop(t, pair.client.inst, func() error {
		wrong := info
		wrong.PeerPort++
		pair.client.inst.udpManager.HandleMessage(response, &wrong)
		wrong = info
		wrong.PeerAddr[15]++
		pair.client.inst.udpManager.HandleMessage(response, &wrong)
		wrong = info
		wrong.SockAddr[15]++
		pair.client.inst.udpManager.HandleMessage(response, &wrong)
		stale := append([]byte(nil), response...)
		stale[1] ^= 1
		pair.client.inst.udpManager.HandleMessage(stale, &info)
		pair.client.inst.udpManager.HandleMessage([]byte{1, 2}, &info)
		if len(pair.binding.notices) != 0 || !pair.binding.timer.active {
			return fmt.Errorf("wrong tuple/ID/malformed reply completed registration or cancelled deadline")
		}
		return nil
	})
	fireSRPTimer(t, pair.binding)
	if nextSRPNotice(t, pair.binding).Err != goterrors.ErrResponseTimeout {
		t.Fatal("accepted send/no response failed to time out")
	}
	old := pair.binding.timer
	mustSRPLoop(t, pair.client.inst, pair.binding.Pause)
	paused := nextSRPNotice(t, pair.binding)
	if paused.State != srp.StatePaused || paused.Err != nil || len(paused.Services) != 0 {
		t.Fatal("pause did not invalidate health without an ACK")
	}
	mustSRPLoop(t, pair.client.inst, func() error { old.fire(); return nil })
	if len(pair.client.driver.captures) != 0 {
		t.Fatal("cancelled retry sent while paused")
	}
	mustSRPLoop(t, pair.client.inst, pair.binding.Resume)
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = true; return nil })
	if notice := exchangeSRP(t, pair); notice.Err != nil || len(notice.Services) != 1 {
		t.Fatal("resumed actual retry failed")
	}
}

func TestBoundSRPPortRollbackLifecycleAndStorageFailure(t *testing.T) {
	for _, mode := range []string{"collision", "read", "before-commit", "after-commit", "invalid-address"} {
		t.Run(mode, func(t *testing.T) {
			pair := newSRPPair(t, false)
			mustSRPLoop(t, pair.client.inst, func() error {
				config := pair.config
				var occupied udp.Socket
				switch mode {
				case "collision":
					if err := pair.client.inst.udpManager.Open(&occupied, udp.NetifThreadInternal, nil); err != nil {
						return err
					}
					if err := pair.client.inst.udpManager.Bind(&occupied, config.Local); err != nil {
						return err
					}
				case "read":
					pair.store.getErr = true
				case "before-commit", "after-commit":
					pair.store.setErr, pair.store.commitThenFail = true, mode == "after-commit"
				case "invalid-address":
					config.Addresses = []ip6.Address{{0x20, 1, 15: 9}}
				}
				binding, err := pair.client.inst.StartSRP(config)
				if err == nil || binding != nil || len(pair.client.driver.captures) != 0 {
					return fmt.Errorf("unqualified config/storage failure admitted signed traffic")
				}
				if mode == "collision" || mode == "invalid-address" {
					if pair.store.keyWrites != 0 {
						return fmt.Errorf("read-only preflight wrote a key")
					}
				} else if !errors.Is(err, errSRPStorage) {
					return fmt.Errorf("storage cause hidden: %w", err)
				}
				if mode != "collision" && pair.client.inst.udpManager.IsPortInUse(config.Local.Port) {
					return fmt.Errorf("failed start leaked UDP port")
				}
				return pair.client.inst.udpManager.Close(&occupied)
			})
		})
	}
	for _, mode := range []string{"binding", "thread", "instance", "entropy", "source"} {
		t.Run(mode, func(t *testing.T) {
			pair := newSRPPair(t, true)
			old := pair.binding.timer
			if mode == "instance" {
				pair.client.inst.Stop()
				if pair.binding.Err() != goterrors.ErrInvalidState {
					t.Fatal("Instance.Stop did not close binding")
				}
				if err := pair.client.inst.Start(); err != nil {
					t.Fatal(err)
				}
			} else {
				mustSRPLoop(t, pair.client.inst, func() error {
					switch mode {
					case "binding":
						return pair.binding.Stop()
					case "thread":
						if err := pair.client.inst.ThreadStop(); err != nil {
							return err
						}
						return pair.client.inst.IfConfigDown()
					case "entropy":
						pair.entropy.fail = true
						old.cancel()
						old.fire()
					case "source":
						for _, address := range pair.client.inst.netif.GetUnicastAddresses() {
							if address.Address == pair.config.Addresses[0] {
								pair.client.inst.netif.RemoveUnicastAddress(&address)
							}
						}
						old.cancel()
						old.fire()
					}
					return nil
				})
			}
			mustSRPLoop(t, pair.client.inst, func() error {
				old.fire()
				if pair.client.inst.udpManager.IsPortInUse(pair.config.Local.Port) || len(pair.client.driver.captures) != 0 {
					return fmt.Errorf("stopped generation retained socket or sent")
				}
				return nil
			})
		})
	}
}

func TestBoundSRPActualRejectionAndRetryableWithdrawal(t *testing.T) {
	pair := newSRPPair(t, true)
	service := nativeService("reject")
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(service); return err })
	mustSRPLoop(t, pair.server.inst, func() error {
		pair.server.inst.srpServer.SetServiceUpdateHandler(func(id uint32, _ *srp.RegHost, _ time.Duration) {
			pair.server.inst.timers.schedule(0, func() {
				pair.server.inst.srpServer.HandleServiceUpdateResult(id, goterrors.ErrSecurity)
			})
		})
		return nil
	})
	rejected := exchangeSRP(t, pair)
	if rejected.Err != dns.ResponseCodeToError(dns.RcodeRefused) || len(rejected.RemovedServices) != 0 ||
		rejected.Services[0].State == srp.ItemStateRegistered || pair.binding.Err() != nil {
		t.Fatal("negative server result published false ACK/terminal state")
	}
	mustSRPLoop(t, pair.server.inst, func() error { pair.server.inst.srpServer.SetServiceUpdateHandler(nil); return nil })
	if notice := exchangeSRP(t, pair); notice.Err != nil || len(notice.Services) != 1 {
		t.Fatal("real rejected registration did not retry")
	}
	mustSRPLoop(t, pair.client.inst, func() error {
		_, err := pair.binding.WithdrawService(service.Name, service.InstanceName)
		return err
	})
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = false; return nil })
	fireSRPTimer(t, pair.binding)
	forwardSRPDatagram(t, pair.client, pair.server)
	fireSRPTimer(t, pair.binding)
	timeout := nextSRPNotice(t, pair.binding)
	if timeout.Err != goterrors.ErrResponseTimeout || len(timeout.RemovedServices) != 0 {
		t.Fatal("withdrawal send/timeout falsely claimed removal ACK")
	}
	mustSRPLoop(t, pair.client.inst, func() error {
		_, err := pair.binding.WithdrawService(service.Name, service.InstanceName)
		return err
	})
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = true; return nil })
	if notice := exchangeSRP(t, pair); notice.Err != nil || len(notice.RemovedServices) != 1 {
		t.Fatal("retryable withdrawal did not reach actual ACK")
	}
}

func TestBoundSRPNoticeAndRXBackpressureFailClosed(t *testing.T) {
	for _, mode := range []string{"notices", "pause", "rx", "commands"} {
		t.Run(mode, func(t *testing.T) {
			pair := newSRPPair(t, true)
			if mode == "notices" || mode == "pause" {
				attempts := SRPNoticeCapacity + 1
				if mode == "pause" {
					attempts--
				}
				for i := 0; i < attempts; i++ {
					service := nativeService("buffered")
					service.Port += uint16(i)
					mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(service); return err })
					performSRPExchange(t, pair)
				}
				if mode == "pause" {
					mustSRPLoop(t, pair.client.inst, func() error {
						if err := pair.binding.Pause(); err != goterrors.ErrNoBufs {
							return fmt.Errorf("full pause notice queue did not fail closed: %v", err)
						}
						return nil
					})
				}
			} else {
				mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(nativeService("rx")); return err })
				mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = false; return nil })
				fireSRPTimer(t, pair.binding)
				forwardSRPDatagram(t, pair.client, pair.server)
				mustSRPLoop(t, pair.client.inst, func() error {
					if mode == "commands" {
						for len(pair.client.inst.taskCh) < cap(pair.client.inst.taskCh) {
							pair.client.inst.taskCh <- func() {}
						}
					}
					info := pair.binding.messageInfo()
					count := SRPNoticeCapacity + 1
					if mode == "commands" {
						count = 1
					}
					for range count {
						pair.binding.receive(pair.response, &info)
					}
					return nil
				})
			}
			if pair.binding.Err() != goterrors.ErrNoBufs {
				t.Fatal("full bounded queue silently lost outcome or stayed healthy")
			}
			mustSRPLoop(t, pair.client.inst, func() error {
				if pair.client.inst.udpManager.IsPortInUse(pair.config.Local.Port) || pair.binding.timer.active {
					return fmt.Errorf("overflow retained socket/timer")
				}
				return nil
			})
			count := 0
			for notice := range pair.binding.Notices() {
				if notice.Err != nil || len(notice.Services) != 1 {
					t.Fatal("previous ACK snapshot corrupted by overflow")
				}
				if notice.Services[0].Port != uint16(5540+count) {
					t.Fatal("buffered ACK content aliases later mutation")
				}
				count++
			}
			if (mode == "notices" || mode == "pause") && count != SRPNoticeCapacity {
				t.Fatal("notice capacity silently truncated")
			}
		})
	}
}

func TestBoundSRPQueuedOldGenerationAndRebind(t *testing.T) {
	pair := newSRPPair(t, true)
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(nativeService("old")); return err })
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = false; return nil })
	fireSRPTimer(t, pair.binding)
	forwardSRPDatagram(t, pair.client, pair.server)
	old := pair.binding
	timer := old.timer
	mustSRPLoop(t, pair.client.inst, func() error {
		info := old.messageInfo()
		old.receive(pair.response, &info)
		if err := old.Stop(); err != nil {
			return err
		}
		var err error
		pair.binding, err = pair.client.inst.StartSRP(pair.config)
		if err != nil {
			return err
		}
		if _, err := pair.binding.UpsertService(nativeService("replacement")); err != nil {
			return err
		}
		timer.fire()
		return nil
	})
	mustSRPLoop(t, pair.client.inst, func() error {
		if len(pair.binding.notices) != 0 || pair.binding.client.GetState() != srp.StateToUpdate ||
			pair.store.keyWrites != 1 {
			return fmt.Errorf("old queued RX/timer contaminated rebound client")
		}
		return nil
	})
	mustSRPLoop(t, pair.server.inst, func() error { pair.sendResponse = true; return nil })
	if notice := exchangeSRP(t, pair); notice.Err != nil || len(notice.Services) != 1 ||
		notice.Services[0].InstanceName != "replacement" {
		t.Fatal("rebound client failed actual peer ACK")
	}
}

func TestBoundSRPFreshInstanceReusesKeyAndSkipsMACReservation(t *testing.T) {
	pair := newSRPPair(t, true)
	service := nativeService("reboot")
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(service); return err })
	if notice := exchangeSRP(t, pair); notice.Err != nil {
		t.Fatal(notice.Err)
	}
	identity, err := pair.store.Get(platform.SettingsKeySRPECDSAKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, err := pair.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != nil || len(state) < 41 {
		t.Fatal("missing actual durable MAC reservation")
	}
	reserved := binary.BigEndian.Uint32(state[37:41])
	pair.client.inst.Stop() // No graceful SRP withdrawal or counter-specific flush.
	pair.client = newFragmentEndpointEntropy(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, pair.store,
		radio.CapCsmaBackoff|radio.CapTransmitRetries|radio.CapAckTimeout, pair.entropy)
	mustSRPLoop(t, pair.client.inst, func() error {
		now := time.Now()
		pair.client.inst.timers.now = func() time.Time { return now }
		pair.client.inst.netif.AddUnicastAddress(&ip6.UnicastAddress{Address: pair.config.Addresses[0], PrefixLength: 64, Valid: true})
		var err error
		pair.binding, err = pair.client.inst.StartSRP(pair.config)
		if err != nil {
			return err
		}
		_, err = pair.binding.UpsertService(service)
		return err
	})
	fireSRPTimer(t, pair.binding)
	first := captureUDP(t, pair.client.driver.boundedUDPRadio)
	ctx, _ := nativeAdaptation(t, first, pair.client.macKey)
	if ctx.Security.FrameCounter < reserved {
		t.Fatal("fresh Instance reused a pre-crash reserved MAC counter")
	}
	deliverNativeFrame(t, pair.server, first)
	completeNativeFrame(t, pair.client, first, nil)
	forwardSRPDatagram(t, pair.client, pair.server)
	forwardSRPDatagram(t, pair.server, pair.client)
	mustSRPLoop(t, pair.client.inst, func() error { return nil })
	notice := nextSRPNotice(t, pair.binding)
	restored, _ := pair.store.Get(platform.SettingsKeySRPECDSAKey, 0)
	if notice.Err != nil || len(notice.Services) != 1 || !bytes.Equal(identity, restored) || pair.store.keyWrites != 1 {
		t.Fatal("real peer did not accept rebooted durable signing identity")
	}
}

func TestBoundSRPHostWithdrawalCoversAllOwnedServices(t *testing.T) {
	pair := newSRPPair(t, true)
	mustSRPLoop(t, pair.client.inst, func() error {
		for _, name := range []string{"A", "B"} {
			if _, err := pair.binding.UpsertService(nativeService(name)); err != nil {
				return err
			}
		}
		return nil
	})
	exchangeSRP(t, pair)
	exchangeSRP(t, pair)
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.WithdrawHost(true); return err })
	notice := exchangeSRP(t, pair)
	if notice.Err != nil || len(notice.Services) != 0 || len(notice.RemovedServices) != 2 || notice.Host.State != srp.ItemStateRemoved {
		t.Fatal("host withdrawal did not acknowledge all owned removals")
	}
	mustSRPLoop(t, pair.server.inst, func() error {
		if len(pair.server.inst.srpServer.GetHosts()) != 0 {
			return fmt.Errorf("server retained host after key-lease-zero ACK")
		}
		return nil
	})
}
