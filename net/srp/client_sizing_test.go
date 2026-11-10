package srp

import (
	"encoding/binary"
	"testing"
)

type sizingEntropy struct{ reads int }

func (r *sizingEntropy) Read(data []byte) (int, error) {
	r.reads++
	for i := range data {
		data[i] = byte(i) + 0x41
	}
	return len(data), nil
}

func TestServiceSizingUsesRealEncoderWithoutSideEffects(t *testing.T) {
	for _, keyLease := range []uint32{9000, 80000} {
		env, service, _ := responseRegressionEnv(t)
		WithSingleServiceUpdates()(env.client)
		reader := &sizingEntropy{}
		WithEntropy(reader)(env.client)
		service.Lease, service.KeyLease = 9000, keyLease
		state, timer := env.client.GetState(), env.timer
		size, err := env.client.ServiceUpdateSize(*service)
		if err != nil {
			t.Fatal(err)
		}
		if reader.reads != 0 || env.sender.packetCount() != 0 || env.timer != timer ||
			env.client.GetState() != state || service.State != ItemStateToAdd {
			t.Fatal("wire sizing signed/sent/changed operation ownership")
		}
		env.fireTimer()
		wire := env.sender.lastPacket().data
		if len(wire) != size || reader.reads == 0 {
			t.Fatal("measured placeholder size differs from actual signed UPDATE")
		}
		records := literalUpdateRecords(t, wire)
		last := records[len(records)-1]
		opt := last.rdata + len(last.data)
		// Literal OPT owner0 + fixed RR10 + option header4.
		leaseOffset := opt + 1 + 10 + 4
		if binary.BigEndian.Uint32(wire[leaseOffset:]) != 9000 {
			t.Fatal("selected service's requested lease was not actually encoded")
		}
	}
}
