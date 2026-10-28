package srp

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/errors"
)

func TestCanonicalSignerLiteralWireLabels(t *testing.T) {
	for _, test := range []struct {
		data   []byte
		offset int
		want   []byte
	}{
		{[]byte("\x07NoDe.v2\x03Com\x00"), 0, []byte("\x07node.v2\x03com\x00")},
		{[]byte("\x07ExAmPle\x03Com\x00\x07NoDe.v2\xc0\x00"), 13,
			[]byte("\x07node.v2\x07example\x03com\x00")},
		{[]byte("\x02\xc3\x84\x00"), 0, []byte("\x02\xc3\x84\x00")}, // No Unicode case folding.
		{[]byte{0}, 0, []byte{0}},
	} {
		got, err := canonicalSignerName(test.data, test.offset)
		if err != nil || !bytes.Equal(got, test.want) {
			t.Fatalf("length-delimited canonical label expansion mismatch: %v", err)
		}
	}
}

func TestCanonicalSignerRejectsInvalidPointersAndNames(t *testing.T) {
	for _, data := range [][]byte{
		nil, {0xc0}, {0xc0, 0}, {0xc0, 2, 0}, {0x40, 0}, {3, 'a'},
		bytes.Repeat(append([]byte{63}, bytes.Repeat([]byte{'a'}, 63)...), 4),
	} {
		if _, err := canonicalSignerName(data, 0); err != errors.ErrParse {
			t.Fatalf("invalid canonical name/pointer accepted: %v", err)
		}
	}
	if _, err := canonicalSignerName([]byte{0xc0, 2, 0xc0, 0}, 2); err != errors.ErrParse {
		t.Fatal("backward/forward pointer cycle accepted")
	}
	maximum := bytes.Repeat(append([]byte{63}, bytes.Repeat([]byte{'a'}, 63)...), 3)
	maximum = append(maximum, 61)
	maximum = append(maximum, bytes.Repeat([]byte{'b'}, 61)...)
	maximum = append(maximum, 0)
	if canonical, err := canonicalSignerName(maximum, 0); err != nil || len(canonical) != 255 {
		t.Fatal("exact 255-byte canonical name incorrectly rejected")
	}
}

func TestStandaloneAddCannotSupersedePendingHostWithdrawal(t *testing.T) {
	env, _, _ := responseRegressionEnv(t)
	env.fireTimer()
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), 0))
	if err := env.client.RemoveHostAndServices(false, true); err != nil {
		t.Fatal(err)
	}
	if err := env.client.AddService(&Service{Name: "_other._udp", InstanceName: "unencoded", Port: 1}); err != errors.ErrInvalidState {
		t.Fatal("global pending host withdrawal admitted an unrelated addition")
	}
}
