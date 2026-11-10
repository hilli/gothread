package mle

import (
	"errors"
	"io"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

type partialChallengeReader struct{ failure error }

func (reader partialChallengeReader) Read(destination []byte) (int, error) {
	copy(destination, []byte{1, 2, 3})
	return 3, reader.failure
}

func TestChallengeReaderCannotBeReplacedAfterUse(t *testing.T) {
	env, _, _, _ := newTestAttacher()
	failure := errors.New("reader failure")
	if err := env.dispatcher.SetEntropyReader(partialChallengeReader{failure}); err != nil {
		t.Fatal(err)
	}
	var challenge Challenge
	if err := env.dispatcher.GenerateChallenge(&challenge); !errors.Is(err, failure) {
		t.Fatal("checked dispatcher ignored reader failure")
	}
	if err := env.dispatcher.SetEntropyReader(partialChallengeReader{io.ErrUnexpectedEOF}); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("failed generator was hot-swapped")
	}
}

func TestCheckedChallengeDoesNotCommitPartialEntropy(t *testing.T) {
	failure := errors.New("entropy failed")
	challenge := Challenge{9, 9, 9, 9, 9, 9, 9, 9}
	before := challenge
	if err := challenge.GenerateChallengeWithReader(partialChallengeReader{failure}); !errors.Is(err, failure) {
		t.Fatalf("entropy cause lost: %v", err)
	}
	if challenge != before {
		t.Fatal("partial entropy committed a challenge")
	}
	if err := challenge.GenerateChallengeWithReader(partialChallengeReader{io.ErrUnexpectedEOF}); err == nil {
		t.Fatal("short entropy accepted")
	}
}
