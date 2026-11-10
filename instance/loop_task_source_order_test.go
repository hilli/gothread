package instance

import (
	"os"
	"strings"
	"testing"
)

// STATIC SOURCE-order oracle only. No public runtime epilogue exposes the
// dispatcher's post-invocation instruction; this is not an old runtime kill,
// parser/compile result, callback-return substitute or production test hook.
func TestSDKRadioTaskDispatcherStaticSourceOrder(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	dispatch := read("loop_task.go")
	invocation := strings.Index(dispatch, "\ttask.fn()\n")
	maintenance := strings.Index(dispatch, "\t\ttask.owner.processSecurityFence()\n")
	retirement := strings.Index(dispatch, "\t\ttask.owner.retireRadioWork()\n")
	if invocation < 0 || maintenance <= invocation || retirement <= maintenance {
		t.Fatal("STATIC dispatcher source does not put original invocation before owned maintenance/retirement")
	}
	instance := read("instance.go")
	if strings.Count(instance, "dispatchLoopTask(task)") != 2 ||
		!strings.Contains(instance, "dispatchLoopTask(loopTask{fn: t.fn, owner: t.owner})") {
		t.Fatal("STATIC actual task/drain/timer dispatch site is missing its explicit entry")
	}
	owner := read("radio_quiescence.go")
	if strings.Count(owner, "dispatchLoopTask(task)") != 1 ||
		!strings.Contains(owner, "return loopTask{fn: fn, owner: inst}, true") ||
		strings.Contains(owner, "runRadioWork(") {
		t.Fatal("STATIC shutdown dispatcher or original-function envelope still uses an inner retirement wrapper")
	}
}
