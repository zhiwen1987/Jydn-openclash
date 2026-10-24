//go:build linux

package mihomodeploy

import (
	"context"
	"os"
	"testing"
)

func TestLabSyntaxRejectsMissingActualConsumedInputBeforeStart(t *testing.T) {
	if _, err := labServiceSyntax(context.Background(), nil, nil, nil, "op-01"); err == nil {
		t.Fatal("missing consumption accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := labServiceSyntax(ctx, &labKernelInput{}, nil, nil, "op-01"); err == nil {
		t.Fatal("cancelled syntax accepted")
	}
}
func TestLabSyntaxKnownParseRejectionAndUnprovenCleanupAreDifferent(t *testing.T) {
	// SYNTHETIC metadata only. This does not start any process or run -t.
	yes := true
	pid := 31415
	exit := 1
	observation := labKernelStartObservation{Attempted: true, Started: &yes, PID: &pid, WaitReturned: &yes, WaitErrorClass: "EXIT_STATUS", ExitCode: &exit, GroupAbsent: &yes, Stdout: &labKernelStream{Complete: true, SHA256: labConfigHash(nil)}, Stderr: &labKernelStream{Complete: true, SHA256: labConfigHash(nil)}}
	known := &labSyntaxCleanupObservation{core: &labSyntaxCleanupCore{process: &os.Process{Pid: pid}, observation: observation}}
	if !known.settled() {
		t.Fatal("known completed parse rejection treated as unknown cleanup")
	}
	for _, kind := range []string{"group_unknown", "group_present", "stream_incomplete", "stream_truncated", "wait_unknown", "wrong_owned_pid"} {
		v := observation
		out := *v.Stdout
		errStream := *v.Stderr
		v.Stdout = &out
		v.Stderr = &errStream
		process := &os.Process{Pid: pid}
		switch kind {
		case "group_unknown":
			v.GroupAbsent = nil
		case "group_present":
			no := false
			v.GroupAbsent = &no
		case "stream_incomplete":
			v.Stdout.Complete = false
		case "stream_truncated":
			v.Stderr.Truncated = true
		case "wait_unknown":
			v.WaitReturned = nil
		case "wrong_owned_pid":
			process.Pid++
		}
		if (&labSyntaxCleanupObservation{core: &labSyntaxCleanupCore{process: process, observation: v}}).settled() {
			t.Fatal("unproven syntax cleanup accepted")
		}
	}
}
