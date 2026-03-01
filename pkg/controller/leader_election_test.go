package controller

import (
	"os"
	"testing"
	"time"
)

func TestLeaderIdentity_FromEnv(t *testing.T) {
	const podName = "sealed-secrets-controller-abc123"
	t.Setenv("POD_NAME", podName)

	id, err := leaderIdentity()
	if err != nil {
		t.Fatalf("leaderIdentity() returned err: %v", err)
	}
	if id != podName {
		t.Errorf("got %q, want %q", id, podName)
	}
}

func TestLeaderIdentity_Hostname(t *testing.T) {
	// Ensure POD_NAME is not set so we fall through to os.Hostname().
	t.Setenv("POD_NAME", "")
	os.Unsetenv("POD_NAME")

	id, err := leaderIdentity()
	if err != nil {
		t.Fatalf("leaderIdentity() returned err: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname() returned err: %v", err)
	}
	if id != hostname {
		t.Errorf("got %q, want %q", id, hostname)
	}
}

func TestMainWithoutLeaderElection(t *testing.T) {
	flags := Flags{
		LeaderElect: false,
	}

	err := Main(&flags, "test")
	if err == nil {
		t.Fatal("expected non-nil error from Main() without in-cluster config")
	}
}

func TestMainWithLeaderElection(t *testing.T) {
	flags := Flags{
		LeaderElect:              true,
		LeaderElectLeaseDuration: 15 * time.Second,
		LeaderElectRenewDeadline: 10 * time.Second,
		LeaderElectRetryPeriod:   2 * time.Second,
	}

	err := Main(&flags, "test")
	if err == nil {
		t.Fatal("expected non-nil error from Main() without in-cluster config")
	}
}
