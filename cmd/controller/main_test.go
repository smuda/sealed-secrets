package main

import (
	"bytes"
	goflag "flag"
	"testing"

	flag "github.com/spf13/pflag"
)

func TestVersion(t *testing.T) {
	buf := bytes.NewBufferString("")
	testVersionFlags := flag.NewFlagSet("testVersionFlags", flag.ExitOnError)
	testNopFlags := goflag.NewFlagSet("nop", goflag.ExitOnError)
	err := mainE(buf, testVersionFlags, testNopFlags, []string{"--version"})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := buf.String(), "controller version: UNKNOWN\n"; got != want {
		t.Errorf("got: %q, want: %q", got, want)
	}
}

func TestLeaderElectFlags(t *testing.T) {
	buf := bytes.NewBufferString("")
	fs := flag.NewFlagSet("testLeaderElectFlags", flag.ContinueOnError)
	gofs := goflag.NewFlagSet("nop", goflag.ContinueOnError)
	args := []string{
		"--version",
		"--leader-elect",
		"--leader-elect-lease-duration=20s",
		"--leader-elect-renew-deadline=15s",
		"--leader-elect-retry-period=3s",
	}
	err := mainE(buf, fs, gofs, args)
	if err != nil {
		t.Fatalf("mainE() returned unexpected error: %v", err)
	}
}
