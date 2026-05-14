// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseIntensity(t *testing.T) {
	cases := []struct {
		in   string
		want Intensity
	}{
		{"low", IntensityLow},
		{"L", IntensityLow},
		{"medium", IntensityMedium},
		{"", IntensityMedium}, // default
		{"weird", IntensityMedium},
		{"high", IntensityHigh},
		{"H", IntensityHigh},
	}
	for _, c := range cases {
		if got := ParseIntensity(c.in); got != c.want {
			t.Errorf("ParseIntensity(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIntensityString(t *testing.T) {
	if IntensityLow.String() != "low" {
		t.Errorf("low: got %q", IntensityLow.String())
	}
	if IntensityHigh.String() != "high" {
		t.Errorf("high: got %q", IntensityHigh.String())
	}
}

func TestRegistryHasAllScenarios(t *testing.T) {
	want := []string{"cpu", "fd-leak", "memory", "disk-sat", "tcp-churn", "cascade"}
	for _, name := range want {
		if _, ok := Get(name); !ok {
			t.Errorf("scenario %q not registered", name)
		}
	}
}

func TestList(t *testing.T) {
	scenarios := List()
	if len(scenarios) < 6 {
		t.Errorf("List() returned %d scenarios, want at least 6", len(scenarios))
	}
	// Sorted alphabetically.
	for i := 1; i < len(scenarios); i++ {
		if scenarios[i].Name() < scenarios[i-1].Name() {
			t.Errorf("scenarios not sorted: %q after %q",
				scenarios[i].Name(), scenarios[i-1].Name())
		}
	}
}

func TestRunUnknownScenario(t *testing.T) {
	err := Run(context.Background(), "nonexistent", Options{Duration: time.Second})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Run(nonexistent) error = %v, want ErrNotFound", err)
	}
}

func TestRunHonorsContextCancel(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before run

	start := time.Now()
	err := Run(ctx, "cpu", Options{
		Duration:  10 * time.Second,
		Intensity: IntensityLow,
		Out:       &buf,
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Run with canceled context returned error: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Run did not honor canceled context: took %v", elapsed)
	}
}

func TestRunUsesDefaults(t *testing.T) {
	// Pass minimal opts and verify Run does not panic, returns when
	// the duration elapses.
	var buf bytes.Buffer
	start := time.Now()
	err := Run(context.Background(), "cpu", Options{
		Duration:  100 * time.Millisecond,
		Intensity: IntensityLow,
		Out:       &buf,
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Run returned error: %v", err)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("Run returned too early: %v", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Run took too long: %v", elapsed)
	}
	if !strings.Contains(buf.String(), "cpu") {
		t.Errorf("Run output missing scenario name; got: %q", buf.String())
	}
}

func TestCPUScenario(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := CPUScenario{}.Run(ctx, Options{
		Intensity: IntensityLow,
		Out:       &buf,
	})
	if err != nil {
		t.Errorf("CPUScenario.Run = %v", err)
	}
}

func TestFDLeakScenario(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := FDLeakScenario{}.Run(ctx, Options{
		Intensity: IntensityLow,
		Out:       &buf,
	})
	if err != nil {
		t.Errorf("FDLeakScenario.Run = %v", err)
	}
	if !strings.Contains(buf.String(), "FDs/sec") {
		t.Errorf("FDLeak output missing rate line; got: %q", buf.String())
	}
}

func TestMemoryScenario(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := MemoryScenario{}.Run(ctx, Options{
		Duration:  300 * time.Millisecond,
		Intensity: IntensityLow,
		Out:       &buf,
	})
	if err != nil {
		t.Errorf("MemoryScenario.Run = %v", err)
	}
}

func TestDiskScenario(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := DiskScenario{}.Run(ctx, Options{
		Intensity: IntensityLow,
		Out:       &buf,
	})
	if err != nil {
		t.Errorf("DiskScenario.Run = %v", err)
	}
	if !strings.Contains(buf.String(), "fsync") {
		t.Errorf("Disk output missing fsync line; got: %q", buf.String())
	}
}

func TestTCPChurnScenario(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := TCPChurnScenario{}.Run(ctx, Options{
		Intensity: IntensityLow,
		Out:       &buf,
	})
	if err != nil {
		t.Errorf("TCPChurnScenario.Run = %v", err)
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Register of duplicate did not panic")
		}
	}()
	Register(CPUScenario{}) // already registered in init()
}

func TestWorkersFromIntensity(t *testing.T) {
	cases := []struct {
		intensity Intensity
		ncpu      int
		want      int
	}{
		{IntensityLow, 8, 4},
		{IntensityMedium, 8, 8},
		{IntensityHigh, 8, 16},
		{IntensityLow, 1, 1},    // floor at 1
		{IntensityMedium, 0, 1}, // ncpu coerced to 1
	}
	for _, c := range cases {
		got := workersFromIntensity(c.intensity, c.ncpu)
		if got != c.want {
			t.Errorf("workersFromIntensity(%v, %d) = %d, want %d",
				c.intensity, c.ncpu, got, c.want)
		}
	}
}
