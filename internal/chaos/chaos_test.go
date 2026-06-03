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
	tests := []struct {
		name string
		in   string
		want Intensity
	}{
		{"low string", "low", IntensityLow},
		{"low shorthand", "L", IntensityLow},
		{"medium string", "medium", IntensityMedium},
		{"empty default", "", IntensityMedium},
		{"unknown", "weird", IntensityMedium},
		{"high string", "high", IntensityHigh},
		{"high shorthand", "H", IntensityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseIntensity(tt.in); got != tt.want {
				t.Errorf("ParseIntensity(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIntensityString(t *testing.T) {
	tests := []struct {
		intensity Intensity
		want      string
	}{
		{IntensityLow, "low"},
		{IntensityMedium, "medium"},
		{IntensityHigh, "high"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.intensity.String(); got != tt.want {
				t.Errorf("Intensity(%d).String() = %q, want %q", tt.intensity, got, tt.want)
			}
		})
	}
}

func TestRegistryHasAllScenarios(t *testing.T) {
	wantScenarios := []string{"cpu", "fd-leak", "memory", "disk-sat", "tcp-churn", "cascade"}
	for _, name := range wantScenarios {
		t.Run(name, func(t *testing.T) {
			if _, ok := Get(name); !ok {
				t.Errorf("scenario %q not registered", name)
			}
		})
	}
}

func TestList(t *testing.T) {
	t.Run("returns at least expected scenarios", func(t *testing.T) {
		scenarios := List()
		if len(scenarios) < 6 {
			t.Errorf("List() returned %d scenarios, want at least 6", len(scenarios))
		}
	})
	t.Run("returns sorted alphabetically", func(t *testing.T) {
		scenarios := List()
		for i := 1; i < len(scenarios); i++ {
			if scenarios[i].Name() < scenarios[i-1].Name() {
				t.Errorf("scenarios not sorted: %q after %q",
					scenarios[i].Name(), scenarios[i-1].Name())
			}
		}
	})
}

func TestRunUnknownScenario(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		wantErr  error
	}{
		{"nonexistent", "nonexistent", ErrNotFound},
		{"empty string", "", ErrNotFound},
		{"typo", "cpuu", ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Run(context.Background(), tt.scenario, Options{Duration: time.Second})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Run(%q) error = %v, want %v", tt.scenario, err, tt.wantErr)
			}
		})
	}
}

func TestRunHonorsContextCancel(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

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
	tests := []struct {
		name     string
		scenario string
		duration time.Duration
	}{
		{"cpu default", "cpu", 100 * time.Millisecond},
		{"fd-leak default", "fd-leak", 100 * time.Millisecond},
		{"memory default", "memory", 100 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			start := time.Now()
			err := Run(context.Background(), tt.scenario, Options{
				Duration:  tt.duration,
				Intensity: IntensityLow,
				Out:       &buf,
			})
			elapsed := time.Since(start)

			if err != nil {
				t.Errorf("Run returned error: %v", err)
			}
			if elapsed < tt.duration {
				t.Errorf("Run returned too early: %v < %v", elapsed, tt.duration)
			}
			if elapsed > 5*time.Second {
				t.Errorf("Run took too long: %v", elapsed)
			}
			if !strings.Contains(buf.String(), tt.scenario) {
				t.Errorf("Run output missing scenario name; got: %q", buf.String())
			}
		})
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
	Register(CPUScenario{})
}

func TestWorkersFromIntensity(t *testing.T) {
	tests := []struct {
		intensity Intensity
		ncpu      int
		want      int
	}{
		{IntensityLow, 8, 4},
		{IntensityMedium, 8, 8},
		{IntensityHigh, 8, 16},
		{IntensityLow, 1, 1},
		{IntensityMedium, 0, 1},
	}
	for _, tt := range tests {
		name := tt.intensity.String()
		if tt.ncpu == 0 {
			name += "_zero_cpu"
		}
		t.Run(name, func(t *testing.T) {
			got := workersFromIntensity(tt.intensity, tt.ncpu)
			if got != tt.want {
				t.Errorf("workersFromIntensity(%v, %d) = %d, want %d",
					tt.intensity, tt.ncpu, got, tt.want)
			}
		})
	}
}
