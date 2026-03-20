// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"math"
	"time"

	"github.com/lowplane/kerno/internal/collector"
)

// Prediction represents a predicted future failure.
type Prediction struct {
	// Title is a human-readable description of the predicted failure.
	Title string

	// Signal is the kernel signal that's trending toward failure.
	Signal string

	// TimeToImpact is the estimated time until the failure occurs.
	TimeToImpact time.Duration

	// Confidence is how confident we are in this prediction (0.0–1.0).
	Confidence float64

	// CurrentValue is the current observed metric value.
	CurrentValue string

	// TrendRate describes the rate of change.
	TrendRate string

	// Limit is the threshold that will be breached.
	Limit string

	// Fix is the recommended action to prevent the failure.
	Fix []string
}

// PredictionReport is the output of a prediction analysis.
type PredictionReport struct {
	// Predictions are ranked by time to impact (most urgent first).
	Predictions []Prediction

	// SnapshotCount is how many signal snapshots were used for trend analysis.
	SnapshotCount int

	// AnalysisWindow is the total time span of collected snapshots.
	AnalysisWindow time.Duration
}

// Predict analyzes a series of signal snapshots to predict future failures.
// It uses linear extrapolation of growth rates against known limits.
// Requires at least 2 snapshots for meaningful predictions.
func Predict(snapshots []*collector.Signals) *PredictionReport {
	report := &PredictionReport{
		SnapshotCount: len(snapshots),
	}

	if len(snapshots) < 2 {
		return report
	}

	// Calculate analysis window.
	first := snapshots[0].Timestamp
	last := snapshots[len(snapshots)-1].Timestamp
	report.AnalysisWindow = last.Sub(first)

	// Run each prediction rule.
	report.Predictions = append(report.Predictions, predictFDExhaustion(snapshots)...)
	report.Predictions = append(report.Predictions, predictDiskSaturation(snapshots)...)
	report.Predictions = append(report.Predictions, predictSchedDegradation(snapshots)...)
	report.Predictions = append(report.Predictions, predictTCPDegradation(snapshots)...)

	// Sort by time to impact (most urgent first).
	sortPredictions(report.Predictions)

	return report
}

// predictFDExhaustion extrapolates FD growth to ulimit (65536 default).
func predictFDExhaustion(snapshots []*collector.Signals) []Prediction {
	rates := make([]float64, 0, len(snapshots))
	for _, s := range snapshots {
		if s.FD != nil && s.FD.GrowthRate > 0 {
			rates = append(rates, s.FD.GrowthRate)
		}
	}

	if len(rates) < 2 {
		return nil
	}

	avgRate := average(rates)
	if avgRate <= 0 {
		return nil
	}

	// Assume 65536 ulimit, estimate current count from latest snapshot.
	latest := snapshots[len(snapshots)-1]
	if latest.FD == nil {
		return nil
	}

	remaining := 65536.0 - float64(latest.FD.NetDelta)
	if remaining <= 0 {
		remaining = 1 // About to exhaust.
	}

	etaSecs := remaining / avgRate
	eta := time.Duration(etaSecs) * time.Second

	// Confidence based on consistency of growth rate.
	confidence := rateConsistency(rates)

	return []Prediction{{
		Title:        "File Descriptor Exhaustion",
		Signal:       "fd",
		TimeToImpact: eta,
		Confidence:   confidence,
		CurrentValue: fmt.Sprintf("growth %.1f FDs/sec, net delta %d", avgRate, latest.FD.NetDelta),
		TrendRate:    fmt.Sprintf("+%.1f FDs/sec", avgRate),
		Limit:        "ulimit 65536",
		Fix:          []string{"Find the leaking process: lsof -p <pid> | wc -l", "Check for unclosed connections/files", "Increase ulimit temporarily: ulimit -n 131072"},
	}}
}

// predictDiskSaturation extrapolates disk latency trend.
func predictDiskSaturation(snapshots []*collector.Signals) []Prediction {
	latencies := make([]float64, 0, len(snapshots))
	for _, s := range snapshots {
		if s.DiskIO != nil && s.DiskIO.SyncLatency.P99 > 0 {
			latencies = append(latencies, float64(s.DiskIO.SyncLatency.P99.Nanoseconds()))
		}
	}

	if len(latencies) < 2 {
		return nil
	}

	// Calculate slope (nanoseconds per snapshot interval).
	slope := linearSlope(latencies)
	if slope <= 0 {
		return nil // Latency is stable or decreasing.
	}

	// Predict time to reach critical threshold (200ms = 200_000_000ns).
	criticalNs := 200_000_000.0
	current := latencies[len(latencies)-1]
	if current >= criticalNs {
		return nil // Already critical — doctor handles this.
	}

	remaining := criticalNs - current
	// Slope is per-snapshot. Convert to per-second.
	interval := snapshots[len(snapshots)-1].Timestamp.Sub(snapshots[0].Timestamp)
	slopePerSec := slope / interval.Seconds() * float64(len(snapshots)-1)

	if slopePerSec <= 0 {
		return nil
	}

	etaSecs := remaining / slopePerSec
	eta := time.Duration(etaSecs) * time.Second

	confidence := rateConsistency(latencies) * 0.8 // Lower confidence for latency trends.

	return []Prediction{{
		Title:        "Disk I/O Saturation",
		Signal:       "diskio",
		TimeToImpact: eta,
		Confidence:   confidence,
		CurrentValue: fmt.Sprintf("sync p99=%s", time.Duration(current)),
		TrendRate:    fmt.Sprintf("+%.0fns/sec", slopePerSec),
		Limit:        "200ms critical threshold",
		Fix:          []string{"Check IOPS: iostat -x 1 5", "Identify write-heavy process: iotop -o", "Consider faster storage or write batching"},
	}}
}

// predictSchedDegradation extrapolates scheduler delay trends.
func predictSchedDegradation(snapshots []*collector.Signals) []Prediction {
	delays := make([]float64, 0, len(snapshots))
	for _, s := range snapshots {
		if s.Sched != nil && s.Sched.RunqDelay.P99 > 0 {
			delays = append(delays, float64(s.Sched.RunqDelay.P99.Nanoseconds()))
		}
	}

	if len(delays) < 2 {
		return nil
	}

	slope := linearSlope(delays)
	if slope <= 0 {
		return nil
	}

	criticalNs := 20_000_000.0 // 20ms critical threshold.
	current := delays[len(delays)-1]
	if current >= criticalNs {
		return nil
	}

	remaining := criticalNs - current
	interval := snapshots[len(snapshots)-1].Timestamp.Sub(snapshots[0].Timestamp)
	slopePerSec := slope / interval.Seconds() * float64(len(delays)-1)

	if slopePerSec <= 0 {
		return nil
	}

	etaSecs := remaining / slopePerSec
	eta := time.Duration(etaSecs) * time.Second

	confidence := rateConsistency(delays) * 0.7

	return []Prediction{{
		Title:        "CPU Scheduler Saturation",
		Signal:       "sched",
		TimeToImpact: eta,
		Confidence:   confidence,
		CurrentValue: fmt.Sprintf("runq p99=%s", time.Duration(current)),
		TrendRate:    fmt.Sprintf("+%.0fns/sec", slopePerSec),
		Limit:        "20ms critical threshold",
		Fix:          []string{"Check CPU usage: top -H", "Reduce worker threads or increase CPU count", "Check for runaway processes: ps aux --sort=-%cpu | head"},
	}}
}

// predictTCPDegradation extrapolates TCP retransmit rate trend.
func predictTCPDegradation(snapshots []*collector.Signals) []Prediction {
	rates := make([]float64, 0, len(snapshots))
	for _, s := range snapshots {
		if s.TCP != nil {
			rates = append(rates, s.TCP.RetransmitRate)
		}
	}

	if len(rates) < 2 {
		return nil
	}

	slope := linearSlope(rates)
	if slope <= 0 {
		return nil
	}

	criticalPct := 2.0 // 2% retransmit rate threshold.
	current := rates[len(rates)-1]
	if current >= criticalPct {
		return nil
	}

	remaining := criticalPct - current
	interval := snapshots[len(snapshots)-1].Timestamp.Sub(snapshots[0].Timestamp)
	slopePerSec := slope / interval.Seconds() * float64(len(rates)-1)

	if slopePerSec <= 0 {
		return nil
	}

	etaSecs := remaining / slopePerSec
	eta := time.Duration(etaSecs) * time.Second

	confidence := rateConsistency(rates) * 0.75

	return []Prediction{{
		Title:        "TCP Retransmit Storm",
		Signal:       "tcp",
		TimeToImpact: eta,
		Confidence:   confidence,
		CurrentValue: fmt.Sprintf("retransmit rate=%.2f%%", current),
		TrendRate:    fmt.Sprintf("+%.3f%%/sec", slopePerSec),
		Limit:        "2% retransmit threshold",
		Fix:          []string{"Check network errors: ethtool -S eth0 | grep -i error", "Check packet loss: ping -c 100 <gateway>", "Check for congestion: ss -ti"},
	}}
}

// Helper functions for trend analysis.

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// linearSlope computes the slope of a simple linear regression.
func linearSlope(values []float64) float64 {
	n := float64(len(values))
	if n < 2 {
		return 0
	}

	var sumX, sumY, sumXY, sumX2 float64
	for i, y := range values {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	denom := n*sumX2 - sumX*sumX
	if denom == 0 {
		return 0
	}

	return (n*sumXY - sumX*sumY) / denom
}

// rateConsistency measures how consistent a series of values is (0.0–1.0).
// Higher values mean more consistent trend (= higher prediction confidence).
func rateConsistency(values []float64) float64 {
	if len(values) < 2 {
		return 0.5
	}

	avg := average(values)
	if avg == 0 {
		return 0.5
	}

	// Coefficient of variation: std_dev / mean.
	var sumSqDiff float64
	for _, v := range values {
		diff := v - avg
		sumSqDiff += diff * diff
	}
	stdDev := math.Sqrt(sumSqDiff / float64(len(values)))
	cv := stdDev / math.Abs(avg)

	// Convert CV to confidence: low CV → high confidence.
	// CV of 0 → confidence 1.0, CV of 1.0 → confidence 0.5.
	confidence := 1.0 - (cv * 0.5)
	if confidence < 0.3 {
		confidence = 0.3
	}
	if confidence > 0.95 {
		confidence = 0.95
	}

	return confidence
}

// sortPredictions sorts by time to impact (most urgent first).
func sortPredictions(predictions []Prediction) {
	for i := 1; i < len(predictions); i++ {
		for j := i; j > 0 && predictions[j].TimeToImpact < predictions[j-1].TimeToImpact; j-- {
			predictions[j], predictions[j-1] = predictions[j-1], predictions[j]
		}
	}
}
