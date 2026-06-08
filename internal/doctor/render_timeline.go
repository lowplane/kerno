// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// jsonTimeline represents the timeline node structure in the JSON report.
type jsonTimeline struct {
	ID     string              `json:"id"`
	Events []jsonTimelineEvent `json:"events"`
	Links  []jsonCausalLink    `json:"links"`
}

// jsonTimelineEvent represents one finding node in the JSON timeline.
type jsonTimelineEvent struct {
	Rule     string    `json:"rule"`
	Signal   string    `json:"signal"`
	FiredAt  time.Time `json:"firedAt"`
	Title    string    `json:"title"`
	Evidence string    `json:"evidence"`
}

// jsonCausalLink represents a causation arrow in the JSON timeline.
type jsonCausalLink struct {
	Cause      string  `json:"cause"`
	Effect     string  `json:"effect"`
	Confidence float64 `json:"confidence"`
	GapMs      int64   `json:"gap_ms"`
}

// renderTimeline prints the timeline structured as a causal box-tree.
func (r *PrettyRenderer) renderTimeline(w io.Writer, tl *Timeline, p palette) {
	if tl == nil || len(tl.Events) == 0 {
		return
	}

	// 1. Find connected components (chains)
	adj := make(map[int][]int)
	for _, link := range tl.Links {
		causeIdx := -1
		effectIdx := -1
		for idx, ev := range tl.Events {
			if ev.FindingRule == link.CauseRule && causeIdx == -1 {
				causeIdx = idx
			}
			if ev.FindingRule == link.EffectRule && effectIdx == -1 {
				effectIdx = idx
			}
		}
		if causeIdx != -1 && effectIdx != -1 {
			adj[causeIdx] = append(adj[causeIdx], effectIdx)
			adj[effectIdx] = append(adj[effectIdx], causeIdx)
		}
	}

	visited := make([]bool, len(tl.Events))
	var components [][]int

	for i := 0; i < len(tl.Events); i++ {
		if visited[i] {
			continue
		}
		var comp []int
		queue := []int{i}
		visited[i] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			comp = append(comp, curr)

			for _, neighbor := range adj[curr] {
				if !visited[neighbor] {
					visited[neighbor] = true
					queue = append(queue, neighbor)
				}
			}
		}
		sort.Ints(comp)
		components = append(components, comp)
	}

	// Sort components by their first event's FiredAt so the chains are rendered in temporal order.
	sort.Slice(components, func(i, j int) bool {
		tI := tl.Events[components[i][0]].FiredAt
		tJ := tl.Events[components[j][0]].FiredAt
		if tI.Equal(tJ) {
			return tl.Events[components[i][0]].FindingRule < tl.Events[components[j][0]].FindingRule
		}
		return tI.Before(tJ)
	})

	// 2. Render box header
	title := "╔═══ CAUSAL TIMELINE "
	titleLen := utf8.RuneCountInString(title)
	headerLine := title + strings.Repeat("═", prBoxWidth-titleLen-1) + "╗"
	fmt.Fprintf(w, "%s%s%s\n", p.dim, headerLine, p.reset)

	// Helper to print a line padded to fit the box
	renderBoxLine := func(w io.Writer, content string, contentVisibleLen int) {
		pad := (prBoxWidth - 6) - contentVisibleLen
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintf(w, "%s║  %s%s  ║%s\n", p.dim, content, strings.Repeat(" ", pad), p.reset)
	}

	// 3. Render each component (chain)
	for compIdx, comp := range components {
		if compIdx > 0 {
			// Print a blank box line between parallel chains
			renderBoxLine(w, "", 0)
		}

		for k := 0; k < len(comp); k++ {
			ev := tl.Events[comp[k]]
			timeStr := ev.FiredAt.Format("15:04:05.000")
			timePart := fmt.Sprintf("[%s]", timeStr)
			sevPart := ev.Severity.Icon()
			titlePart := ev.Title

			var sevColor string
			switch ev.Severity {
			case SeverityCritical:
				sevColor = p.red
			case SeverityWarning:
				sevColor = p.yellow
			case SeverityInfo:
				sevColor = p.blue
			default:
				sevColor = p.gray
			}

			// Format: [14:32:01.000] CRIT  Disk I/O Bottleneck Detected
			content := fmt.Sprintf("%s%s%s %s%s%s%s  %s%s%s",
				p.gray, timePart, p.reset,
				sevColor, p.bold, sevPart, p.reset,
				p.bold, titlePart, p.reset,
			)
			visibleLen := len(timePart) + 1 + len(sevPart) + 2 + utf8.RuneCountInString(titlePart)
			renderBoxLine(w, content, visibleLen)

			// If not the last event in this chain, check if there is a link to the next event in the chain.
			if k < len(comp)-1 {
				nextEv := tl.Events[comp[k+1]]
				// Find link from current event to next event.
				var matchLink *CausalLink
				for _, l := range tl.Links {
					if l.CauseRule == ev.FindingRule && l.EffectRule == nextEv.FindingRule {
						matchLink = &l
						break
					}
				}

				if matchLink != nil {
					// Format link details
					gapSec := float64(matchLink.GapMs) / 1000.0
					gapStr := fmt.Sprintf("%.1fs", gapSec)
					if float64(int(gapSec)) == gapSec {
						gapStr = fmt.Sprintf("%.0fs", gapSec)
					}
					confStr := fmt.Sprintf("%.0f%%", matchLink.Confidence*100)

					arrowPart := p.gray + "│" + p.reset
					arrowHead := p.gray + "▼" + p.reset
					signalPart := p.cyan + matchLink.CauseSignal + p.reset + p.gray + " → " + p.reset + p.cyan + matchLink.EffectSignal + p.reset
					gapConfPart := p.gray + fmt.Sprintf("(%s gap, %s confidence)", gapStr, confStr) + p.reset

					line1Content := fmt.Sprintf("       %s  %s  %s", arrowPart, signalPart, gapConfPart)
					line1VisLen := 7 + 1 + 2 + len(matchLink.CauseSignal) + 3 + len(matchLink.EffectSignal) + 2 + (len(gapStr) + 22 + len(confStr))

					line2Content := fmt.Sprintf("       %s", arrowHead)
					line2VisLen := 7 + 1

					renderBoxLine(w, line1Content, line1VisLen)
					renderBoxLine(w, line2Content, line2VisLen)
				}
			}
		}
	}

	// 4. Render box footer
	bottomLine := "╚" + strings.Repeat("═", prBoxWidth-2) + "╝"
	fmt.Fprintf(w, "%s%s%s\n", p.dim, bottomLine, p.reset)

	// 5. Render root signal + timeline ID info line
	var rootSignals []string
	for _, comp := range components {
		if len(comp) > 0 {
			sig := tl.Events[comp[0]].Signal
			found := false
			for _, s := range rootSignals {
				if s == sig {
					found = true
					break
				}
			}
			if !found {
				rootSignals = append(rootSignals, sig)
			}
		}
	}
	rootSigStr := strings.Join(rootSignals, ", ")

	fmt.Fprintf(w, "  %sRoot signal:%s %s   %sTimeline ID:%s %s%s%s\n\n",
		p.gray, p.reset, rootSigStr,
		p.gray, p.reset, p.cyan, tl.ID, p.reset,
	)
}
