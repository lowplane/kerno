// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"github.com/optiqor/kerno/internal/doctor"
)

// mockAnalysisResponse builds a doctor.AnalysisResponse for cache tests.
// Lives in its own file because the doctor import is only needed by tests.
func mockAnalysisResponse(summary string) *doctor.AnalysisResponse {
	return &doctor.AnalysisResponse{Summary: summary}
}
