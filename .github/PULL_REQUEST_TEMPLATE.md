<!--
Thanks for contributing to Kerno! A few notes:

- PR title must follow Conventional Commits: `feat(scope): subject` (linted in CI).
- Every commit must be DCO-signed (`git commit -s`).
- Squash merges are the default — your PR title becomes the merge commit.
- CI runs build + race tests + lint + (when configured) the kernel matrix.
-->

## What

<!-- 1–2 sentences. What does this PR change? -->

## Why

<!-- Link the issue. -->
Fixes #

## How

<!-- Notable design decisions, tradeoffs, or implementation notes. Keep it short. -->

## Testing

- [ ] `go build ./...` passes
- [ ] `go test ./...` passes
- [ ] `go vet ./...` passes
- [ ] `golangci-lint run ./...` passes
- [ ] Tested locally with: <!-- e.g. `sudo ./bin/kerno doctor --duration 5s` -->

<!-- Required for changes touching internal/bpf/, internal/collector/, internal/doctor/. -->

- [ ] N/A — pure docs/refactor
- [ ] `sudo ./bin/bpf-verify --read 5s` confirms 6/6 programs still load
- [ ] `./scripts/verify.sh` passes (or specific phase: `./scripts/verify.sh quality`)

## Checklist

- [ ] PR title follows Conventional Commits (`feat(scope): subject`)
- [ ] All commits are DCO-signed (`git commit -s`)
- [ ] No unrelated changes pulled in
- [ ] Documentation updated where user-visible behavior changed
- [ ] Added/updated tests for new code paths
- [ ] If a new doctor rule, paired with a chaos scenario in `scripts/verify.sh`
