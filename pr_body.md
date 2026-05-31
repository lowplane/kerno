fixes #29

added built-in webhook sinks for `kerno doctor` findings. wired up the `--sink`, `--severity-floor`, and `--sink-dedupe` flags.

what's included:
- `Sink` interface with exponential backoff retries on 5xx errors
- in-memory deduplicator to prevent flapping rules from spamming on-call
- slack integration using block kit format for clean readability
- pagerduty integration via events api v2. handles trigger events and automatically sends a resolve event when a finding clears in continuous mode
- discord integration utilizing discord's native slack-compat url suffix
- `kerno_sinks_deduped_total` and `kerno_sinks_failed_total` metrics
- full test suite using `httptest.Server`

all env vars like `KERNO_SLACK_WEBHOOK_URL` are expanded automatically if passed as flag values to keep shell history clean.

let me know if anything needs tweaks.
