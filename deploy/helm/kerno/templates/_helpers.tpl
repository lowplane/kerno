{{/*
Common labels applied to every resource.
Follows the Kubernetes recommended label set:
  https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
*/}}
{{- define "kerno.labels" -}}
app.kubernetes.io/name: kerno
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Selector labels — the minimal stable set used by the DaemonSet selector and
the Service. Must not include version or chart labels (those change on upgrade
and would break rolling updates).
*/}}
{{- define "kerno.selectorLabels" -}}
app.kubernetes.io/name: kerno
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Full image reference.

Priority:
  1. values.image.tag (explicit override — use for pinned production deploys)
  2. Chart.AppVersion (set in Chart.yaml — matches the release tag)

Example outputs:
  ghcr.io/optiqor/kerno:v0.2.0        (tag set in values)
  ghcr.io/optiqor/kerno:0.1.0         (tag falls back to Chart.AppVersion)
*/}}
{{- define "kerno.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Validate required values at render time so users get a clear error message
instead of a cryptic Kubernetes admission failure.

Usage: add {{ include "kerno.validateValues" . }} at the top of any template.
*/}}
{{- define "kerno.validateValues" -}}
{{- if not .Values.image.repository -}}
  {{- fail "values.image.repository must not be empty" -}}
{{- end -}}
{{- if and .Values.serviceMonitor.enabled (gt (int (trimSuffix "s" .Values.serviceMonitor.scrapeTimeout)) (int (trimSuffix "s" .Values.serviceMonitor.interval))) -}}
  {{- fail "values.serviceMonitor.scrapeTimeout must be less than values.serviceMonitor.interval" -}}
{{- end -}}
{{- end }}

