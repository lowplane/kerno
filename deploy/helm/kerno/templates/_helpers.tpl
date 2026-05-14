{{/*
Common labels for all resources.
*/}}
{{- define "kerno.labels" -}}
app.kubernetes.io/name: kerno
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Selector labels for matching pods.
*/}}
{{- define "kerno.selectorLabels" -}}
app.kubernetes.io/name: kerno
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference with tag fallback.
*/}}
{{- define "kerno.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
