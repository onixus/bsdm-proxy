{{/*
Expand the name of the chart.
*/}}
{{- define "bsdm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "bsdm.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "bsdm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "bsdm.labels" -}}
helm.sh/chart: {{ include "bsdm.chart" . }}
{{ include "bsdm.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "bsdm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "bsdm.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "bsdm.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "bsdm.indexerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}-indexer
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: cache-indexer
{{- end }}
