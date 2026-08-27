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

{{/*
ServiceAccount name. With serviceAccount.create=false and an empty name the
chart used to silently bind every pod to the namespace "default" SA, which in
many clusters carries inherited RoleBindings — the opposite of the intended
"no K8s API access". Refuse to guess instead.
*/}}
{{- define "bsdm.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "bsdm.fullname" .) .Values.serviceAccount.name }}
{{- else if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- fail "serviceAccount.create=false requires serviceAccount.name: set it to an existing ServiceAccount in the release namespace (the chart will not fall back to the namespace \"default\" ServiceAccount). Either set serviceAccount.name=<existing-sa> or leave serviceAccount.create=true." }}
{{- end }}
{{- end }}

{{/*
Container securityContext for a component: <component>.securityContext when the
operator set one, otherwise the chart-wide default. Call as
  {{ include "bsdm.containerSecurityContext" (dict "ctx" . "component" .Values.indexer) }}
so that relaxing one workload does not relax the other five.
*/}}
{{- define "bsdm.containerSecurityContext" -}}
{{- $override := dig "securityContext" nil (.component | default dict) -}}
{{- toYaml ($override | default .ctx.Values.securityContext) -}}
{{- end }}

{{/*
Pod-level securityContext, same override rule as above.
*/}}
{{- define "bsdm.podSecurityContext" -}}
{{- $override := dig "podSecurityContext" nil (.component | default dict) -}}
{{- toYaml ($override | default .ctx.Values.podSecurityContext) -}}
{{- end }}

{{/*
Egress rule allowing cluster DNS only (kube-dns / CoreDNS), instead of :53 to
0.0.0.0/0. Rendered at the caller's indentation.
*/}}
{{- define "bsdm.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.networkPolicy.dnsNamespace | default "kube-system" }}
      podSelector:
        matchLabels:
          {{- toYaml (.Values.networkPolicy.dnsPodSelector | default (dict "k8s-app" "kube-dns")) | nindent 10 }}
  ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
{{- end }}

{{- define "bsdm.indexerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}-indexer
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: cache-indexer
{{- end }}

{{- define "bsdm.alertWorkerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}-alert-worker
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: alert-worker
{{- end }}

{{- define "bsdm.mlWorkerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}-ml-worker
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ml-worker
{{- end }}

{{- define "bsdm.threatIntelSelectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}-threat-intel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: threat-intel
{{- end }}

{{- define "bsdm.dnsSinkholeSelectorLabels" -}}
app.kubernetes.io/name: {{ include "bsdm.name" . }}-dns-sinkhole
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: dns-sinkhole
{{- end }}

