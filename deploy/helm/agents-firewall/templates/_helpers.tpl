{{/* Chart name. */}}
{{- define "afw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "afw.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "afw.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "afw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agents-firewall
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Selector labels for a component: include "afw.selector" (dict "ctx" . "component" "api") */}}
{{- define "afw.selector" -}}
app.kubernetes.io/name: {{ include "afw.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "afw.image" -}}
{{- printf "%s:%s" .repository (toString .tag) -}}
{{- end -}}

{{/* Name of the secret holding data-key / database-url / bootstrap-admin-token. */}}
{{- define "afw.secretName" -}}
{{- default (printf "%s-secrets" (include "afw.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "afw.postgresHost" -}}
{{- printf "%s-postgres" (include "afw.fullname" .) -}}
{{- end -}}

{{/* Keep a generated value across upgrades: include "afw.persisted" (dict "ctx" . "key" "data-key" "value" "" "gen" "...") */}}
{{- define "afw.persisted" -}}
{{- $existing := lookup "v1" "Secret" .ctx.Release.Namespace (printf "%s-secrets" (include "afw.fullname" .ctx)) -}}
{{- if .value -}}
{{- .value | b64enc -}}
{{- else if and $existing (index $existing.data .key) -}}
{{- index $existing.data .key -}}
{{- else -}}
{{- .gen | b64enc -}}
{{- end -}}
{{- end -}}

{{/* In-cluster gateway endpoint of the control plane. */}}
{{- define "afw.gatewayEndpoint" -}}
{{- if .Values.gateway.consoleUrl -}}
{{- .Values.gateway.consoleUrl -}}
{{- else -}}
{{- printf "https://%s-api-gw.%s.svc:%v" (include "afw.fullname" .) .Release.Namespace .Values.api.gatewayService.port -}}
{{- end -}}
{{- end -}}
