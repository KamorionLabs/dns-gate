{{- define "eurodns-gate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "eurodns-gate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "eurodns-gate.labels" -}}
app.kubernetes.io/name: {{ include "eurodns-gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "eurodns-gate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "eurodns-gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "eurodns-gate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "eurodns-gate.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "eurodns-gate.storeType" -}}
{{- (.Values.config.store | default dict).type | default "memory" -}}
{{- end -}}

{{- define "eurodns-gate.validate" -}}
{{- $store := include "eurodns-gate.storeType" . -}}
{{- if and (has $store (list "memory" "sqlite")) (gt (int .Values.replicaCount) 1) -}}
{{- fail (printf "store %q supports a single replica only (replicaCount=%d): use postgres or dynamodb" $store (int .Values.replicaCount)) -}}
{{- end -}}
{{- if not .Values.eurodns.existingSecret -}}
{{- fail "eurodns.existingSecret is required (EuroDNS API key)" -}}
{{- end -}}
{{- if and (eq $store "postgres") (not .Values.postgres.existingSecret) -}}
{{- fail "postgres.existingSecret is required with store.type=postgres" -}}
{{- end -}}
{{- if and ((.Values.config.ui | default dict).enabled) (not .Values.ui.existingSecret) -}}
{{- fail "ui.existingSecret is required when config.ui.enabled" -}}
{{- end -}}
{{- end -}}
