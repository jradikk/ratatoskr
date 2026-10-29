{{/* Common labels. */}}
{{- define "ratatoskr.labels" -}}
app.kubernetes.io/name: ratatoskr
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* image renders "<registry>/ratatoskr-<component>:<tag>". */}}
{{- define "ratatoskr.image" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- printf "%s/ratatoskr-%s:%s" $root.Values.image.registry $component (default $root.Chart.AppVersion $root.Values.image.tag) -}}
{{- end -}}

{{/* Fail closed on modes that do not have an implementation. */}}
{{- define "ratatoskr.validate" -}}
{{- if not (has .Values.driver (list "init" "agent")) -}}
{{- fail (printf "driver must be init or agent, got %q" .Values.driver) -}}
{{- end -}}
{{- if ne .Values.datapath "iproute" -}}
{{- fail (printf "M5 only implements datapath=iproute (ebpf is not available); got %q" .Values.datapath) -}}
{{- end -}}
{{- if and .Values.operatorNamespace (ne .Values.operatorNamespace .Release.Namespace) -}}
{{- fail "operatorNamespace must match the Helm release namespace (webhook Service and TLS bootstrap use .Release.Namespace)" -}}
{{- end -}}
{{- end -}}

{{- define "ratatoskr.selectorLabels" -}}
app.kubernetes.io/name: ratatoskr
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}
