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

{{/* Validate enumerated values early with clear messages. */}}
{{- define "ratatoskr.validate" -}}
{{- if not (has .Values.driver (list "init" "agent")) -}}
{{- fail (printf "driver must be \"init\" or \"agent\", got %q" .Values.driver) -}}
{{- end -}}
{{- if not (has .Values.datapath (list "iproute" "ebpf")) -}}
{{- fail (printf "datapath must be \"iproute\" or \"ebpf\", got %q" .Values.datapath) -}}
{{- end -}}
{{- end -}}
