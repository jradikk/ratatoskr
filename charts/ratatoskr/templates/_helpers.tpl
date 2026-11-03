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
{{- if not (has .Values.datapath (list "iproute" "ebpf")) -}}
{{- fail (printf "datapath must be iproute or ebpf, got %q" .Values.datapath) -}}
{{- end -}}
{{- if and (not .Values.metrics.enabled) (or .Values.metrics.serviceMonitor.enabled .Values.metrics.podMonitor.enabled) -}}
{{- fail "metrics monitors require metrics.enabled=true" -}}
{{- end -}}
{{- if and .Values.metrics.dashboard.enabled (or (contains "/" .Values.metrics.dashboard.sidecarLabel) (contains " " .Values.metrics.dashboard.sidecarLabel)) -}}
{{- fail "metrics.dashboard.sidecarLabel must be a simple Kubernetes label name" -}}
{{- end -}}
{{- if and .Values.metrics.enabled (or (not (kindIs "map" .Values.metrics.ingress.namespaceSelector)) (not (kindIs "map" .Values.metrics.ingress.podSelector))) -}}
{{- fail "metrics.ingress namespaceSelector and podSelector must be Kubernetes label selector objects (use {} for unrestricted)" -}}
{{- end -}}
{{- if and .Values.operatorNamespace (ne .Values.operatorNamespace .Release.Namespace) -}}
{{- fail "operatorNamespace must match the Helm release namespace (webhook Service and TLS bootstrap use .Release.Namespace)" -}}
{{- end -}}
{{- if or (lt (int .Values.controller.replicas) 1) (lt (int .Values.webhook.replicas) 1) -}}
{{- fail "controller.replicas and webhook.replicas must both be at least 1" -}}
{{- end -}}
{{- if and (gt (int .Values.controller.replicas) 1) (not .Values.controller.leaderElection.enabled) -}}
{{- fail "controller.replicas > 1 requires controller.leaderElection.enabled=true to prevent concurrent reconciliation" -}}
{{- end -}}
{{- end -}}

{{- define "ratatoskr.selectorLabels" -}}
app.kubernetes.io/name: ratatoskr
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}
