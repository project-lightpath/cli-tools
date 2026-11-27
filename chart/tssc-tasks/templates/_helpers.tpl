{{/* The tssc tools image reference. When a digest is set it wins over the
     tag: a tag is a moving reference, and a TaskRun resolving it can get a
     different image than a previous run of the same pipeline used. */}}
{{- define "tssc-tasks.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}
