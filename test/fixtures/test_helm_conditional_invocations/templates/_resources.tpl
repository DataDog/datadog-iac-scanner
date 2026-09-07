{{- define "resource.a" -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-a
{{- end -}}

{{- define "resource.b" -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-b
{{- end -}}
