{{- define "portal.name" -}}
{{- printf "ap-%s-%s" (.Release.Name | trunc 10 | trimSuffix "-") (printf "%s/%s" .Release.Namespace .Release.Name | sha256sum | trunc 8) -}}
{{- end -}}
{{- define "portal.sa" -}}{{ default (include "portal.name" .) .Values.serviceAccount.name }}{{- end -}}
{{- define "portal.secret" -}}{{ default (printf "%s-security" (include "portal.name" .)) .Values.secrets.existingSecret }}{{- end -}}
{{- define "portal.labels" -}}
app.kubernetes.io/name: agentgateway-access-portal
app.kubernetes.io/instance: {{ .Release.Name | quote }}
accessportal.io/instance: {{ include "portal.name" . | quote }}
{{- end -}}
