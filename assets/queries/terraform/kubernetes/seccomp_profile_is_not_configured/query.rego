package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

resources := {"kubernetes_cron_job", "kubernetes_pod"}

is_secure_seccomp_type(profile_type) {
	profile_type == "RuntimeDefault"
}

is_secure_seccomp_type(profile_type) {
	profile_type == "Localhost"
}

# Returns true when spec.security_context.seccomp_profile.type is defined
has_pod_seccomp_defined(spec) {
	spec.security_context.seccomp_profile.type
}

#######################################
# seccomp_profile checks (v1.19+)
#######################################

# kubernetes_pod: seccomp_profile.type is insecure
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	profile_type := resource.spec.security_context.seccomp_profile.type
	not is_secure_seccomp_type(profile_type)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_pod",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_pod[%s].spec.security_context.seccomp_profile.type", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("kubernetes_pod[%s].spec.security_context.seccomp_profile.type should be 'RuntimeDefault' or 'Localhost'", [name]),
		"keyActualValue": sprintf("kubernetes_pod[%s].spec.security_context.seccomp_profile.type is '%s'", [name, profile_type]),
		"searchLine": common_lib.build_search_line(["resource", "kubernetes_pod", name], ["spec", "security_context", "seccomp_profile", "type"]),
	}
}

# kubernetes_cron_job: seccomp_profile.type is insecure
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	profile_type := resource.spec.job_template.spec.template.spec.security_context.seccomp_profile.type
	not is_secure_seccomp_type(profile_type)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_cron_job",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.security_context.seccomp_profile.type", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.security_context.seccomp_profile.type should be 'RuntimeDefault' or 'Localhost'", [name]),
		"keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.spec.security_context.seccomp_profile.type is '%s'", [name, profile_type]),
		"searchLine": common_lib.build_search_line(["resource", "kubernetes_cron_job", name], ["spec", "job_template", "spec", "template", "spec", "security_context", "seccomp_profile", "type"]),
	}
}

# general (deployment, etc.): seccomp_profile.type is insecure
CxPolicy[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	profile_type := resource[name].spec.template.spec.security_context.seccomp_profile.type
	not is_secure_seccomp_type(profile_type)

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].spec.template.spec.security_context.seccomp_profile.type", [resourceType, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].spec.template.spec.security_context.seccomp_profile.type should be 'RuntimeDefault' or 'Localhost'", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].spec.template.spec.security_context.seccomp_profile.type is '%s'", [resourceType, name, profile_type]),
		"searchLine": common_lib.build_search_line(["resource", resourceType, name], ["spec", "template", "spec", "security_context", "seccomp_profile", "type"]),
	}
}

#######################################
# Legacy annotation checks (pre-v1.19)
# Only fire when seccomp_profile.type is not defined
#######################################

# kubernetes_pod: no annotations
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	not has_pod_seccomp_defined(resource.spec)

	metadata := resource.metadata
	not common_lib.valid_key(metadata, "annotations")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_pod",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_pod[%s].metadata", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations should be set", [name]),
		"keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations is undefined", [name]),
	}
}

# kubernetes_pod: annotations present, seccomp annotation missing
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	not has_pod_seccomp_defined(resource.spec)

	metadata := resource.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	not common_lib.valid_key(annotations, "seccomp.security.alpha.kubernetes.io/defaultProfileName")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_pod",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_pod[%s].metadata.annotations", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName should be set", [name]),
		"keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is undefined", [name]),
	}
}

# kubernetes_pod: seccomp annotation wrong value
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_pod[name]
	not has_pod_seccomp_defined(resource.spec)

	metadata := resource.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "seccomp.security.alpha.kubernetes.io/defaultProfileName")
	seccomp := annotations["seccomp.security.alpha.kubernetes.io/defaultProfileName"]
	seccomp != "runtime/default"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_pod",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_pod[%s].metadata.annotations", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is 'runtime/default'", [name]),
		"keyActualValue": sprintf("kubernetes_pod[%s].metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is '%s'", [name, seccomp]),
	}
}

# kubernetes_cron_job: no annotations
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	not has_pod_seccomp_defined(resource.spec.job_template.spec.template.spec)

	metadata := resource.spec.job_template.spec.template.metadata
	not common_lib.valid_key(metadata, "annotations")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_cron_job",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations should be set", [name]),
		"keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations is undefined", [name]),
	}
}

# kubernetes_cron_job: annotations present, seccomp annotation missing
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	not has_pod_seccomp_defined(resource.spec.job_template.spec.template.spec)

	metadata := resource.spec.job_template.spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	not common_lib.valid_key(annotations, "seccomp.security.alpha.kubernetes.io/defaultProfileName")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_cron_job",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName should be set", [name]),
		"keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is undefined", [name]),
	}
}

# kubernetes_cron_job: seccomp annotation wrong value
CxPolicy[result] {
	resource := input.document[i].resource.kubernetes_cron_job[name]
	not has_pod_seccomp_defined(resource.spec.job_template.spec.template.spec)

	metadata := resource.spec.job_template.spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "seccomp.security.alpha.kubernetes.io/defaultProfileName")
	seccomp := annotations["seccomp.security.alpha.kubernetes.io/defaultProfileName"]
	seccomp != "runtime/default"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "kubernetes_cron_job",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is 'runtime/default'", [name]),
		"keyActualValue": sprintf("kubernetes_cron_job[%s].spec.job_template.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is '%s'", [name, seccomp]),
	}
}

# general: no annotations
CxPolicy[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	not has_pod_seccomp_defined(resource[name].spec.template.spec)

	metadata := resource[name].spec.template.metadata
	not common_lib.valid_key(metadata, "annotations")

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].spec.template.metadata", [resourceType, name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s[%s].spec.template.metadata.annotations should be set", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].spec.template.metadata.annotations is undefined", [resourceType, name]),
	}
}

# general: annotations present, seccomp annotation missing
CxPolicy[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	not has_pod_seccomp_defined(resource[name].spec.template.spec)

	metadata := resource[name].spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	not common_lib.valid_key(annotations, "seccomp.security.alpha.kubernetes.io/defaultProfileName")

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].spec.template.metadata.annotations", [resourceType, name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName should be set", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is undefined", [resourceType, name]),
	}
}

# general: seccomp annotation wrong value
CxPolicy[result] {
	resource := input.document[i].resource[resourceType]
	resourceType != resources[x]
	not has_pod_seccomp_defined(resource[name].spec.template.spec)

	metadata := resource[name].spec.template.metadata
	common_lib.valid_key(metadata, "annotations")
	annotations := metadata.annotations
	common_lib.valid_key(annotations, "seccomp.security.alpha.kubernetes.io/defaultProfileName")
	seccomp := annotations["seccomp.security.alpha.kubernetes.io/defaultProfileName"]
	seccomp != "runtime/default"

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType,
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].spec.template.metadata.annotations", [resourceType, name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is 'runtime/default'", [resourceType, name]),
		"keyActualValue": sprintf("%s[%s].spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName is '%s'", [resourceType, name, seccomp]),
	}
}
