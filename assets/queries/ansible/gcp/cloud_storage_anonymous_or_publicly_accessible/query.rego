package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_storage_bucket"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	not common_lib.valid_key(bucket, "acl")
	not common_lib.valid_key(bucket, "default_object_acl")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_storage_bucket.default_object_acl should be defined",
		"keyActualValue": "gcp_storage_bucket.default_object_acl is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	check(bucket.acl.entity)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.acl.entity", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_storage_bucket.acl.entity should not be 'allUsers' or 'allAuthenticatedUsers'",
		"keyActualValue": "gcp_storage_bucket.acl.entity is 'allUsers' or 'allAuthenticatedUsers'",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	bucket := task[variant]
	ansLib.checkState(bucket)

	not common_lib.valid_key(bucket, "acl")
	check(bucket.default_object_acl.entity)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(bucket, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.default_object_acl.entity", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_storage_bucket.default_object_acl.entity should not be 'allUsers' or 'allAuthenticatedUsers'",
		"keyActualValue": "gcp_storage_bucket.default_object_acl.entity is 'allUsers' or 'allAuthenticatedUsers'",
	}
}

check(entity) {
	is_string(entity)
	lower(entity) == "allusers"
}

check(entity) {
	is_string(entity)
	lower(entity) == "allauthenticatedusers"
}
