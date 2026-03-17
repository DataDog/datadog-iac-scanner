package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront := task[variant]

	ansLib.checkState(cloudfront)
	certificate := cloudfront.viewer_certificate.cloudfront_default_certificate
	ansLib.isAnsibleTrue(certificate)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.viewer_certificate.cloudfront_default_certificate", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "Attribute 'cloudfront_default_certificate' should be 'false' or not defined",
		"keyActualValue": "Attribute 'cloudfront_default_certificate' is 'true'",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], ["viewer_certificate", "cloudfront_default_certificate"]),
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront := task[variant]

	ansLib.checkState(cloudfront)
	hasCustomConfig(cloudfront.viewer_certificate)

	attributes := {"ssl_support_method", "minimum_protocol_version"}
	attr := attributes[a]
	not common_lib.valid_key(cloudfront.viewer_certificate, attr)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.viewer_certificate", [task.name, variant]),
		"searchValue": attr,
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("Attribute %s should be defined when one of 'acm_certificate_arn' or 'iam_certificate_id' is declared.", [attr]),
		"keyActualValue": sprintf("Attribute '%s' is not defined", [attr]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant], ["viewer_certificate"]),
	}
}

hasCustomConfig(viewer_certificate) {
	common_lib.valid_key(viewer_certificate, "acm_certificate_arn")
}

hasCustomConfig(viewer_certificate) {
	common_lib.valid_key(viewer_certificate, "iam_certificate_id")
}
