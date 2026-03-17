package Cx

import data.generic.ansible as ansLib

canonical := "cloudfront_distribution"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cloudfront_distribution := task[variant]
	ansLib.checkState(cloudfront_distribution)

	ansLib.isAnsibleFalse(cloudfront_distribution.viewer_certificate.cloudfront_default_certificate)
	not checkMinPortocolVersion(cloudfront_distribution.viewer_certificate.minimum_protocol_version)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cloudfront_distribution, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.viewer_certificate.minimum_protocol_version", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "cloudfront_distribution.viewer_certificate.minimum_protocol_version should be TLSv1.1 or TLSv1.2",
		"keyActualValue": "cloudfront_distribution.viewer_certificate.minimum_protocol_version isn't TLSv1.1 or TLSv1.2",
	}
}

checkMinPortocolVersion("TLSv1.1") = true

checkMinPortocolVersion("TLSv1.2") = true
