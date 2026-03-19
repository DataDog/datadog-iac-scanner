package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "acm_certificate"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	acm := task[variant]
	ansLib.checkState(acm)

	expiration_date := acm.certificate.expiration_date
	common_lib.expired(expiration_date)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(acm, canonical, task),
		"searchKey": sprintf("name={{%s}}.%s.certificate", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'community.aws.aws_acm.certificate' should not have expired",
		"keyActualValue": "'community.aws.aws_acm.certificate' has expired",
	}
}
