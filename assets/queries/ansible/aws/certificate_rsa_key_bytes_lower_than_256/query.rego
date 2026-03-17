package Cx

import data.generic.ansible as ansLib

canonical := "acm_certificate"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	acm := task[variant]
	ansLib.checkState(acm)

	acm.certificate.rsa_key_bytes < 256

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(acm, canonical, task),
		"searchKey": sprintf("name={{%s}}.%s.certificate", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'community.aws.aws_acm.certificate' should use a RSA key with a length equal to or higher than 256 bytes",
		"keyActualValue": "'community.aws.aws_acm.certificate' does not use a RSA key with a length equal to or higher than 256 bytes",
	}
}
