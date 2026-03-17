package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "gcp_kms_crypto_key"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cryptoKey := task[variant]
	ansLib.checkState(cryptoKey)

	not common_lib.valid_key(cryptoKey, "rotation_period")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cryptoKey, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "gcp_kms_crypto_key.rotation_period should be defined with a value less or equal to 7776000",
		"keyActualValue": "gcp_kms_crypto_key.rotation_period is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	cryptoKey := task[variant]
	ansLib.checkState(cryptoKey)

	rotationPeriod := substring(cryptoKey.rotation_period, 0, count(cryptoKey.rotation_period) - 1)
	to_number(rotationPeriod) > 7776000

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(cryptoKey, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.rotation_period", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "gcp_kms_crypto_key.rotation_period should be less or equal to 7776000",
		"keyActualValue": "gcp_kms_crypto_key.rotation_period exceeds 7776000",
	}
}
