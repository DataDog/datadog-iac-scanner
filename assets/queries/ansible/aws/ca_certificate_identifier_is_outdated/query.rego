package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "rds_instance"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	not common_lib.valid_key(rds_instance, "ca_certificate_identifier")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "rds_instance.ca_certificate_identifier should be defined",
		"keyActualValue": "rds_instance.ca_certificate_identifier is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	rds_instance := task[variant]
	ansLib.checkState(rds_instance)

	rds_instance.ca_certificate_identifier != "rds-ca-2019"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(rds_instance, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.ca_certificate_identifier", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "rds_instance.ca_certificate_identifier should equal to 'rds-ca-2019'",
		"keyActualValue": "rds_instance.ca_certificate_identifier is not equal to 'rds-ca-2019'",
	}
}
