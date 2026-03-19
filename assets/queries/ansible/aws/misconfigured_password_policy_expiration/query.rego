package Cx

import data.generic.ansible as ansLib

canonical := "iam_password_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	pwPolicy := task[variant]
	ansLib.checkState(pwPolicy)

	searchKey := checkPwMaxAge(pwPolicy)
	searchKey != "none"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(pwPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}%s", [task.name, variant, searchKey]),
		"issueType": issueType(searchKey),
		"keyExpectedValue": "iam_password_policy should have the property 'pw_max_age/password_max_age' lower than 90",
		"keyActualValue": "iam_password_policy has the property 'pw_max_age/password_max_age' unassigned or greater than 90",
	}
}

issueType(str) = "MissingAttribute" {
	str == ""
} else = "IncorrectValue" {
	true
}

checkPwMaxAge(pwPolicy) = ".pw_max_age" {
	pwPolicy.pw_max_age > 90
} else = ".password_max_age" {
	pwPolicy.password_max_age > 90
} else = "" {
	not pwPolicy.pw_max_age
	not pwPolicy.password_max_age
} else = "none" {
	true
}
