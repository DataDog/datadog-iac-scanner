package Cx

import data.generic.ansible as ansLib

canonical := "iam_password_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	pwPolicy := task[variant]
	ansLib.checkState(pwPolicy)

	searchKey := checkAllowPass(pwPolicy)
	searchKey != "none"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(pwPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}%s", [task.name, variant, searchKey]),
		"issueType": issueType(searchKey),
		"keyExpectedValue": "iam_password_policy should have the property 'allow_pw_change/allow_password_change' true",
		"keyActualValue": "iam_password_policy has the property 'allow_pw_change/allow_password_change' undefined or false",
	}
}

issueType(str) = "MissingAttribute" {
	str == ""
} else = "IncorrectValue" {
	true
}

checkAllowPass(pwPolicy) = ".allow_pw_change" {
	ansLib.isAnsibleFalse(pwPolicy.allow_pw_change)
} else = ".allow_password_change" {
	ansLib.isAnsibleFalse(pwPolicy.allow_password_change)
} else = "" {
	not pwPolicy.allow_pw_change
	not pwPolicy.allow_password_change
} else = "none" {
	true
}
