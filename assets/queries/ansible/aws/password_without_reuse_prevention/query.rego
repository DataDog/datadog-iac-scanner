package Cx

import data.generic.ansible as ansLib

canonical := "iam_password_policy"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	pwPolicy := task[variant]
	ansLib.checkState(pwPolicy)

	searchKey := checkPwReusePrevent(pwPolicy)
	searchKey != "none"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(pwPolicy, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}%s", [task.name, variant, searchKey]),
		"issueType": issueType(searchKey),
		"keyExpectedValue": "iam_password_policy should have the property 'password_reuse_prevent' greater than 0",
		"keyActualValue": "iam_password_policy has the property 'password_reuse_prevent' unassigned or assigned to 0",
	}
}

issueType(str) = "MissingAttribute" {
	str == ""
} else = "IncorrectValue" {
	true
}

checkPwReusePrevent(pwPolicy) = ".password_reuse_prevent" {
	pwPolicy.password_reuse_prevent == 0
} else = ".pw_reuse_prevent" {
	pwPolicy.pw_reuse_prevent == 0
} else = ".prevent_reuse" {
	pwPolicy.prevent_reuse == 0
} else = "" {
	not pwPolicy.password_reuse_prevent
	not pwPolicy.pw_reuse_prevent
	not pwPolicy.prevent_reuse
} else = "none" {
	true
}
