package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# ec2_instance whose vpc_subnet_id references a subnet in default VPC
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	inst := task[variant]
	ansLib.checkState(inst)

	common_lib.valid_key(inst, "vpc_subnet_id")
	subnetNameUnclean := split(inst.vpc_subnet_id, ".")[0]
	subnetNameHalfClean := replace(subnetNameUnclean, " ", "")
	subnetNameClean := replace(subnetNameHalfClean, "{{", "")

	sbs := ansLib.get_variants("ec2_vpc_subnet")
	tk := ansLib.tasks[_][_]
	sb := tk[sbs[_]]
	ansLib.checkState(sb)

	tk.register == subnetNameClean

	contains(lower(sb.vpc_id), "default")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(inst, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.vpc_subnet_id", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'vpc_subnet_id' should not be associated with a default VPC",
		"keyActualValue":  "'vpc_subnet_id' is associated with a default VPC",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant, "vpc_subnet_id"], []),
	}
}
