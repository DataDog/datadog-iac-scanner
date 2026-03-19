package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

canonical_rds := "rds_instance"
canonical_sg := "rds_subnet_group"
canonical_subnet := "ec2_vpc_subnet"

options := {"db_subnet_group_name", "subnet_group"}

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant_rds := ans_lib.get_variants(canonical_rds)[_]
	rds_instance := task[variant_rds]
	ans_lib.checkState(rds_instance)

	# get subnet group name (RDS can use either key)
	subnetGroupName := rds_instance[options[o]]

	# get subnet group task
	tk := ans_lib.tasks[_][_]
	variant_sg := ans_lib.get_variants(canonical_sg)[_]
	sg := tk[variant_sg]
	ans_lib.checkState(sg)
	sg.name == subnetGroupName

	# get subnets info
	subnets := sg.subnets

	# verify if some subnet is public
	is_public(subnets)

	result := {
		"documentId": id,
		"resourceType": canonical_rds,
		"resourceName": ans_lib.get_resource_name(rds_instance, canonical_rds, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.%s", [task.name, variant_rds, options[o]]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "RDS should not be running in a public subnet",
		"keyActualValue": "RDS is running in a public subnet",
		"searchLine": common_lib.build_search_line(["playbooks", t, variant_rds, options[o]], []),
	}
}

unrestricted_cidr(sb) {
	sb.cidr == "0.0.0.0/0"
} else {
	sb.ipv6_cidr == "::/0"
}

is_public(subnets) {
	subnet := subnets[_]
	subnetNameUnclean := split(subnet, ".")[0]
	subnetNameHalfClean := replace(subnetNameUnclean, " ", "")
	subnetNameClean := replace(subnetNameHalfClean, "{{", "")

	tk := ans_lib.tasks[_][_]
	variant_subnet := ans_lib.get_variants(canonical_subnet)[_]
	sb := tk[variant_subnet]
	ans_lib.checkState(sb)

	tk.register == subnetNameClean
	unrestricted_cidr(sb)
}
