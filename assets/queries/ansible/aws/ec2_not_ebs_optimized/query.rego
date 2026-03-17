package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

# ec2_instance missing ebs_optimized when instance type is not EBS-optimized by default
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	inst := task[variant]
	ansLib.checkState(inst)

	instanceType := get_instance_type(inst)
	not common_lib.is_aws_ebs_optimized_by_default(instanceType)
	not common_lib.valid_key(inst, "ebs_optimized")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(inst, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "ec2_instance to have ebs_optimized set to true.",
		"keyActualValue": "ec2_instance doesn't have ebs_optimized set to true.",
	}
}

# ec2_instance with ebs_optimized explicitly false
CxPolicy[result] {
	task := ansLib.tasks[id][t]
	canonical := "ec2_instance"
	variant := ansLib.get_variants(canonical)[_]
	inst := task[variant]
	ansLib.checkState(inst)

	instanceType := get_instance_type(inst)
	not common_lib.is_aws_ebs_optimized_by_default(instanceType)
	inst.ebs_optimized == false

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(inst, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.ebs_optimized", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ec2_instance to have ebs_optimized set to true.",
		"keyActualValue": "ec2_instance ebs_optimized is set to false.",
	}
}

# The default InstanceType is t2.micro as defined by these docs (https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html)
get_instance_type(instanceProperties) = result {
	common_lib.valid_key(instanceProperties, "instance_type")
	result = instanceProperties.instance_type
} else = result {
	result = "t2.micro"
}
