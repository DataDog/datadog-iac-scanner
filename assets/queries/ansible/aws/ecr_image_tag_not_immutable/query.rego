package Cx

import data.generic.ansible as ansLib
import data.generic.common as common_lib

canonical := "ecs_ecr"

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs_ecr := task[variant]
	ansLib.checkState(ecs_ecr)

	not common_lib.valid_key(ecs_ecr, "image_tag_mutability")

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs_ecr, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [task.name, variant]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "ecs_ecr.image_tag_mutability should be set ",
		"keyActualValue": "ecs_ecr.image_tag_mutability is undefined",
	}
}

CxPolicy[result] {
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	ecs_ecr := task[variant]
	ansLib.checkState(ecs_ecr)

	ecs_ecr.image_tag_mutability != "immutable"

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(ecs_ecr, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.image_tag_mutability", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "ecs_ecr.image_tag_mutability should be set to 'immutable'",
		"keyActualValue": "ecs_ecr.image_tag_mutability is not set to 'immutable'",
	}
}
