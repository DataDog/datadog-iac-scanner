package Cx

import data.generic.ansible as ansLib

# [canonical, folder] for modules that use src with relative path
canonical_with_folder[[canonical, folder]] {
	[canonical, folder] := [["copy", "files"], ["template", "templates"], ["win_copy", "files"], ["win_template", "win_templates"]][_]
}

CxPolicy[result] {
	[canonical, folder] := canonical_with_folder[_]
	task := ansLib.tasks[id][t]
	variant := ansLib.get_variants(canonical)[_]
	copyOrTemplate := task[variant]
	ansLib.checkState(copyOrTemplate)

	relative_path := sprintf("../%s", [folder])
	contains(copyOrTemplate.src, relative_path)

	result := {
		"documentId": id,
		"resourceType": canonical,
		"resourceName": ansLib.get_resource_name(copyOrTemplate, canonical, task),
		"searchKey": sprintf("name={{%s}}.{{%s}}.src", [task.name, variant]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("%s.src should not be a relative path", [variant]),
		"keyActualValue": sprintf("%s.src is a relative path", [variant]),
	}
}
