package Cx

CxPolicy[result] {
	resource := input.document[i]

	# Find the minimum line number across all commands and args
	minLineCmd := min({c._kics_line | c := resource.command[_][_]})
	minLineArg := min({c._kics_line | c := resource.args[_]})

    # Check that the first arg appears before first Cmd
    minLineArg < minLineCmd

    # Get first arg
    firstArg := resource.args[_]
	firstArg._kics_line == minLineArg

	# Check if first command is not ARG
    firstArg.Cmd != "arg"

	result := {
		"documentId": resource.id,
		"searchKey": sprintf("{{%s}}", [firstArg.Original]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "First instruction should be ARG or FROM",
		"keyActualValue": sprintf("First instruction is '%s'", [upper(firstArg.Cmd)]),
		"resourceName": "dockerfile_container",
		"resourceType": "dockerfile_container",
	}
}
