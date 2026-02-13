package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Enforce check on aws_instance, aws_launch_template, and aws_launch_configuration
IMDSv1_Disabled[resource_type] {
    resource_type := "aws_instance"
}

IMDSv1_Disabled[resource_type] {
    resource_type := "aws_launch_template"
}

IMDSv1_Disabled[resource_type] {
    resource_type := "aws_launch_configuration"
}

# Case where metadata_options is an array
CxPolicy[result] {
    resource_type := IMDSv1_Disabled[_]
    resource := input.document[i].resource[resource_type][name]

    common_lib.valid_key(resource, "metadata_options")
    is_array(resource.metadata_options)

    metadata_opt := resource.metadata_options[_]
    common_lib.valid_key(metadata_opt, "http_tokens")

    metadata_opt.http_tokens != "required"

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_specific_resource_name(resource, resource_type, name),
        "searchKey": sprintf("%s[%s].metadata_options.http_tokens", [resource_type, name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "metadata_options.http_tokens should be 'required'",
        "keyActualValue": sprintf("metadata_options.http_tokens is '%s'", [metadata_opt.http_tokens]),
        "searchLine": common_lib.build_search_line(["resource", resource_type, name, "metadata_options", "http_tokens"], []),
        "remediation": json.marshal({
            "before": "optional",
            "after": "required"
        }),
        "remediationType": "replacement"
    }
}

# Case where metadata_options is a single object
CxPolicy[result] {
    resource_type := IMDSv1_Disabled[_]
    resource := input.document[i].resource[resource_type][name]

    common_lib.valid_key(resource, "metadata_options")
    not is_array(resource.metadata_options)

    metadata_opt := resource.metadata_options
    common_lib.valid_key(metadata_opt, "http_tokens")

    metadata_opt.http_tokens != "required"

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_specific_resource_name(resource, resource_type, name),
        "searchKey": sprintf("%s[%s].metadata_options.http_tokens", [resource_type, name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "metadata_options.http_tokens should be 'required'",
        "keyActualValue": sprintf("metadata_options.http_tokens is '%s'", [metadata_opt.http_tokens]),
        "searchLine": common_lib.build_search_line(["resource", resource_type, name, "metadata_options", "http_tokens"], []),
        "remediation": json.marshal({
            "before": "optional",
            "after": "required"
        }),
        "remediationType": "replacement"
    }
}

# Case where metadata_options is missing (defaults to IMDSv1)
CxPolicy[result] {
    resource_type := IMDSv1_Disabled[_]
    resource := input.document[i].resource[resource_type][name]

    not common_lib.valid_key(resource, "metadata_options")

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_specific_resource_name(resource, resource_type, name),
        "searchKey": sprintf("%s[%s]", [resource_type, name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "metadata_options must be defined with http_tokens set to 'required'",
        "keyActualValue": "metadata_options is missing, defaulting to IMDSv1",
        "searchLine": common_lib.build_search_line(["resource", resource_type, name], []),
        "remediation": "metadata_options {\n\t  http_tokens = \"required\"\n}",
        "remediationType": "addition"
    }
}

#######################################################################################################

# Case where metadata_options is an array
CxPolicy[result] {
    resource_type := IMDSv1_Disabled[_]
    modules := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", modules.source, resource_type, "metadata_options")

    common_lib.valid_key(modules, keyToCheck)
    is_array(modules[keyToCheck])

    metadata_opt := modules[keyToCheck][_]
    common_lib.valid_key(metadata_opt, "http_tokens")

    metadata_opt.http_tokens != "required"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "module",
        "resourceName": sprintf("%s", [name]),
        "searchKey": sprintf("module[%s].%s.http_tokens", [name, keyToCheck]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("%s.http_tokens should be 'required'", [keyToCheck]),
        "keyActualValue": sprintf("%s.http_tokens is '%s'", [keyToCheck, metadata_opt.http_tokens]),
        "searchLine": common_lib.build_search_line(["module", name, keyToCheck, "http_tokens"], []),
        "remediation": json.marshal({
            "before": "optional",
            "after": "required"
        }),
        "remediationType": "replacement"
    }
}

# Case where metadata_options is a single object
CxPolicy[result] {
    resource_type := IMDSv1_Disabled[_]
    modules := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", modules.source, resource_type, "metadata_options")

    common_lib.valid_key(modules, keyToCheck)
    not is_array(modules[keyToCheck])

    metadata_opt := modules[keyToCheck]
    common_lib.valid_key(metadata_opt, "http_tokens")

    metadata_opt.http_tokens != "required"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "module",
        "resourceName": sprintf("%s", [name]),
        "searchKey": sprintf("module[%s].%s.http_tokens", [name, keyToCheck]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("%s.http_tokens should be 'required'", [keyToCheck]),
        "keyActualValue": sprintf("%s.http_tokens is '%s'", [keyToCheck, metadata_opt.http_tokens]),
        "searchLine": common_lib.build_search_line(["module", name, keyToCheck, "http_tokens"], []),
        "remediation": json.marshal({
            "before": "optional",
            "after": "required"
        }),
        "remediationType": "replacement"
    }
}

# Case where metadata_options is missing (defaults to IMDSv1)
CxPolicy[result] {
    modules := input.document[i].module[name]
    resource_type := IMDSv1_Disabled[_]
    keyToCheck := common_lib.get_module_equivalent_key("aws", modules.source, resource_type, "metadata_options")

    not common_lib.valid_key(modules, keyToCheck)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "module",
        "resourceName": sprintf("%s", [name]),
        "searchKey": sprintf("module[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("%s must be defined with http_tokens set to 'required'", [keyToCheck]),
        "keyActualValue": sprintf("%s is missing, defaulting to IMDSv1", [keyToCheck]),
        "searchLine": common_lib.build_search_line(["module", name], []),
        "remediation": sprintf("%s {\n\t  http_tokens = \"required\"\n}", keyToCheck),
        "remediationType": "addition"
    }
}
