package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Required tags to be enforced across all Terraform resources
required_tags := {"Team"}

# Case where "tags" block exists but required tags are missing (including merge({...}, {...}))
CxPolicy[result] {
    startswith(resource_name, "aws_")
    tf_lib.check_aws_resource_supports_tags(resource_name)

    resource_type := input.document[i].resource[resource_name][name]
    common_lib.valid_key(resource_type, "tags")

    tags := resource_type.tags

    # Determine all tag keys (including merge scenarios)
    all_tag_keys := get_all_tag_keys(tags)

    missing_labels := {
        req_lower |
        req := required_tags[_]
        req_lower := lower(req)
        not key_in_set_ignore_case(req, all_tag_keys)
    }

    count(missing_labels) > 0

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_name,
        "resourceName": tf_lib.get_specific_resource_name(resource_type, resource_name, name),
        "searchKey": sprintf("%s[%s].tags", [resource_name, name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("Every resource should have tags: %v", [required_tags]),
        "keyActualValue": sprintf("Missing tags: %v", [missing_labels]),
        "searchLine": common_lib.build_search_line(["resource", resource_name, name, "tags"], [])
    }
}

# Case where "tags" block is completely missing
CxPolicy[result] {
    # Only consider resources whose type begins with "aws_"
    startswith(resource_type, "aws_")

    # Only consider resources that support tags
    tf_lib.check_aws_resource_supports_tags(resource_type)

    resource := input.document[i].resource[resource_type][name]
    not common_lib.valid_key(resource, "tags")

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_specific_resource_name(resource, resource_type, name),
        "searchKey": sprintf("%s[%s].tags", [resource_type, name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("Every resource should have a 'tags' block containing: %v", [required_tags]),
        "keyActualValue": "'tags' block is missing",
        "searchLine": common_lib.build_search_line(["resource", resource_type, name], []),
    }
}

# Handles merge(...) and normal map by extracting all tag keys
get_all_tag_keys(tags) = keys {
    # Case: tags is a plain object
    type_name(tags) == "object"
    keys := {k | tags[k]}
} else = keys {
    # Case: tags is a merge() function call
    is_merge_call(tags)
    keys := {
        merged_key |
        some i
        part := tags.function_args[i]
        type_name(part) == "object"
        part[merged_key]
    }
}

# Helper: check if `tags` is a merge(...) function call
is_merge_call(tags) {
    tags.function == "merge"
    tags.function_args
}

# Case-insensitive key match
key_in_set_ignore_case(key, keyset) {
    k := keyset[_]
    lower(k) == lower(key)
}
