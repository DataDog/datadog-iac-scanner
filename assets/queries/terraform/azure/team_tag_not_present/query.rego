package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Required tags to be enforced across all Terraform resources
required_tags := {"team"}

# Case where "tags" exists but required tags are missing
CxPolicy[result] {
    # Only consider resources whose type begins with "azurerm_"
    startswith(resource_name, "azurerm_")

    # Only consider resources that support tags
    tf_lib.check_azure_resource_supports_tags(resource_name)

    resource_type := input.document[i].resource[resource_name][name]
    common_lib.valid_key(resource_type, "tags")

    tags := resource_type.tags
    missing_labels := {
        req_lower |
        req := required_tags[_]               # iterate over each required tag
        req_lower := lower(req)               # store a lowercase version
        not valid_key_ignore_case(tags, req)  # keep it if NOT found in tags ignoring case
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
    # Only consider resources whose type begins with "azurerm_"
    startswith(resource_type, "azurerm_")

    # Only consider resources that support tags
    tf_lib.check_azure_resource_supports_tags(resource_type)

    resource := input.document[i].resource[resource_type][name]
    not common_lib.valid_key(resource, "tags")

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_specific_resource_name(resource, resource_type, name),
        "searchKey": sprintf("%s[%s]", [resource_type, name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("Every resource should have a 'tags' block containing: %v", [required_tags]),
        "keyActualValue": "'tags' block is missing",
        "searchLine": common_lib.build_search_line(["resource", resource_type, name], [])
    }
}

valid_key_ignore_case(tags, key) {
  some k
  lower(k) == lower(key)
  tags[k]  # ensures `k` is an actual key in `tags`
}
