package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Required labels to be enforced across all Terraform resources
required_labels := {"Team"}

# Case where "labels" exists but required labels are missing
CxPolicy[result] {
    # Only consider resources whose type begins with "google_"
    startswith(resource_name, "google_")

    # Only consider resources that support labels
    tf_lib.check_gcp_resource_supports_labels(resource_name)

    resource_type := input.document[i].resource[resource_name][name]
    common_lib.valid_key(resource_type, "labels")

    labels := resource_type.labels
    missing_labels := {
        req_lower |
        req := required_labels[_]               # iterate over each required label
        req_lower := lower(req)               # store a lowercase version
        not valid_key_ignore_case(labels, req)  # keep it if NOT found in labels ignoring case
    }

    count(missing_labels) > 0

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_name,
        "resourceName": tf_lib.get_specific_resource_name(resource_type, resource_name, name),
        "searchKey": sprintf("%s[%s].labels", [resource_name, name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("Every resource should have labels: %v", [required_labels]),
        "keyActualValue": sprintf("Missing labels: %v", [missing_labels]),
        "searchLine": common_lib.build_search_line(["resource", resource_name, name, "labels"], [])
    }
}

# Case where "labels" block is completely missing
CxPolicy[result] {
    # Only consider resources whose type begins with "google_"
    startswith(resource_type, "google_")

    # Only consider resources that support labels
    tf_lib.check_gcp_resource_supports_labels(resource_type)

    resource := input.document[i].resource[resource_type][name]
    not common_lib.valid_key(resource, "labels")

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_specific_resource_name(resource, resource_type, name),
        "searchKey": sprintf("%s[%s]", [resource_type, name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("Every resource should have a 'labels' block containing: %v", [required_labels]),
        "keyActualValue": "'labels' block is missing",
        "searchLine": common_lib.build_search_line(["resource", resource_type, name], [])
    }
}

valid_key_ignore_case(tags, key) {
  some k
  lower(k) == lower(key)
  tags[k]  # ensures `k` is an actual key in `tags`
}
