package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.google_compute_network[name]
    resource.auto_create_subnetworks == true
    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_compute_network",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_compute_network[%s].auto_create_subnetworks", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "auto_create_subnetworks should be false",
        "keyActualValue": "auto_create_subnetworks is true",
        "searchLine": common_lib.build_search_line(["resource", "google_compute_network", name],["auto_create_subnetworks"]),
        "remediation": json.marshal({
            "before": "true",
            "after": "false"
        }),
        "remediationType": "replacement",
    }
}
