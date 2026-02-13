package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_neptune_cluster_snapshot[name]
    common_lib.valid_key(resource, "storage_encrypted")

    resource.storage_encrypted != true

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_neptune_cluster_snapshot",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_neptune_cluster_snapshot[{{%s}}].storage_encrypted", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_neptune_cluster_snapshot", name, "storage_encrypted"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_neptune_cluster_snapshot.storage_encrypted should be true",
        "keyActualValue": sprintf("aws_neptune_cluster_snapshot.storage_encrypted is '%v'", [resource.storage_encrypted]),
        "remediation": json.marshal({
            "before": "false",
            "after": "true"
        }),
        "remediationType": "replacement"
    }
}
