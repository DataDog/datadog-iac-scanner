package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.google_dataproc_cluster[name]

    common_lib.valid_key(resource, "cluster_config")
    cluster_configs := common_lib.as_array(resource.cluster_config)
    cluster_config := cluster_configs[_]

    common_lib.valid_key(cluster_config, "gce_cluster_config")
    gce_configs := common_lib.as_array(cluster_config.gce_cluster_config)
    gce_config := gce_configs[_]

    common_lib.valid_key(gce_config, "internal_ip_only")
    not gce_config.internal_ip_only == true

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_dataproc_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_dataproc_cluster[%s].cluster_config.gce_cluster_config.internal_ip_only", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_dataproc_cluster", name, "cluster_config", "gce_cluster_config", "internal_ip_only"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "internal_ip_only should be set to true (private cluster)",
        "keyActualValue": "internal_ip_only is not set to true",
        "remediation": json.marshal({
            "before": "internal_ip_only = false",
            "after": "internal_ip_only = true"
        }),
        "remediationType": "replacement"
    }
}
