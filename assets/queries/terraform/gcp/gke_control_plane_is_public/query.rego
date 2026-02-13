package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    some i, name
    resource := input.document[i].resource.google_container_cluster[name]

    # Normalize master_authorized_networks_config to an array
    master_configs := common_lib.as_array(resource.master_authorized_networks_config)
    master_config := master_configs[_]

    # Normalize cidr_blocks to an array and extract each cidr_block value
    cidr_blocks := common_lib.as_array(master_config.cidr_blocks)
    block := cidr_blocks[_]
    block.cidr_block == "0.0.0.0/0"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "google_container_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("google_container_cluster[{{%s}}].master_authorized_networks_config.cidr_blocks", [name]),
        "searchLine": common_lib.build_search_line(["resource", "google_container_cluster", name, "master_authorized_networks_config", "cidr_blocks"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "master_authorized_networks_config.cidr_blocks should not include '0.0.0.0/0'",
        "keyActualValue": "master_authorized_networks_config.cidr_blocks includes '0.0.0.0/0'"
    }
}
