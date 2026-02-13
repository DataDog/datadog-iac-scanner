package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    input.document[i].data["aws_ami"][name].most_recent == true
    not has_valid_owner_or_filter(input.document[i].data["aws_ami"][name])

    result := {
        "documentId": input.document[i].id,
        "resourceType": "data.aws_ami",
        "resourceName": tf_lib.get_specific_resource_name(input.document[i].data.aws_ami[name], "aws_ami", name),
        "searchKey": sprintf("data.aws_ami[%s].most_recent", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "Must define 'owners' or a filter with 'owner-id', 'owner-alias', or 'image-id' when most_recent = true",
        "keyActualValue": "'most_recent = true' without owner or valid filter",
        "searchLine": common_lib.build_search_line(["data", "aws_ami", name, "most_recent"], [])
    }
}

has_valid_owner_or_filter(resource) {
    resource.owners != null
}

has_valid_owner_or_filter(resource) {
    f := resource.filter[_]
    f.name != null
    check_valid_filters(f.name)
}

check_valid_filters(p) {
	filters = {
        "owner-id",
        "owner-alias",
        "image-id"
    }
	filters[p]
}

# No module support for aws_ami which is data so cannot use get_module_equivalent_key
