package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Case where "grant" is an array (multiple grants)
CxPolicy[result] {
    resource := input.document[i].resource["aws_s3_bucket_acl"][name]
    acl_policy := resource.access_control_policy
    is_array(acl_policy.grant)

    grant := acl_policy.grant[grant_index]
    common_lib.valid_key(grant, "grantee")
    common_lib.valid_key(grant.grantee, "uri")
    
    grant.grantee.uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_s3_bucket_acl",
        "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket_acl", name),
        "searchKey": sprintf("aws_s3_bucket_acl[%s].access_control_policy.grant[%d].grantee.uri", [name, grant_index]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_s3_bucket_acl.access_control_policy.grant[*].grantee.uri should not be 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'",
        "keyActualValue": sprintf("aws_s3_bucket_acl.access_control_policy.grant[%d].grantee.uri is '%s'", [grant_index, grant.grantee.uri]),
        "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_acl", name, "access_control_policy", "grant", grant_index, "grantee", "uri"], [])
    }
}

# Case where "grant" is not an array (only one grant)
CxPolicy[result] {
    resource := input.document[i].resource["aws_s3_bucket_acl"][name]
    acl_policy := resource.access_control_policy
    not is_array(acl_policy.grant)

    grant := acl_policy.grant
    common_lib.valid_key(grant, "grantee")
    common_lib.valid_key(grant.grantee, "uri")

    grant.grantee.uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_s3_bucket_acl",
        "resourceName": tf_lib.get_specific_resource_name(resource, "aws_s3_bucket_acl", name),
        "searchKey": sprintf("aws_s3_bucket_acl[%s].access_control_policy.grant.grantee.uri", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_s3_bucket_acl.access_control_policy.grant.grantee.uri should not be 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'",
        "keyActualValue": sprintf("aws_s3_bucket_acl.access_control_policy.grant.grantee.uri is '%s'", [grant.grantee.uri]),
        "searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket_acl", name, "access_control_policy", "grant", "grantee", "uri"], [])
    }
}

# No module with access_control_policy so can't get_module_equivalent_key
