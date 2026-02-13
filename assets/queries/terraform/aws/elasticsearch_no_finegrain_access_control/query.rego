package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

domains := {
  "aws_opensearch_domain",
  "aws_elasticsearch_domain"
}

CxPolicy[result] {
    resource_type := domains[_]
    resource := input.document[i].resource[resource_type][name]

    not common_lib.valid_key(resource, "advanced_security_options")

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[{{%s}}].advanced_security_options", [resource_type, name]),
        "searchLine": common_lib.build_search_line(["resource", resource_type, name, "advanced_security_options"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "advanced_security_options block should be present with enabled = true and internal_user_database_enabled = true",
        "keyActualValue": "advanced_security_options block is missing"
    }
}

CxPolicy[result] {
    resource_type := domains[_]
    resource := input.document[i].resource[resource_type][name]

    common_lib.valid_key(resource.advanced_security_options, "enabled")
    not resource.advanced_security_options.enabled

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[{{%s}}].advanced_security_options.enabled", [resource_type, name]),
        "searchLine": common_lib.build_search_line(["resource", resource_type, name, "advanced_security_options"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "advanced_security_options.enabled should be true",
        "keyActualValue": "advanced_security_options.enabled is false"
    }
}

CxPolicy[result] {
    resource_type := domains[_]
    resource := input.document[i].resource[resource_type][name]

    common_lib.valid_key(resource.advanced_security_options, "internal_user_database_enabled")
    not resource.advanced_security_options.internal_user_database_enabled

    result := {
        "documentId": input.document[i].id,
        "resourceType": resource_type,
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[{{%s}}].advanced_security_options.internal_user_database_enabled", [resource_type, name]),
        "searchLine": common_lib.build_search_line(["resource", resource_type, name, "advanced_security_options", "internal_user_database_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "advanced_security_options.internal_user_database_enabled should be true",
        "keyActualValue": "advanced_security_options.internal_user_database_enabled is false"
    }
}

#######################################################################################################

CxPolicy[result] {
    module := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_opensearch_domain", "advanced_security_options")

    not common_lib.valid_key(module, keyToCheck)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "module",
        "resourceName": sprintf("%s", [name]),
        "searchKey": sprintf("module[%s].%s", [name, keyToCheck]),
        "searchLine": common_lib.build_search_line(["module", name, keyToCheck, "enabled"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": sprintf("module[%s].%s block should be present with enabled = true and internal_user_database_enabled = true", [name, keyToCheck]),
        "keyActualValue": sprintf("module[%s].%s block is missing", [name, keyToCheck])
    }
}

CxPolicy[result] {
    module := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_opensearch_domain", "advanced_security_options")

    common_lib.valid_key(module[keyToCheck], "enabled")
    not module[keyToCheck].enabled

    result := {
        "documentId": input.document[i].id,
        "resourceType": "module",
        "resourceName": sprintf("%s", [name]),
        "searchKey": sprintf("module[%s].%s.enabled", [name, keyToCheck]),
        "searchLine": common_lib.build_search_line(["module", name, keyToCheck, "enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("module[%s].%s.enabled should be true", [name, keyToCheck]),
        "keyActualValue": sprintf("module[%s].%s.enabled is false", [name, keyToCheck])
    }
}

CxPolicy[result] {
    module := input.document[i].module[name]
    keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_opensearch_domain", "advanced_security_options")

    common_lib.valid_key(module[keyToCheck], "internal_user_database_enabled")
    not module[keyToCheck].internal_user_database_enabled

    result := {
        "documentId": input.document[i].id,
        "resourceType": "module",
        "resourceName": sprintf("%s", [name]),
        "searchKey": sprintf("module[%s].%s.internal_user_database.enabled", [name, keyToCheck]),
        "searchLine": common_lib.build_search_line(["module", name, keyToCheck, "internal_user_database_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("module[%s].%s.internal_user_database_enabled should be true", [name, keyToCheck]),
        "keyActualValue": sprintf("module[%s].%s.internal_user_database_enabled is false", [name, keyToCheck])
    }
}
