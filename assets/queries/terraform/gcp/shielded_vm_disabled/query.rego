package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Flag when 'enable_secure_boot', 'enable_vtpm' or 'enable_integrity_monitoring' is false (object form)
CxPolicy[result] {
  document := input.document[_]
  resourceType := ["data", "resource"]
  resource := document[resourceType[_]].google_compute_instance[name]

  not skip_instance_check(resource)

  fields := ["enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"]
  field := fields[_]

  is_object(resource.shielded_instance_config)
  resource.shielded_instance_config[field] == false

  result := {
    "documentId": document.id,
    "resourceType": "google_compute_instance",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("google_compute_instance[%s].shielded_instance_config.%s", [name, field]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": sprintf("Attribute 'shielded_instance_config.%s' should be true", [field]),
    "keyActualValue": sprintf("Attribute 'shielded_instance_config.%s' is false", [field]),
    "searchLine": common_lib.build_search_line(["resource", "google_compute_instance", name, "shielded_instance_config", field], [])
  }
}

# Flag when 'enable_secure_boot',  'enable_vtpm' or 'enable_integrity_monitoring' is false (array form)
CxPolicy[result] {
  document := input.document[_]
  resourceType := ["data", "resource"]
  resource := document[resourceType[_]].google_compute_instance[name]

  not skip_instance_check(resource)

  fields := ["enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"]
  field := fields[_]

  is_array(resource.shielded_instance_config)
  index := array_index(resource.shielded_instance_config, field)

  result := {
    "documentId": document.id,
    "resourceType": "google_compute_instance",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("google_compute_instance[%s].shielded_instance_config[%d].%s", [name, index, field]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": sprintf("Attribute 'shielded_instance_config.%s' should be true", [field]),
    "keyActualValue": sprintf("Attribute 'shielded_instance_config.%s' is false", [field]),
    "searchLine": common_lib.build_search_line(["resource", "google_compute_instance", name, "shielded_instance_config", index, field], [])
  }
}

CxPolicy[result] {
  document := input.document[_]
  resourceType := ["data", "resource"]
  resource := document[resourceType[_]].google_compute_instance[name]

  not skip_instance_check(resource)
  not common_lib.valid_key(resource, "shielded_instance_config")

  result := {
    "documentId": document.id,
    "resourceType": "google_compute_instance",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("google_compute_instance[%s]", [name]),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "shielded_instance_config block should be present",
    "keyActualValue": "shielded_instance_config block is missing",
    "searchLine": common_lib.build_search_line(["resource", "google_compute_instance", name], [])
  }
}

# Flag when 'enable_secure_boot', 'enable_vtpm' or 'enable_integrity_monitoring' is missing (object form)
CxPolicy[result] {
  document := input.document[_]
  resource := document.data.google_compute_instance[name]

  not skip_instance_check(resource)

  fields := ["enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"]
  field := fields[_]

  is_object(resource.shielded_instance_config)
  not common_lib.valid_key(resource.shielded_instance_config, field)

  result := {
    "documentId": document.id,
    "resourceType": "google_compute_instance",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("google_compute_instance[%s].shielded_instance_config", [name]),
    "issueType": "MissingAttribute",
    "keyExpectedValue": sprintf("Attribute 'shielded_instance_config.%s' should be defined and set to true", [field]),
    "keyActualValue": sprintf("Attribute 'shielded_instance_config.%s' is undefined", [field]),
    "searchLine": common_lib.build_search_line(["resource", "google_compute_instance", name, "shielded_instance_config"], [])
  }
}

# Helper to get index in array where field is false
array_index(arr, field) = idx {
  some idx
  arr[idx][field] == false
}

# Skip instances created from templates without a local override
skip_instance_check(resource) {
  resource.source_instance_template
  not resource.shielded_instance_config
}
