package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
  resource := input.document[i].resource.google_dns_managed_zone[name]

  not skip_dnssec(resource)
  not dnssec_is_valid(resource)

  result := {
    "documentId": input.document[i].id,
    "resourceType": "google_dns_managed_zone",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("google_dns_managed_zone[%s].dnssec_config.state", [name]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": "'dnssec_config.state' should be 'on' or 'transfer'",
    "keyActualValue": "missing or not valid",
    "searchLine": common_lib.build_search_line(["resource","google_dns_managed_zone", name, "dnssec_config", "state"],[])
  }
}

skip_dnssec(resource) {
  resource.visibility == "private"
}

dnssec_is_valid(resource) {
  is_object(resource.dnssec_config)
  dnssec_enabled(resource.dnssec_config.state)
}

dnssec_is_valid(resource) {
  is_array(resource.dnssec_config)
  some i
  dnssec_enabled(resource.dnssec_config[i].state)
}

dnssec_enabled(state) {
  state == "on"
} else {
  state == "transfer"
}
