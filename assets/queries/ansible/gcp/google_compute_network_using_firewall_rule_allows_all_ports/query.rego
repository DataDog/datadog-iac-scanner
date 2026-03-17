package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

canonical_firewall := "gcp_compute_firewall"
canonical_network := "gcp_compute_network"

CxPolicy[result] {
	task := ans_lib.tasks[id][t]
	variant_fw := ans_lib.get_variants(canonical_firewall)[_]
	firewall := task[variant_fw]
	ans_lib.checkState(firewall)

	common_lib.is_ingress(firewall)
	firewall.allowed[_].ports[0] == "0-65535"

	tk := ans_lib.tasks[id][_]
	variant_net := ans_lib.get_variants(canonical_network)[_]
	computeNetwork := tk[variant_net]
	ans_lib.checkState(computeNetwork)
	firewall.network == sprintf("{{ %s }}", [tk.register])

	result := {
		"documentId": id,
		"resourceType": canonical_network,
		"resourceName": ans_lib.get_resource_name(computeNetwork, canonical_network, tk),
		"searchKey": sprintf("name={{%s}}.{{%s}}", [tk.name, variant_net]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be using a firewall rule that allows access to all ports", [canonical_network]),
		"keyActualValue": sprintf("'%s' is using a firewall rule that allows access to all ports", [canonical_network]),
		"searchLine": common_lib.build_search_line(["playbooks", t, variant_net], []),
	}
}
