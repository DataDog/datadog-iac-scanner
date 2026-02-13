package Cx

import data.generic.terraform as tf_lib
import data.generic.common as commonLib

CxPolicy[result] {
  resource := input.document[i].resource.aws_security_group[name]
  ingress := getIngressList(resource.ingress)[j]

  cidr_block := ingress.cidr_blocks[_]
  isEntireNetwork(cidr_block)

  unknownPort(ingress.from_port, ingress.to_port)

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_security_group",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_security_group[%s].ingress.cidr_blocks", [name]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": sprintf("aws_security_group[%s].ingress ports are known", [name]),
    "keyActualValue": sprintf("aws_security_group[%s].ingress ports are unknown and exposed to the entire Internet", [name]),
    "searchLine": commonLib.build_search_line(["resource", "aws_security_group", name, "ingress", j, "cidr_blocks"], []),
  }
}

getIngressList(ingress) = list {
  type_name(ingress) == "array"
  list := ingress
} else = list {
  type_name(ingress) == "object"
  list := [ingress]
}

unknownPort(from_port, to_port) {
  from_port <= to_port
  offset := [i | i := 0; i <= to_port - from_port][_]
  port := from_port + offset
  not commonLib.valid_key(commonLib.tcpPortsMap, port)
}

isEntireNetwork(cidr) {
  cidr == "0.0.0.0/0"
}
