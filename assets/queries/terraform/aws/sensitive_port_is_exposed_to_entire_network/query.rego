package Cx

import data.generic.terraform as tf_lib
import data.generic.common as commonLib

CxPolicy[result] {
  resource := input.document[i].resource.aws_security_group[name]
  ingress := resource.ingress[j]
  protocol := tf_lib.getProtocolList(ingress.protocol)[_]

  endswith(ingress.cidr_blocks[_], "/0")
  port := getMatchedPort(ingress)[_]

  sensitive_tcp_port(port, protocol, portName)

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_security_group",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_security_group[%s].ingress", [name]),
    "searchValue": sprintf("%s,%d", [protocol, port]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": sprintf("%s (%s:%d) should not be allowed", [portName, protocol, port]),
    "keyActualValue": sprintf("%s (%s:%d) is allowed", [portName, protocol, port]),
  }
}

isTCP(protocol) {
  lower(protocol) == "tcp"
}

# Only match if the protocol is TCP and the port is in tcpPortsMap
sensitive_tcp_port(port, protocol) = portName {
  isTCP(protocol)
  portName := commonLib.tcpPortsMap[port]
}

getMatchedPort(ingress) = ports {
  from := ingress.from_port
  to := ingress.to_port

  ports := [p |
    i := [j | j := 0; j <= to - from][_]
    p := from + i
    p <= to
  ]
}
