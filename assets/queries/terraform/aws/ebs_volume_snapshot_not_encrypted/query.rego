package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	doc := input.document[i]
	volume := doc.resource.aws_ebs_volume[volName]
	snapshot := doc.resource.aws_ebs_snapshot[snapName]

	volName == split(snapshot.volume_id, ".")[1]

	snapshot.encrypted == false

	result := {
		"documentId": doc.id,
		"resourceType": "aws_ebs_snapshot",
		"resourceName": snapName,
		"searchKey": sprintf("aws_ebs_snapshot[%s].encrypted", [snapName]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_ebs_snapshot[%s].encrypted' should be true", [volName, snapName]),
		"keyActualValue": sprintf("'aws_ebs_snapshot[%s].encrypted' is false", [volName, snapName]),
	}
}

CxPolicy[result] {
	doc := input.document[i]
	volume := doc.resource.aws_ebs_volume[volName]
	snapshot := doc.resource.aws_ebs_snapshot[snapName]

	volName == split(snapshot.volume_id, ".")[1]

	not common_lib.valid_key(snapshot, "encrypted")

	result := {
		"documentId": doc.id,
		"resourceType": "aws_ebs_snapshot",
		"resourceName": snapName,
		"searchKey": sprintf("aws_ebs_snapshot[%s]", [snapName]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("'aws_ebs_snapshot[%s].encrypted' should be true", [volName, snapName]),
		"keyActualValue": sprintf("'aws_ebs_snapshot[%s].encrypted' is undefined", [volName, snapName]),
	}
}
