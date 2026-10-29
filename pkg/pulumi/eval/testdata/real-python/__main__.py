"""Test fixture: patterns that a static parser gets wrong.

Each numbered block exercises one pattern. The expected behaviour of the
fake-engine capture is described in the comment above each block.
"""
import json

import pulumi
import pulumi_aws as aws
from pulumi_aws import rds, s3

config = pulumi.Config()
public = config.require_bool("public")  # real value lives in Pulumi.prod.yaml

# 1. Plain resource with literal values.
db = rds.Instance(
    "db",
    engine="postgres",
    instance_class="db.t3.micro",
    publicly_accessible=True,
    storage_encrypted=False,
    tags={"cost_center": "infra"},
)

# 2. Value driven by stack config (no default in code): must be read from Pulumi.prod.yaml.
db2 = rds.Instance("db2", engine="postgres", instance_class="db.t3.micro", publicly_accessible=public)

# 3. Resources created in a loop: one registration per iteration, with the real name.
for env in ["dev", "prod"]:
    s3.BucketV2(f"logs-{env}", force_destroy=True)


# 4. Resource hidden inside a ComponentResource.
class SecureBucket(pulumi.ComponentResource):
    def __init__(self, name, opts=None):
        super().__init__("demo:SecureBucket", name, None, opts)
        self.bucket = s3.BucketV2(name, acl="public-read")


SecureBucket("assets")

# 5. Nested typed args, two levels deep.
s3.BucketServerSideEncryptionConfigurationV2(
    "enc",
    bucket="x",
    rules=[
        s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="aws:kms",
            ),
        )
    ],
)

# 6. JSON policy document built in code.
aws.iam.Policy("pol", policy=json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))

# 7. Data sources (invokes): not resources, answered with an empty result.
ident = aws.get_caller_identity()
ami = aws.ec2.get_ami(most_recent=True, owners=["amazon"])

# 8. Cross-resource reference: bucket.id is unknown in preview, the dependency is kept.
b = s3.BucketV2("data")
s3.BucketPublicAccessBlock("data-pab", bucket=b.id, block_public_acls=False)

# 9. EC2 instances: monitoring set, absent, and from config inside a loop.
aws.ec2.Instance("web-ok", ami="ami-1", instance_type="t3.micro", monitoring=True, ebs_optimized=True)
aws.ec2.Instance("web-absent", ami="ami-1", instance_type="t3.micro")
for i in range(2):
    aws.ec2.Instance(
        f"worker-{i}", ami="ami-1", instance_type="t3.micro", monitoring=config.get_bool("monitoring") or False
    )

# 10. Logging configured through a separate resource linked to the bucket.
log_target = s3.BucketV2("log-target")
s3.BucketLoggingV2("data-logging", bucket=b.id, target_bucket=log_target.id, target_prefix="data/")
