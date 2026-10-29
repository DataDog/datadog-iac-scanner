package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/rds"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "")
		if _, err := rds.NewInstance(ctx, "db", &rds.InstanceArgs{
			Engine:             pulumi.String("postgres"),
			InstanceClass:      pulumi.String("db.t3.micro"),
			PubliclyAccessible: pulumi.Bool(true),
			StorageEncrypted:   pulumi.Bool(cfg.GetBool("enc")),
		}); err != nil {
			return err
		}
		for _, env := range []string{"dev", "prod"} {
			if _, err := s3.NewBucketV2(ctx, "logs-"+env, &s3.BucketV2Args{ForceDestroy: pulumi.Bool(true)}); err != nil {
				return err
			}
		}
		_, err := s3.NewBucketServerSideEncryptionConfigurationV2(ctx, "enc", &s3.BucketServerSideEncryptionConfigurationV2Args{
			Bucket: pulumi.String("x"),
			Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
				&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
					ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
						SseAlgorithm: pulumi.String("aws:kms"),
					},
				},
			},
		})
		return err
	})
}
