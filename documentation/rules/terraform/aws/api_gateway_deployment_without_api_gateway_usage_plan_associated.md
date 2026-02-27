---
title: "API gateway deployment without API gateway usage plan associated"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_deployment_without_api_gateway_usage_plan_associated"
  id: "b3a59b8e-94a3-403e-b6e2-527abaf12034"
  display_name: "API gateway deployment without API gateway usage plan associated"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `b3a59b8e-94a3-403e-b6e2-527abaf12034`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_deployment)

### Description

An API Gateway Deployment should have an associated UsagePlan defined using the `aws_api_gateway_usage_plan` resource, with the `api_stages` attribute referencing the relevant API and stage. Without a UsagePlan, API Gateway endpoints are left unprotected, allowing unlimited, unauthenticated access and risking abuse, denial of service, or unexpected cost overruns. To prevent this, always associate deployments with a UsagePlan, as shown below:

```
resource "aws_api_gateway_usage_plan" "example" {
  name = "usage-plan"
  api_stages {
    api_id = aws_api_gateway_deployment.example.rest_api_id
    stage  = aws_api_gateway_deployment.example.stage_name
  }
}
```

## Compliant Code Examples
```terraform
resource "aws_api_gateway_deployment" "negative1" {
  rest_api_id   = "rest_api_1"
  stage_name    = "development"
}

resource "aws_api_gateway_usage_plan" "negative2" {
  name         = "my-usage-plan"
  description  = "my description"
  product_code = "MYCODE"

  api_stages {
    api_id = "rest_api_1"
    stage  = "development"
  }

  api_stages {
    api_id = "rest_api_2"
    stage  = "development_2"
  }
}

```

```json
{
  "format_version": "0.2",
  "terraform_version": "1.0.5",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_api_gateway_deployment.negative1",
          "mode": "managed",
          "type": "aws_api_gateway_deployment",
          "name": "negative1",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "description": null,
            "rest_api_id": "rest_api_1",
            "stage_description": null,
            "stage_name": "development",
            "triggers": null,
            "variables": null
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_api_gateway_usage_plan.negative2",
          "mode": "managed",
          "type": "aws_api_gateway_usage_plan",
          "name": "negative2",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "api_stages": [
              {
                "api_id": "rest_api_1",
                "stage": "development"
              }
            ],
            "description": "my description",
            "name": "my-usage-plan",
            "product_code": "MYCODE",
            "quota_settings": [],
            "tags": null,
            "throttle_settings": []
          },
          "sensitive_values": {
            "api_stages": [
              {}
            ],
            "quota_settings": [],
            "tags_all": {},
            "throttle_settings": []
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_api_gateway_deployment.negative1",
      "mode": "managed",
      "type": "aws_api_gateway_deployment",
      "name": "negative1",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "description": null,
          "rest_api_id": "rest_api_1",
          "stage_description": null,
          "stage_name": "development",
          "triggers": null,
          "variables": null
        },
        "after_unknown": {
          "created_date": true,
          "execution_arn": true,
          "id": true,
          "invoke_url": true
        },
        "before_sensitive": false,
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_api_gateway_usage_plan.negative2",
      "mode": "managed",
      "type": "aws_api_gateway_usage_plan",
      "name": "negative2",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "api_stages": [
            {
              "api_id": "rest_api_1",
              "stage": "development"
            }
          ],
          "description": "my description",
          "name": "my-usage-plan",
          "product_code": "MYCODE",
          "quota_settings": [],
          "tags": null,
          "throttle_settings": []
        },
        "after_unknown": {
          "api_stages": [
            {}
          ],
          "arn": true,
          "id": true,
          "quota_settings": [],
          "tags_all": true,
          "throttle_settings": []
        },
        "before_sensitive": false,
        "after_sensitive": {
          "api_stages": [
            {}
          ],
          "quota_settings": [],
          "tags_all": {},
          "throttle_settings": []
        }
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_api_gateway_deployment.negative1",
          "mode": "managed",
          "type": "aws_api_gateway_deployment",
          "name": "negative1",
          "provider_config_key": "aws",
          "expressions": {
            "rest_api_id": {
              "constant_value": "rest_api_1"
            },
            "stage_name": {
              "constant_value": "development"
            }
          },
          "schema_version": 0
        },
        {
          "address": "aws_api_gateway_usage_plan.negative2",
          "mode": "managed",
          "type": "aws_api_gateway_usage_plan",
          "name": "negative2",
          "provider_config_key": "aws",
          "expressions": {
            "api_stages": [
              {
                "api_id": {
                  "constant_value": "rest_api_1"
                },
                "stage": {
                  "constant_value": "development"
                }
              }
            ],
            "description": {
              "constant_value": "my description"
            },
            "name": {
              "constant_value": "my-usage-plan"
            },
            "product_code": {
              "constant_value": "MYCODE"
            }
          },
          "schema_version": 0
        }
      ]
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "format_version": "0.2",
  "terraform_version": "1.0.5",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_api_gateway_deployment.positive1",
          "mode": "managed",
          "type": "aws_api_gateway_deployment",
          "name": "positive1",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "description": null,
            "rest_api_id": "some rest api id",
            "stage_description": null,
            "stage_name": "some name",
            "triggers": null,
            "variables": null
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_api_gateway_deployment.positive2",
          "mode": "managed",
          "type": "aws_api_gateway_deployment",
          "name": "positive2",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "description": null,
            "rest_api_id": "some rest api id",
            "stage_description": null,
            "stage_name": "development",
            "triggers": null,
            "variables": null
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_api_gateway_usage_plan.positive3",
          "mode": "managed",
          "type": "aws_api_gateway_usage_plan",
          "name": "positive3",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "api_stages": [
              {
                "api_id": "another id",
                "stage": "development"
              }
            ],
            "description": "my description",
            "name": "my-usage-plan",
            "product_code": "MYCODE",
            "quota_settings": [],
            "tags": null,
            "throttle_settings": []
          },
          "sensitive_values": {
            "api_stages": [
              {}
            ],
            "quota_settings": [],
            "tags_all": {},
            "throttle_settings": []
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_api_gateway_deployment.positive1",
      "mode": "managed",
      "type": "aws_api_gateway_deployment",
      "name": "positive1",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "description": null,
          "rest_api_id": "some rest api id",
          "stage_description": null,
          "stage_name": "some name",
          "triggers": null,
          "variables": null
        },
        "after_unknown": {
          "created_date": true,
          "execution_arn": true,
          "id": true,
          "invoke_url": true
        },
        "before_sensitive": false,
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_api_gateway_deployment.positive2",
      "mode": "managed",
      "type": "aws_api_gateway_deployment",
      "name": "positive2",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "description": null,
          "rest_api_id": "some rest api id",
          "stage_description": null,
          "stage_name": "development",
          "triggers": null,
          "variables": null
        },
        "after_unknown": {
          "created_date": true,
          "execution_arn": true,
          "id": true,
          "invoke_url": true
        },
        "before_sensitive": false,
        "after_sensitive": {}
      }
    },
    {
      "address": "aws_api_gateway_usage_plan.positive3",
      "mode": "managed",
      "type": "aws_api_gateway_usage_plan",
      "name": "positive3",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": [
          "create"
        ],
        "before": null,
        "after": {
          "api_stages": [
            {
              "api_id": "another id",
              "stage": "development"
            }
          ],
          "description": "my description",
          "name": "my-usage-plan",
          "product_code": "MYCODE",
          "quota_settings": [],
          "tags": null,
          "throttle_settings": []
        },
        "after_unknown": {
          "api_stages": [
            {}
          ],
          "arn": true,
          "id": true,
          "quota_settings": [],
          "tags_all": true,
          "throttle_settings": []
        },
        "before_sensitive": false,
        "after_sensitive": {
          "api_stages": [
            {}
          ],
          "quota_settings": [],
          "tags_all": {},
          "throttle_settings": []
        }
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_api_gateway_deployment.positive1",
          "mode": "managed",
          "type": "aws_api_gateway_deployment",
          "name": "positive1",
          "provider_config_key": "aws",
          "expressions": {
            "rest_api_id": {
              "constant_value": "some rest api id"
            },
            "stage_name": {
              "constant_value": "some name"
            }
          },
          "schema_version": 0
        },
        {
          "address": "aws_api_gateway_deployment.positive2",
          "mode": "managed",
          "type": "aws_api_gateway_deployment",
          "name": "positive2",
          "provider_config_key": "aws",
          "expressions": {
            "rest_api_id": {
              "constant_value": "some rest api id"
            },
            "stage_name": {
              "constant_value": "development"
            }
          },
          "schema_version": 0
        },
        {
          "address": "aws_api_gateway_usage_plan.positive3",
          "mode": "managed",
          "type": "aws_api_gateway_usage_plan",
          "name": "positive3",
          "provider_config_key": "aws",
          "expressions": {
            "api_stages": [
              {
                "api_id": {
                  "constant_value": "another id"
                },
                "stage": {
                  "constant_value": "development"
                }
              }
            ],
            "description": {
              "constant_value": "my description"
            },
            "name": {
              "constant_value": "my-usage-plan"
            },
            "product_code": {
              "constant_value": "MYCODE"
            }
          },
          "schema_version": 0
        }
      ]
    }
  }
}

```

```terraform
resource "aws_api_gateway_deployment" "positive1" {
  rest_api_id   = "some rest api id"
  stage_name = "some name"
  tags {
    project = "ProjectName"
  }
}

resource "aws_api_gateway_deployment" "positive2" {
  rest_api_id   = "some rest api id"
  stage_name    = "development"
}

resource "aws_api_gateway_usage_plan" "positive3" {
  name         = "my-usage-plan"
  description  = "my description"
  product_code = "MYCODE"

  api_stages {
    api_id = "another id"
    stage  = "development"
  }
}

```