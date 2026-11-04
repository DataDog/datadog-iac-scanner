/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terraform

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

func requireLines(t *testing.T, src string, lines map[string]int) {
	t.Helper()
	file := &model.FileMetadata{
		ScanID: "t", ID: "t", Kind: model.KindTerraform, FilePath: "main.tf",
		OriginalData: src, LinesOriginalData: utils.SplitLines(src),
	}
	for key, want := range lines {
		require.Equal(t, want, (&DetectKindLine{}).DetectLine(context.Background(), file, key, 3).Line, key)
	}
}

func TestDetectLineMapKeyStaysInAttribute(t *testing.T) {
	requireLines(t, `resource "aws_x" "a" {
  tags = {
    name = "t"
  }
  name = "real"
}
`, map[string]int{"aws_x[a].tags.name": 3, "aws_x[a].name": 5, "aws_x[a].tags": 2})

	requireLines(t, `resource "aws_x" "a" {
  tags = { name = "t" }
  name = "real"
}
`, map[string]int{"aws_x[a].tags.name": 2, `aws_x[a].tags["name"]`: 2})

	requireLines(t, `resource "aws_s3_bucket" "b" {
  settings = {
    versioning = true
  }
  versioning {
    enabled = false
  }
}
`, map[string]int{"aws_s3_bucket[b].settings.versioning": 3, "aws_s3_bucket[b].versioning.enabled": 6})

	requireLines(t, `resource "x" "a" {
  tags = {
    "kubernetes.io/name" = "a"
    Name                 = "b"
  }
}
`, map[string]int{"x[a].tags.Name": 4, "x[a].tags[kubernetes.io/name]": 3})
}

func TestDetectLineJsonencodeKeys(t *testing.T) {
	requireLines(t, `resource "aws_ecs_task_definition" "t" {
  container_definitions = jsonencode([
    {
      name        = "web"
      environment = [{ name = "A", value = "b" }]
    },
    {
      name       = "side"
      privileged = true
    }
  ])
  family = "f"
  name   = "n"
}
`, map[string]int{
		"aws_ecs_task_definition[t].container_definitions":               2,
		"aws_ecs_task_definition[t].container_definitions[1].privileged": 9,
		"aws_ecs_task_definition[t].container_definitions.name":          4,
		"aws_ecs_task_definition[t].container_definitions.privileged":    9,
		"aws_ecs_task_definition[t].family":                              12,
		"aws_ecs_task_definition[t].name":                                13,
	})
}

func TestDetectLineDynamicBlocks(t *testing.T) {
	requireLines(t, `resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = ["a", "b"]
    content {
      from_port   = 1
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  ingress {
    from_port   = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`, map[string]int{
		"aws_security_group[sg].ingress.cidr_blocks":    6,
		"aws_security_group[sg].ingress[0].cidr_blocks": 6,
		"aws_security_group[sg].ingress[1].cidr_blocks": 6,
		"aws_security_group[sg].ingress[2].cidr_blocks": 11,
		"aws_security_group[sg].ingress[2]":             9,
		"aws_security_group[sg].ingress":                2,
	})
}

func TestDetectLineMissingChildKeepsNearestAncestor(t *testing.T) {
	requireLines(t, `resource "kubernetes_pod" "p" {
  spec {
    container {
      name = "a"
    }
    container {
      name = "b"
      security_context {
        privileged = true
      }
    }
  }
  security_context {
    privileged = false
  }
}
`, map[string]int{
		"kubernetes_pod[p].spec.container[0].security_context.privileged": 3,
		"kubernetes_pod[p].spec.container[1].security_context.privileged": 9,
		"kubernetes_pod[p].spec.container.security_context.privileged":    9,
		"kubernetes_pod[p].spec.container[5].name":                        3,
		"kubernetes_pod[p].spec.missing.privileged":                       2,
	})

	requireLines(t, `resource "x" "a" {
  a {
    b {
      a {
        b {
          x = 1
        }
      }
    }
    x = 2
  }
  x = 3
}
`, map[string]int{"x[a].a.b.a.b.x": 6, "x[a].a.x": 10, "x[a].x": 12, "x[a].a.b.a.x": 4})
}

func TestDetectLineHeredocKeysStayInAttribute(t *testing.T) {
	requireLines(t, `resource "aws_iam_policy" "p" {
  policy = <<POLICY
{"Statement": [{"Effect": "Allow"}],
 "name": "x"}
POLICY
  name = "real"
}
`, map[string]int{
		"aws_iam_policy[p].name":             6,
		"aws_iam_policy[p].policy":           2,
		"aws_iam_policy[p].policy.Statement": 3,
		"aws_iam_policy[p].policy.missing":   2,
	})
}

func TestDetectLineValueAnchorPicksElement(t *testing.T) {
	requireLines(t, `resource "google_compute_firewall" "f" {
  allow {
    ports = [
      "80",
      "22",
    ]
  }
}
`, map[string]int{"google_compute_firewall[f].allow.ports=22": 5, "google_compute_firewall[f].allow.ports": 3})
}

func TestDetectLineStartsAtNamedBlock(t *testing.T) {
	requireLines(t, `resource "aws_lb" "decoy" {
  name = "aws_lb_listener l default_action redirect"
}

resource "aws_lb_listener" "l" {
  default_action {
    type = "redirect"
    redirect {
      port = "443"
    }
  }
}
`, map[string]int{
		"resource.aws_lb_listener[l]":                         5,
		"aws_lb_listener[l]":                                  5,
		"resource.aws_lb_listener[l].default_action.redirect": 8,
		"aws_lb_listener[l].default_action.type":              7,
	})
}
