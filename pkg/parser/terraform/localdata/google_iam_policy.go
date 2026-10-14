/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package localdata

import (
	"bytes"
	"encoding/json"

	"github.com/hashicorp/hcl/v2"
)

// googleIAMPolicyType is the Google data source that renders an IAM policy.
const googleIAMPolicyType = "google_iam_policy"

var googlePolicySchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "binding"}, {Type: "audit_config"}, dynamicHeader},
}

var googleBindingSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "role"}, {Name: "members"}},
	Blocks:     []hcl.BlockHeaderSchema{{Type: "condition"}, dynamicHeader},
}

var googleConditionSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "expression"}, {Name: "title"}, {Name: "description"}},
}

var googleAuditConfigSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "service"}},
	Blocks:     []hcl.BlockHeaderSchema{{Type: "audit_log_configs"}, dynamicHeader},
}

var googleAuditLogConfigSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "log_type"}, {Name: "exempted_members"}},
}

type googlePolicy struct {
	AuditConfigs []googleAuditConfig `json:"auditConfigs,omitempty"`
	Bindings     []googleBinding     `json:"bindings,omitempty"`
}

type googleBinding struct {
	Condition *googleCondition `json:"condition,omitempty"`
	Members   []string         `json:"members,omitempty"`
	Role      string           `json:"role,omitempty"`
}

type googleCondition struct {
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression,omitempty"`
	Title       string `json:"title,omitempty"`
}

type googleAuditConfig struct {
	AuditLogConfigs []googleAuditLogConfig `json:"auditLogConfigs,omitempty"`
	Service         string                 `json:"service,omitempty"`
}

type googleAuditLogConfig struct {
	ExemptedMembers []string `json:"exemptedMembers,omitempty"`
	LogType         string   `json:"logType,omitempty"`
}

// googleIAMPolicyAttributes renders policy_data in the JSON shape of a GCP IAM
// policy, as Terraform does.
func googleIAMPolicyAttributes(body hcl.Body, eval EvalFunc) map[string]string {
	content, _, _ := body.PartialContent(googlePolicySchema)
	if content == nil {
		return nil
	}
	d := newDecoder(eval)
	var policy googlePolicy
	for _, block := range d.blocks(content, "binding") {
		policy.Bindings = append(policy.Bindings, block.d.googleBinding(block.body))
	}
	for _, block := range d.blocks(content, "audit_config") {
		policy.AuditConfigs = append(policy.AuditConfigs, block.d.googleAuditConfig(block.body))
	}
	if *d.skipped && len(policy.Bindings) == 0 && len(policy.AuditConfigs) == 0 {
		return nil
	}
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(policy); err != nil {
		return nil
	}
	return map[string]string{"policy_data": string(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))}
}

func (d decoder) googleBinding(body hcl.Body) googleBinding {
	content, _, _ := body.PartialContent(googleBindingSchema)
	if content == nil {
		return googleBinding{}
	}
	binding := googleBinding{
		Role:    d.str(content.Attributes["role"]),
		Members: d.list(content.Attributes["members"]),
	}
	for _, block := range d.blocks(content, "condition") {
		attrs, _, _ := block.body.PartialContent(googleConditionSchema)
		if attrs == nil {
			continue
		}
		binding.Condition = &googleCondition{
			Description: block.d.str(attrs.Attributes["description"]),
			Expression:  block.d.str(attrs.Attributes["expression"]),
			Title:       block.d.str(attrs.Attributes["title"]),
		}
	}
	return binding
}

func (d decoder) googleAuditConfig(body hcl.Body) googleAuditConfig {
	content, _, _ := body.PartialContent(googleAuditConfigSchema)
	if content == nil {
		return googleAuditConfig{}
	}
	config := googleAuditConfig{Service: d.str(content.Attributes["service"])}
	for _, block := range d.blocks(content, "audit_log_configs") {
		attrs, _, _ := block.body.PartialContent(googleAuditLogConfigSchema)
		if attrs == nil {
			continue
		}
		config.AuditLogConfigs = append(config.AuditLogConfigs, googleAuditLogConfig{
			ExemptedMembers: block.d.list(attrs.Attributes["exempted_members"]),
			LogType:         block.d.str(attrs.Attributes["log_type"]),
		})
	}
	return config
}
